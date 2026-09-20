"""Asynchronous JWKS validation with bounded refresh and strict provider claim adapters."""

import asyncio
import time

import httpx
import jwt
from pydantic import ValidationError

from boundedllm.config import Settings
from boundedllm.errors import InvalidToken, Unavailable
from boundedllm.models import Principal
from boundedllm.network import bounded_json


def string_set(value: object) -> frozenset[str]:
    """Only supported claim shapes; never turn 'admin' into a set of characters."""
    if isinstance(value, str):
        items = value.split()
    elif isinstance(value, list) and all(isinstance(x, str) for x in value):
        items = value
    else:
        raise InvalidToken("CLAIM_SHAPE")
    if len(items) > 64 or any(not item or len(item) > 128 for item in items):
        raise InvalidToken("CLAIM_SIZE")
    return frozenset(items)


class JWTAuthenticator:
    """Use only a configured JWKS URL; unverified jku/x5u values are never fetched."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings = settings
        self.client = client
        self._keys: dict[str, jwt.PyJWK] = {}
        self._valid_until = 0.0
        self._next_refresh = 0.0
        self._lock = asyncio.Lock()

    async def _key(self, kid: str) -> jwt.PyJWK:
        async with self._lock:
            now = time.monotonic()
            if now < self._valid_until and kid in self._keys:
                return self._keys[kid]
            if now < self._next_refresh:
                raise InvalidToken("KEY_UNAVAILABLE")
            # Set cooldown before I/O to stop attacker-controlled kid values from
            # causing one IdP request for every unauthenticated API call.
            self._next_refresh = now + self.settings.jwks_refresh_cooldown_seconds
            try:
                data = await bounded_json(self.client, "GET", self.settings.jwks_url, max_bytes=65536)
                raw_keys = data.get("keys")
                if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= 32:
                    raise InvalidToken("JWKS_SCHEMA")
                keys = {}
                for value in raw_keys:
                    if not isinstance(value, dict):
                        raise InvalidToken("JWKS_SCHEMA")
                    key_id = value.get("kid")
                    if not isinstance(key_id, str) or not 1 <= len(key_id) <= 128 or key_id in keys:
                        raise InvalidToken("JWKS_KEY_ID")
                    if value.get("use", "sig") != "sig" or value.get("alg") not in self.settings.algorithms:
                        continue
                    if any(field in value for field in ("d", "p", "q")):
                        raise InvalidToken("JWKS_PRIVATE_KEY")
                    if "key_ops" in value and value["key_ops"] != ["verify"]:
                        continue
                    key = jwt.PyJWK.from_dict(value)
                    if value["alg"] == "RS256" and getattr(key.key, "key_size", 0) < 2048:
                        raise InvalidToken("WEAK_KEY")
                    keys[key_id] = key
                self._keys = keys
                self._valid_until = time.monotonic() + self.settings.jwks_ttl_seconds
            except (Unavailable, jwt.PyJWTError, ValueError, TypeError) as exc:
                raise InvalidToken("KEY_UNAVAILABLE") from exc
            if kid not in self._keys:
                raise InvalidToken("UNKNOWN_KEY")
            return self._keys[kid]

    async def authenticate(self, token: str) -> Principal:
        if not isinstance(token, str) or len(token) > 8192:
            raise InvalidToken("TOKEN_SIZE")
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            alg = header.get("alg")
            if alg not in self.settings.algorithms or not isinstance(kid, str) or not 1 <= len(kid) <= 128:
                raise InvalidToken("TOKEN_HEADER")
            if header.get("crit") or header.get("jku") or header.get("x5u"):
                raise InvalidToken("TOKEN_HEADER")
            if self.settings.access_token_type and header.get("typ") != self.settings.access_token_type:
                raise InvalidToken("TOKEN_TYPE")
            key = await self._key(kid)
            if key.algorithm_name != alg:
                raise InvalidToken("ALGORITHM_MISMATCH")
            # Signature verification can consume CPU, so it does not block the async loop.
            claims = await asyncio.to_thread(
                jwt.decode,
                token,
                key.key,
                algorithms=[alg],
                audience=self.settings.audience,
                issuer=self.settings.issuer,
                leeway=0,
                options={"require": ["exp", "iat", "iss", "aud", "sub", self.settings.tenant_claim]},
            )
            exp, iat = claims["exp"], claims["iat"]
            if (
                type(exp) not in (int, float)
                or type(iat) not in (int, float)
                or not 0 < exp - iat <= self.settings.max_token_lifetime_seconds
            ):
                raise InvalidToken("TOKEN_LIFETIME")
            tenant = claims[self.settings.tenant_claim]
            if self.settings.allowed_tenants and tenant not in self.settings.allowed_tenants:
                raise InvalidToken("TENANT_NOT_ALLOWED")
            return Principal(
                subject=claims["sub"],
                tenant_id=tenant,
                expires_at=float(exp),
                roles=string_set(claims.get(self.settings.roles_claim, [])),
                scopes=string_set(claims.get(self.settings.scopes_claim, "")),
            )
        except (jwt.PyJWTError, ValidationError, TypeError, ValueError, KeyError) as exc:
            raise InvalidToken("INVALID_TOKEN") from exc
