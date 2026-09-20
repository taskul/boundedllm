"""Tenant-scoped application repository for users, policies, claims, sessions, and lab results."""

import json
import time
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import create_engine, delete, insert, inspect, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from roadshield.auth import fingerprint, hash_password, new_token, verify_password, verify_totp
from roadshield.config import AppSettings
from roadshield.schema import attack_runs, claims, login_limits, metadata, policies, sessions, users


@dataclass(frozen=True)
class DemoUser:
    """Authenticated identity; password hashes and unnecessary PII stay in the repository."""

    id: str
    tenant_id: str
    email: str
    display_name: str
    role: str
    scopes: frozenset[str]
    conversation_id: str
    expires_at: float


class AppStore:
    """Every user-data query includes both tenant and authenticated user identifiers."""

    def __init__(self, settings: AppSettings):
        self.settings = settings
        kwargs = {"pool_pre_ping": True}
        if settings.database_url.startswith("sqlite:"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 5}
        self.engine = create_engine(settings.database_url, **kwargs)

    def initialize(self) -> None:
        metadata.create_all(self.engine)
        # Preserve databases created before the admin MFA field was introduced.
        columns = {column["name"] for column in inspect(self.engine).get_columns("demo_users")}
        if "mfa_secret" not in columns:
            with self.engine.begin() as conn:
                conn.exec_driver_sql("ALTER TABLE demo_users ADD COLUMN mfa_secret VARCHAR(64)")

    def seed_user(
        self,
        *,
        tenant_id: str,
        email: str,
        password: str,
        display_name: str,
        phone: str,
        address: str,
        role: str,
        scopes: set[str],
        conversation_id: str,
        mfa_secret: str | None = None,
        refresh_password: bool = False,
    ) -> str:
        """Create a fixture and optionally repair its known lab password hash."""
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(users.c.id).where(users.c.tenant_id == tenant_id, users.c.email == email.lower())
            ).scalar()
            if existing:
                if refresh_password:
                    # Early lab releases generated a new pepper on restart.
                    # Refreshing synthetic hashes upgrades those databases
                    # without deleting policies or attack history.
                    conn.execute(
                        update(users)
                        .where(users.c.id == existing, users.c.tenant_id == tenant_id)
                        .values(
                            password_hash=hash_password(password, self.settings.secret),
                            mfa_secret=mfa_secret,
                            scopes=json.dumps(sorted(scopes)),
                            role=role,
                        )
                    )
                return existing
            user_id = uuid4().hex
            conn.execute(
                insert(users).values(
                    id=user_id,
                    tenant_id=tenant_id,
                    email=email.lower(),
                    password_hash=hash_password(password, self.settings.secret),
                    display_name=display_name,
                    phone=phone,
                    address=address,
                    role=role,
                    scopes=json.dumps(sorted(scopes)),
                    conversation_id=conversation_id,
                    mfa_secret=mfa_secret,
                )
            )
            return user_id

    def seed_policy(self, **values) -> None:
        with self.engine.begin() as conn:
            if not conn.execute(
                select(policies.c.id).where(policies.c.policy_number == values["policy_number"])
            ).first():
                conn.execute(insert(policies).values(id=uuid4().hex, **values))

    def seed_claim(self, **values) -> None:
        with self.engine.begin() as conn:
            if not conn.execute(
                select(claims.c.id).where(claims.c.claim_number == values["claim_number"])
            ).first():
                conn.execute(insert(claims).values(id=uuid4().hex, **values))

    def _count_attempt(self, conn, key: str, bucket: int, ceiling: int) -> None:
        conn.execute(
            sqlite_insert(login_limits)
            .values(key_hash=key, bucket=bucket, attempts=0)
            .on_conflict_do_nothing()
        )
        row = conn.execute(
            select(login_limits.c.attempts).where(
                login_limits.c.key_hash == key, login_limits.c.bucket == bucket
            )
        ).scalar_one()
        if row >= ceiling:
            raise PermissionError("login rate exceeded")
        conn.execute(
            update(login_limits)
            .where(login_limits.c.key_hash == key, login_limits.c.bucket == bucket)
            .values(attempts=row + 1)
        )

    def _throttle_login(self, conn, email: str, remote: str) -> None:
        """Count attempts per source and, separately, per account.

        Keying only on (account, address) leaves the account itself unprotected:
        an attacker spreading guesses across many addresses never reaches the
        ceiling. The per-account counter closes that, with a higher ceiling so a
        shared office address does not lock out a legitimate user.
        """
        bucket = int(time.time() // 60)
        identity = email.lower()
        self._count_attempt(
            conn,
            fingerprint(f"{identity}|{remote}", self.settings.secret),
            bucket,
            self.settings.login_attempts_per_minute,
        )
        self._count_attempt(
            conn,
            fingerprint(f"account|{identity}", self.settings.secret),
            bucket,
            self.settings.account_login_attempts_per_minute,
        )

    @staticmethod
    def _user(row, expires_at: float) -> DemoUser:
        return DemoUser(
            id=row["id"],
            tenant_id=row["tenant_id"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            scopes=frozenset(json.loads(row["scopes"])),
            conversation_id=row["conversation_id"],
            expires_at=expires_at,
        )

    def login(
        self,
        tenant_id: str,
        email: str,
        password: str,
        remote: str,
        mfa_code: str | None = None,
    ) -> tuple[DemoUser, str, str]:
        """Use the same public response for unknown users and invalid passwords."""
        # The attempt is recorded and committed before the credentials are
        # checked. Sharing a transaction with the check meant the rollback on
        # "invalid credentials" discarded the very increment that failure was
        # supposed to record, so the counter only ever saw successful logins and
        # the lockout never engaged.
        with self.engine.begin() as throttle_conn:
            self._throttle_login(throttle_conn, f"{tenant_id}:{email}", remote)
        with self.engine.begin() as conn:
            row = (
                conn.execute(
                    select(users).where(users.c.tenant_id == tenant_id, users.c.email == email.lower())
                )
                .mappings()
                .first()
            )
            encoded = (
                row["password_hash"]
                if row
                else hash_password("constant-dummy-password", self.settings.secret)
            )
            valid = verify_password(password, encoded, self.settings.secret)
            mfa_valid = not row or not row["mfa_secret"] or verify_totp(row["mfa_secret"], mfa_code)
            if row is None or not valid or not mfa_valid:
                raise PermissionError("invalid credentials")
            session_token, csrf_token = new_token(), new_token()
            now = time.time()
            conn.execute(
                insert(sessions).values(
                    token_hash=fingerprint(session_token, self.settings.secret),
                    user_id=row["id"],
                    tenant_id=row["tenant_id"],
                    csrf_hash=fingerprint(csrf_token, self.settings.secret),
                    expires_at=now + self.settings.session_seconds,
                    created_at=now,
                )
            )
            return self._user(row, now + self.settings.session_seconds), session_token, csrf_token

    def authenticate(self, session_token: str) -> DemoUser | None:
        token_hash = fingerprint(session_token, self.settings.secret)
        with self.engine.begin() as conn:
            row = (
                conn.execute(
                    select(sessions).where(
                        sessions.c.token_hash == token_hash, sessions.c.expires_at > time.time()
                    )
                )
                .mappings()
                .first()
            )
            if not row:
                return None
            user = (
                conn.execute(
                    select(users).where(users.c.id == row["user_id"], users.c.tenant_id == row["tenant_id"])
                )
                .mappings()
                .first()
            )
            return self._user(user, row["expires_at"]) if user else None

    def validate_csrf(self, session_token: str, csrf_token: str) -> bool:
        with self.engine.connect() as conn:
            expected = conn.execute(
                select(sessions.c.csrf_hash).where(
                    sessions.c.token_hash == fingerprint(session_token, self.settings.secret),
                    sessions.c.expires_at > time.time(),
                )
            ).scalar()
        return bool(expected and hmac_compare(expected, fingerprint(csrf_token, self.settings.secret)))

    def logout(self, session_token: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                delete(sessions).where(
                    sessions.c.token_hash == fingerprint(session_token, self.settings.secret)
                )
            )

    def dashboard(self, user: DemoUser) -> dict:
        """Return PII to its owner for UI display; this object never enters an LLM prompt."""
        with self.engine.connect() as conn:
            profile = (
                conn.execute(
                    select(users.c.display_name, users.c.email, users.c.phone, users.c.address).where(
                        users.c.id == user.id, users.c.tenant_id == user.tenant_id
                    )
                )
                .mappings()
                .one()
            )
            policy_rows = (
                conn.execute(
                    select(policies).where(
                        policies.c.user_id == user.id, policies.c.tenant_id == user.tenant_id
                    )
                )
                .mappings()
                .all()
            )
            claim_rows = (
                conn.execute(
                    select(claims).where(claims.c.user_id == user.id, claims.c.tenant_id == user.tenant_id)
                )
                .mappings()
                .all()
            )
            return {
                "profile": dict(profile),
                "policies": [dict(row) for row in policy_rows],
                "claims": [dict(row) for row in claim_rows],
                "security_admin": "security:audit" in user.scopes and user.role == "security_admin",
            }

    def record_attack(self, user: DemoUser, scenario: str, status: str, protected: bool) -> str:
        identifier = uuid4().hex
        with self.engine.begin() as conn:
            conn.execute(
                insert(attack_runs).values(
                    id=identifier,
                    tenant_id=user.tenant_id,
                    user_id=user.id,
                    scenario=scenario,
                    result_status=status,
                    protected=int(protected),
                    created_at=time.time(),
                )
            )
        return identifier

    def attack_history(self, user: DemoUser) -> list[dict]:
        with self.engine.connect() as conn:
            rows = (
                conn.execute(
                    select(
                        attack_runs.c.id,
                        attack_runs.c.scenario,
                        attack_runs.c.result_status,
                        attack_runs.c.protected,
                        attack_runs.c.created_at,
                    )
                    .where(attack_runs.c.tenant_id == user.tenant_id, attack_runs.c.user_id == user.id)
                    .order_by(attack_runs.c.created_at.desc())
                    .limit(30)
                )
                .mappings()
                .all()
            )
        return [{**dict(row), "protected": bool(row["protected"])} for row in rows]

    def close(self) -> None:
        self.engine.dispose()


def hmac_compare(left: str, right: str) -> bool:
    """Keep comparison timing independent of the first mismatching character."""
    import hmac

    return hmac.compare_digest(left, right)
