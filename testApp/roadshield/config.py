"""Application configuration keeps browser and session policy outside request data."""

import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

APP_ROOT = Path(__file__).resolve().parents[1]
LOCAL_STATE_FILE = ".roadshield-dev-secret"
LOCAL_ENV_KEYS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "TESTAPP_CLAUDE_MODEL",
        "TESTAPP_COOKIE_SECURE",
        "TESTAPP_DATABASE_URL",
        "TESTAPP_ENVIRONMENT",
        "TESTAPP_ORIGIN",
        "TESTAPP_SECRET",
        "TESTAPP_SECRET_FILE",
    }
)


def _load_local_env() -> None:
    """Load only known settings from .env without interpolation or value logging."""
    try:
        lines = (APP_ROOT / ".env").read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return
    for raw in lines:
        statement = raw.strip()
        if not statement or statement.startswith("#"):
            continue
        if statement.startswith("export "):
            statement = statement[7:].lstrip()
        key, separator, value = statement.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or key not in LOCAL_ENV_KEYS or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[key] = value


def _load_or_create_development_secret() -> str:
    """Keep the disposable lab's pepper stable across server restarts.

    Production must inject ``TESTAPP_SECRET`` from a secret manager. The local
    lab instead creates a private, ignored file so its persistent SQLite
    password hashes and sessions remain usable after restarting Uvicorn.
    """
    path = Path(os.getenv("TESTAPP_SECRET_FILE", APP_ROOT / LOCAL_STATE_FILE))
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = secrets.token_urlsafe(48)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Exclusive creation prevents two starting workers from silently
            # choosing different secrets for the same development database.
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            value = path.read_text(encoding="utf-8").strip()
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(value)
    if len(value.encode()) < 32:
        raise ValueError("development secret file must contain at least 32 bytes")
    return value


@dataclass(frozen=True)
class AppSettings:
    """Small explicit settings object suitable for environment or test composition."""

    database_url: str
    secret: str
    origin: str
    cookie_secure: bool
    environment: str = "development"
    session_seconds: int = 3600
    login_attempts_per_minute: int = 8
    # Applies to the account regardless of source address, so spreading guesses
    # across many addresses does not evade the lockout.
    account_login_attempts_per_minute: int = 20
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-opus-5"
    upload_max_bytes: int = 2 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "AppSettings":
        # The local file is ignored by Git. Existing process environment always
        # wins, matching production secret-injection behavior.
        _load_local_env()
        environment = os.getenv("TESTAPP_ENVIRONMENT", "development")
        raw_secret = os.getenv("TESTAPP_SECRET")
        if environment == "production" and not raw_secret:
            raise ValueError("TESTAPP_SECRET is required outside the disposable lab")
        secret = raw_secret or _load_or_create_development_secret()
        origin = os.getenv("TESTAPP_ORIGIN", "http://127.0.0.1:8010")
        secure = os.getenv("TESTAPP_COOKIE_SECURE", "false").lower() == "true"
        if len(secret.encode()) < 32:
            raise ValueError("TESTAPP_SECRET must contain at least 32 bytes")
        if environment == "production" and (not origin.startswith("https://") or not secure):
            raise ValueError("production requires an HTTPS origin and Secure cookies")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        anthropic_model = os.getenv("TESTAPP_CLAUDE_MODEL", "claude-opus-5").strip()
        if not re.fullmatch(r"claude-[a-z0-9-]{3,80}", anthropic_model):
            raise ValueError("TESTAPP_CLAUDE_MODEL is invalid")
        return cls(
            database_url=os.getenv(
                "TESTAPP_DATABASE_URL", f"sqlite:///{(APP_ROOT / 'testapp.db').as_posix()}"
            ),
            secret=secret,
            origin=origin.rstrip("/"),
            cookie_secure=secure,
            environment=environment,
            anthropic_api_key=SecretStr(anthropic_key) if anthropic_key else None,
            anthropic_model=anthropic_model,
        )
