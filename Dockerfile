# Minimal runtime image. The application runs as a non-root user and owns nothing
# it executes: the virtual environment and source tree stay root-owned and
# read-only to that user, so a compromised request handler cannot rewrite its own
# code. Run the container with a read-only root filesystem and a tmpfs for /tmp.
#
# The build stage resolves dependencies from uv.lock, which is the same set CI
# audits with `pip-audit --locked`. Installing from pyproject.toml instead would
# silently float transitive versions and make the audited set and the shipped set
# different artifacts.
FROM python:3.12-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
# Pinned to the toolchain that produced uv.lock; an older uv cannot read its
# revision and would fail the build rather than resolve a different set.
COPY --from=ghcr.io/astral-sh/uv:0.12.9 /uv /bin/uv
WORKDIR /app
# Dependencies resolve before the source is copied so a code-only change reuses
# this layer and cannot quietly pull a different dependency set.
COPY pyproject.toml uv.lock README.md ./
# The extras are explicit: since the core depends only on Pydantic, a plain sync
# produces an image with no web server and no database driver, and the failure
# does not appear until the container tries to start.
RUN uv sync --locked --no-dev --extra sql --extra postgres --extra api --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --extra sql --extra postgres --extra api

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=build --chown=root:root /app /app
USER app
EXPOSE 8000
# The liveness route touches no database, secret, or model provider. Keep
# "127.0.0.1" in GUARD_ALLOWED_HOSTS or TrustedHostMiddleware rejects this probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).status == 200 else 1)"]
# Production supplies all GUARD_* values through the orchestrator secret/config APIs.
#
# Three are required for the process to start at all, and each fails at startup
# rather than on the first request:
#   GUARD_AUDIT_KEY      >= 32 bytes; without it there is no signed ledger
#   GUARD_DATABASE_URL   must point somewhere writable - /app is read-only here,
#                        so a SQLite path must be under the tmpfs, and production
#                        uses postgresql+psycopg://
#   GUARD_MODEL_URL      an HTTPS endpoint; the provider refuses to build without one
#
# Run it hardened. The image expects no writable application tree:
#   docker run --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     --cap-drop ALL --security-opt no-new-privileges \
#     -e GUARD_AUDIT_KEY=... -e GUARD_DATABASE_URL=... -e GUARD_MODEL_URL=... \
#     -p 8000:8000 agentguard
CMD ["uvicorn", "agentguard.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
