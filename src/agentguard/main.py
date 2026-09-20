"""Authenticated API adapter; app construction is explicit and dependency-injectable."""

import asyncio
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware

from agentguard.adapters.http_model import HTTPModelProvider
from agentguard.adapters.sql import sql_ports
from agentguard.audit import Audit
from agentguard.config import Settings
from agentguard.engine import Guard
from agentguard.errors import Conflict, Denied, GuardError, InvalidToken, LimitExceeded, Unavailable
from agentguard.identity import JWTAuthenticator
from agentguard.middleware import SecurityMiddleware
from agentguard.models import ChatRequest, IngestRequest, OpaqueID, Principal
from agentguard.output_firewall import PatternScanner, PresidioScanner, Scanner
from agentguard.support import SupportPolicy, SupportSQLStore, ToolGateway


class EmptyBody(BaseModel):
    """Approval accepts no arguments, signatures, tenant IDs, or model-supplied claims."""

    model_config = ConfigDict(extra="forbid", strict=True)


def create_app(
    settings: Settings | None = None,
    *,
    guard: Guard | None = None,
    store: SupportSQLStore | None = None,
    policy: SupportPolicy | None = None,
    scanner: Scanner | None = None,
    authenticator: JWTAuthenticator | None = None,
) -> FastAPI:
    """Reference HTTP adapter over the bundled SQL storage and support domain.

    This is one deployment of the library, not the library. A host embedding
    ``Guard`` in its own service supplies its own ports and never imports this.
    """
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # The shared client disables proxy environment variables and redirects.
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5, read=settings.model_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        ) as client:
            local_store = None
            if guard is None:
                audit = Audit.from_settings(settings)
                local_store = SupportSQLStore(
                    settings,
                    audit,
                    max_waiver_cents=settings.max_waiver_cents,
                    auto_approve_below_cents=settings.auto_approve_below_cents,
                    approval_ttl_seconds=settings.approval_ttl_seconds,
                )
                if settings.environment == "development":
                    await asyncio.to_thread(local_store.initialize)
                else:
                    await asyncio.to_thread(local_store.verify_production)
                if settings.dlp_backend == "reviewed":
                    if scanner is None:
                        raise ValueError(
                            "GUARD_DLP_BACKEND=reviewed requires passing your own "
                            "evaluated Scanner to create_app"
                        )
                    active_scanner = scanner
                elif settings.dlp_backend == "presidio":
                    active_scanner = scanner or await asyncio.to_thread(PresidioScanner)
                else:
                    active_scanner = scanner or PatternScanner()
                ports = sql_ports(local_store)
                policy = SupportPolicy(settings.max_waiver_cents, settings.auto_approve_below_cents)
                app.state.policy = policy
                app.state.store = local_store
                app.state.guard = Guard(
                    provider=HTTPModelProvider(settings, client),
                    signer=audit,
                    limits=settings.limits(),
                    scanner=active_scanner,
                    tool_executor=ToolGateway(ports["documents"], policy),
                    **ports,
                )
            else:
                if settings.environment == "production" and store is not None:
                    await asyncio.to_thread(store.verify_production)
                app.state.guard = guard
                app.state.store = store
                app.state.policy = policy or SupportPolicy(
                    settings.max_waiver_cents, settings.auto_approve_below_cents
                )
            app.state.authenticator = authenticator or JWTAuthenticator(settings, client)
            try:
                yield
            finally:
                if local_store:
                    await asyncio.to_thread(local_store.close)

    app = FastAPI(title="AgentGuard", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_body_bytes)

    async def principal(request: Request) -> Principal:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
        return await request.app.state.authenticator.authenticate(authorization[7:])

    Auth = Annotated[Principal, Depends(principal)]

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # Framework validation errors include offending inputs by default, which
        # can reflect credentials or sensitive document text into response bodies.
        return JSONResponse({"detail": "invalid request"}, status_code=422)

    @app.exception_handler(GuardError)
    async def guard_error(request, exc):
        codes = {InvalidToken: 401, Denied: 404, Conflict: 409, LimitExceeded: 429, Unavailable: 503}
        status = next((value for kind, value in codes.items() if isinstance(exc, kind)), 503)
        detail = {
            401: "authentication required",
            404: "not found",
            409: "operation conflict",
            429: "resource limit reached",
            503: "service unavailable",
        }[status]
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else {}
        if status == 429:
            headers["Retry-After"] = "60"
        return JSONResponse({"detail": detail}, status_code=status, headers=headers)

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        # Operational logging is deliberately metadata-only; no str(exc) can leak
        # database URLs, request bodies, vendor responses, or authorization headers.
        return JSONResponse({"detail": "service unavailable"}, status_code=503)

    @app.get("/health/live")
    async def live():
        return {"status": "live"}

    @app.post("/conversations")
    async def conversation(body: EmptyBody, caller: Auth, request: Request):
        service, repo = request.app.state.guard, request.app.state.store
        ctx = service.context(caller)
        await asyncio.to_thread(repo.throttle, caller)
        identifier = await asyncio.to_thread(repo.create_conversation, ctx)
        return {"conversation_id": identifier}

    @app.delete("/conversations/{conversation_id}")
    async def delete_conversation(conversation_id: OpaqueID, caller: Auth, request: Request):
        service, repo = request.app.state.guard, request.app.state.store
        await asyncio.to_thread(repo.throttle, caller)
        await asyncio.to_thread(repo.delete_conversation, service.context(caller), conversation_id)
        return {"status": "deleted"}

    @app.post("/chat")
    async def chat(body: ChatRequest, caller: Auth, request: Request):
        return await request.app.state.guard.chat(caller, body)

    @app.post("/documents")
    async def ingest(body: IngestRequest, caller: Auth, request: Request):
        service, repo = request.app.state.guard, request.app.state.store
        await asyncio.to_thread(repo.throttle, caller)
        await asyncio.to_thread(repo.ingest, service.context(caller), body)
        return {"status": "stored"}

    @app.delete("/documents/{doc_id}")
    async def delete_document(doc_id: str, caller: Auth, request: Request):
        service, repo = request.app.state.guard, request.app.state.store
        await asyncio.to_thread(repo.throttle, caller)
        await asyncio.to_thread(repo.delete_document, service.context(caller), doc_id)
        return {"status": "deleted"}

    @app.get("/actions/{action_id}")
    async def pending(action_id: OpaqueID, caller: Auth, request: Request):
        repo = request.app.state.store
        await asyncio.to_thread(repo.throttle, caller)
        return await asyncio.to_thread(repo.pending_action, caller, action_id)

    @app.post("/actions/{action_id}/approve")
    async def approve(action_id: OpaqueID, body: EmptyBody, caller: Auth, request: Request):
        service, repo = request.app.state.guard, request.app.state.store
        ctx = service.context(caller)
        await asyncio.to_thread(repo.throttle, caller)
        return await asyncio.to_thread(repo.approve, ctx, action_id, request.app.state.policy)

    return app
