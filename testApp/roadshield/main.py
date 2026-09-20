"""RoadShield website and JSON API, composed with the installed LLM guard package."""

import asyncio
import secrets
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from uuid import uuid4

try:
    import truststore
except ModuleNotFoundError:  # The standard SSL context is a secure fallback on supported Python builds.
    truststore = None

from boundedllm.adapters.sql import sql_ports
from boundedllm.audit import Audit
from boundedllm.config import Settings as GuardSettings
from boundedllm.engine import Guard
from boundedllm.errors import Denied
from boundedllm.middleware import SecurityMiddleware
from boundedllm.models import ChatRequest, IngestRequest, Principal
from boundedllm.normalize import normalize
from boundedllm.risk import assess
from boundedllm.support import SupportPolicy, SupportSQLStore, ToolGateway
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from roadshield.agent import InsuranceAgentProvider
from roadshield.attacks import CASES, protected_result, public_cases
from roadshield.claude import ClaudeProvider, build_client
from roadshield.config import AppSettings
from roadshield.documents import MAX_UPLOAD_BYTES, DocumentRejected, parse_pdf
from roadshield.prompts import ROADSHIELD_SYSTEM_POLICY
from roadshield.seed import seed
from roadshield.store import AppStore, DemoUser

STATIC = Path(__file__).parent / "static"


class StrictBody(BaseModel):
    """Reject undeclared client fields, including attempted tenant or role overrides."""

    model_config = ConfigDict(extra="forbid", strict=True)


class LoginBody(StrictBody):
    tenant_id: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9-]+$")
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=12, max_length=256)
    mfa_code: str | None = Field(default=None, pattern=r"^[0-9]{6}$")


class ChatBody(StrictBody):
    message: str = Field(min_length=1, max_length=4000)
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    attachment_ids: list[str] = Field(default_factory=list, max_length=4)


class SecurityCaseBody(StrictBody):
    state: str = Field(pattern=r"^(open|acknowledged|resolved)$")
    case_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:@/-]+$")


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Factory enables temporary databases in tests and avoids import-time secrets."""
    app_settings = settings or AppSettings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app_store = AppStore(app_settings)
        app_store.initialize()
        model_name = (
            app_settings.anthropic_model if app_settings.anthropic_api_key else "roadshield-simulator"
        )
        guard_settings = GuardSettings(
            database_url=app_settings.database_url,
            audit_key=app_settings.secret,
            model_name=model_name,
            allowed_models=frozenset({model_name}),
            allowed_tenants=frozenset({"roadshield-midwest", "globex-insurance"}),
            max_docs=4,
            user_requests_per_minute=60,
            tenant_requests_per_minute=200,
        )
        guard_audit = Audit(guard_settings.audit_key.get_secret_value(), guard_settings.audit_key_id)
        guard_store = SupportSQLStore(guard_settings, guard_audit)
        guard_store.initialize()
        model_client = None
        if app_settings.anthropic_api_key:
            # Use the operating-system CA store so managed enterprise roots work
            # without disabling TLS verification or trusting ambient proxies.
            tls_context = (
                truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if truststore is not None
                else ssl.create_default_context()
            )
            model_client = build_client(app_settings.anthropic_api_key, tls_context)
            provider = ClaudeProvider(
                app_settings.anthropic_api_key, model_client, app_settings.anthropic_model
            )
            provider_name = f"Claude - {app_settings.anthropic_model}"
        else:
            provider = InsuranceAgentProvider()
            provider_name = "Local deterministic simulator"
        # Composed through the port contract, exactly as a host integration would.
        guard_ports = sql_ports(guard_store)
        guard = Guard(
            provider=provider,
            signer=guard_audit,
            limits=guard_settings.limits(),
            tool_executor=ToolGateway(guard_ports["documents"], SupportPolicy()),
            system_policy=ROADSHIELD_SYSTEM_POLICY,
            **guard_ports,
        )
        await asyncio.to_thread(seed, app_store, guard_store)
        app.state.app_store, app.state.guard_store = app_store, guard_store
        app.state.guard, app.state.agent_provider = guard, provider
        app.state.provider_name = provider_name
        try:
            yield
        finally:
            if model_client is not None:
                await model_client.close()
            await asyncio.to_thread(app_store.close)
            await asyncio.to_thread(guard_store.close)

    app = FastAPI(
        title="RoadShield Attack Lab", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
    app.add_middleware(
        SecurityMiddleware,
        max_body_bytes=32768,
        upload_paths=frozenset({"/api/chat/upload"}),
        upload_max_body_bytes=app_settings.upload_max_bytes + 65536,
        content_security_policy=(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        ),
    )

    def require_origin(request: Request) -> None:
        """SameSite cookies are strengthened with an exact Origin check on writes."""
        if request.headers.get("origin") != app_settings.origin:
            raise HTTPException(403, "request origin rejected")

    def current_user(request: Request, roadshield_session: str | None = Cookie(default=None)) -> DemoUser:
        if not roadshield_session or len(roadshield_session) > 256:
            raise HTTPException(401, "authentication required")
        user = request.app.state.app_store.authenticate(roadshield_session)
        if not user:
            raise HTTPException(401, "authentication required")
        return user

    User = Annotated[DemoUser, Depends(current_user)]

    def require_csrf(
        request: Request,
        x_csrf_token: str | None = Header(default=None),
        roadshield_session: str | None = Cookie(default=None),
        roadshield_csrf: str | None = Cookie(default=None),
    ) -> None:
        require_origin(request)
        if (
            not roadshield_session
            or not x_csrf_token
            or not roadshield_csrf
            or not secrets.compare_digest(x_csrf_token, roadshield_csrf)
            or not request.app.state.app_store.validate_csrf(roadshield_session, x_csrf_token)
        ):
            raise HTTPException(403, "request verification failed")

    Csrf = Annotated[None, Depends(require_csrf)]

    @app.exception_handler(Exception)
    async def unexpected(request, exc):
        # Lab responses never expose database errors, credentials, or rejected payloads.
        if isinstance(exc, HTTPException):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return JSONResponse({"detail": "service unavailable"}, status_code=503)

    @app.get("/")
    async def home():
        return FileResponse(STATIC / "index.html")

    @app.post("/api/auth/login")
    async def login(body: LoginBody, request: Request, response: Response):
        require_origin(request)
        try:
            user, session_token, csrf_token = await asyncio.to_thread(
                request.app.state.app_store.login,
                body.tenant_id,
                body.email,
                body.password,
                request.client.host if request.client else "unknown",
                body.mfa_code,
            )
        except PermissionError:
            raise HTTPException(401, "invalid credentials") from None
        response.set_cookie(
            "roadshield_session",
            session_token,
            httponly=True,
            secure=app_settings.cookie_secure,
            samesite="strict",
            max_age=app_settings.session_seconds,
            path="/",
        )
        response.set_cookie(
            "roadshield_csrf",
            csrf_token,
            httponly=False,
            secure=app_settings.cookie_secure,
            samesite="strict",
            max_age=app_settings.session_seconds,
            path="/",
        )
        return {"display_name": user.display_name}

    @app.post("/api/auth/logout")
    async def logout(
        request: Request, response: Response, user: User, csrf: Csrf, roadshield_session: str = Cookie()
    ):
        await asyncio.to_thread(request.app.state.app_store.logout, roadshield_session)
        response.delete_cookie("roadshield_session", path="/")
        response.delete_cookie("roadshield_csrf", path="/")
        return {"status": "signed-out"}

    @app.get("/api/dashboard")
    async def dashboard(request: Request, user: User):
        return await asyncio.to_thread(request.app.state.app_store.dashboard, user)

    @app.get("/api/agent/status")
    async def agent_status(request: Request, user: User):
        """Expose the selected model name without exposing credentials or configuration."""
        return {"provider": request.app.state.provider_name}

    @app.post("/api/chat/upload")
    async def upload_chat_document(
        request: Request,
        user: User,
        csrf: Csrf,
        file: Annotated[UploadFile, File()],
    ):
        """Ingest a text-only PDF bound to this exact customer conversation."""
        principal = _principal(user).model_copy(
            update={"scopes": user.scopes | frozenset({"documents:write"})}
        )
        ctx = request.app.state.guard.context(principal)
        # Parsing a 2 MB PDF costs far more than a chat turn, so this endpoint
        # needs the shared quota at least as much as the others do.
        await asyncio.to_thread(request.app.state.guard_store.throttle, principal)
        doc_id = f"upload-{uuid4().hex}"
        await asyncio.to_thread(
            request.app.state.guard_store.event,
            ctx,
            "document_upload_received",
            document_ids=[doc_id],
            status="received",
            severity="info",
        )
        try:
            payload = await file.read(MAX_UPLOAD_BYTES + 1)
            parsed = await asyncio.to_thread(parse_pdf, file.filename, file.content_type, payload)
        except DocumentRejected as exc:
            await asyncio.to_thread(
                request.app.state.guard_store.event,
                ctx,
                "document_upload_rejected",
                document_ids=[doc_id],
                code="FILE_VALIDATION_FAILED",
                status="rejected",
                severity="medium",
            )
            raise HTTPException(400, str(exc)) from None
        finally:
            await file.close()
        # Remove secret-shaped and common PII before storing the text. Retrieval
        # applies the same minimization again before any model call.
        body = await request.app.state.guard.firewall.minimize(parsed.text)
        document_risk = assess(normalize(body))
        await asyncio.to_thread(
            request.app.state.guard_store.event,
            ctx,
            "document_upload_validated",
            document_ids=[doc_id],
            status="scanned",
            signals=list(document_risk.signals),
            severity="info" if document_risk.action == "continue" else "high",
        )
        await asyncio.to_thread(
            request.app.state.guard_store.ingest,
            ctx,
            IngestRequest(
                doc_id=doc_id,
                classification="internal",
                allowed_roles=[user.role],
                source="customer_upload_pdf",
                body=body,
                owner_subject=user.id,
                conversation_id=user.conversation_id,
                retention_policy="customer-upload-30d",
            ),
        )
        if document_risk.action != "continue":
            await asyncio.to_thread(
                request.app.state.guard_store.quarantine_document,
                ctx,
                doc_id,
                list(document_risk.signals),
            )
            return {
                "document_id": doc_id,
                "filename": parsed.filename,
                "pages": parsed.pages,
                "state": "quarantined",
                "message": "Quarantined because the extracted text contained instruction-like content.",
            }
        return {
            "document_id": doc_id,
            "filename": parsed.filename,
            "pages": parsed.pages,
            "state": "ready",
            "message": "Validated, scanned, and bound to this conversation.",
        }

    @app.post("/api/chat")
    async def chat(body: ChatBody, request: Request, user: User, csrf: Csrf):
        result = await request.app.state.guard.chat(
            _principal(user),
            ChatRequest(
                message=body.message,
                conversation_id=user.conversation_id,
                operation_id=body.operation_id,
                attachment_ids=body.attachment_ids,
            ),
        )
        return result

    @app.get("/api/attacks")
    async def attacks(user: User):
        return {"scenarios": public_cases()}

    @app.post("/api/attacks/{scenario}")
    async def run_attack(scenario: str, request: Request, user: User, csrf: Csrf):
        case = CASES.get(scenario)
        if not case:
            raise HTTPException(404, "scenario not found")
        result = await request.app.state.guard.chat(
            _principal(user),
            ChatRequest(message=case.message, conversation_id=user.conversation_id, operation_id=uuid4().hex),
        )
        protected = protected_result(case, result.status, result.answer)
        run_id = await asyncio.to_thread(
            request.app.state.app_store.record_attack, user, scenario, result.status, protected
        )
        return {
            "run_id": run_id,
            "scenario": scenario,
            "expected": case.expected_status,
            "actual": result.status,
            "protected": protected,
            "answer": result.answer,
            "provider": request.app.state.provider_name,
        }

    @app.get("/api/attacks/history")
    async def attack_history(request: Request, user: User):
        return {"runs": await asyncio.to_thread(request.app.state.app_store.attack_history, user)}

    def require_security_admin(user: DemoUser) -> None:
        """Both the dedicated role and scope must be present on the verified session."""
        if user.role != "security_admin" or "security:audit" not in user.scopes:
            raise HTTPException(403, "security administrator access required")

    @app.get("/api/security/overview")
    async def security_overview(request: Request, user: User):
        require_security_admin(user)
        stats, integrity, quarantined = await asyncio.gather(
            asyncio.to_thread(request.app.state.guard_store.audit_stats, user.tenant_id),
            asyncio.to_thread(request.app.state.guard_store.verify_audit_chain, user.tenant_id),
            asyncio.to_thread(request.app.state.guard_store.list_quarantined_documents, user.tenant_id, 25),
        )
        return {"stats": stats, "integrity": integrity, "quarantined": quarantined}

    @app.get("/api/security/events")
    async def security_events(
        request: Request,
        user: User,
        limit: Annotated[int, Query(ge=1, le=250)] = 100,
        event_type: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")] = None,
        severity: Annotated[str | None, Query(pattern=r"^(info|low|medium|high|critical)$")] = None,
        model: Annotated[str | None, Query(pattern=r"^[A-Za-z0-9_.:@/-]{1,128}$")] = None,
        subject_fingerprint: Annotated[str | None, Query(pattern=r"^[a-f0-9]{64}$")] = None,
        since: Annotated[float | None, Query(ge=0)] = None,
        until: Annotated[float | None, Query(ge=0)] = None,
    ):
        require_security_admin(user)
        events = await asyncio.to_thread(
            request.app.state.guard_store.list_audit_events,
            user.tenant_id,
            limit=limit,
            event_type=event_type,
            severity=severity,
            model=model,
            subject_fingerprint=subject_fingerprint,
            since=since,
            until=until,
        )
        # Reading the security ledger is itself a privileged, metadata-only event.
        ctx = request.app.state.guard.context(_principal(user))
        await asyncio.to_thread(
            request.app.state.guard_store.event,
            ctx,
            "audit_viewed",
            count=len(events),
            status="OK",
            severity="info",
        )
        return {"events": events}

    @app.get("/api/security/events/{event_id}")
    async def security_event(event_id: str, request: Request, user: User):
        require_security_admin(user)
        if len(event_id) != 32 or any(char not in "0123456789abcdef" for char in event_id):
            raise HTTPException(404, "event not found")
        event = await asyncio.to_thread(
            request.app.state.guard_store.get_audit_event, user.tenant_id, event_id
        )
        if event is None:
            raise HTTPException(404, "event not found")
        await asyncio.to_thread(
            request.app.state.guard_store.event,
            request.app.state.guard.context(_principal(user)),
            "audit_viewed",
            related_event_id=event_id,
            count=1,
            status="OK",
            severity="info",
        )
        return event

    @app.post("/api/security/events/{event_id}/case")
    async def update_security_case(
        event_id: str,
        body: SecurityCaseBody,
        request: Request,
        user: User,
        csrf: Csrf,
    ):
        require_security_admin(user)
        if len(event_id) != 32 or any(char not in "0123456789abcdef" for char in event_id):
            raise HTTPException(404, "event not found")
        try:
            return await asyncio.to_thread(
                request.app.state.guard_store.update_security_case,
                request.app.state.guard.context(_principal(user)),
                event_id,
                body.state,
                body.case_id,
            )
        except Denied:
            raise HTTPException(404, "event not found") from None

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def _principal(user: DemoUser) -> Principal:
    """The authenticated session is the only source of tenant, subject, role, and scopes."""
    return Principal(
        subject=user.id,
        tenant_id=user.tenant_id,
        roles=frozenset({user.role}),
        scopes=user.scopes,
        expires_at=user.expires_at,
    )
