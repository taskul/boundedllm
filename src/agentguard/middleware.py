"""Bound ASGI request bytes before JSON parsing and attach browser security headers."""

from starlette.responses import JSONResponse


class SecurityMiddleware:
    """Buffer at most max_body_bytes; do not trust Content-Length or chunked clients."""

    def __init__(
        self,
        app,
        max_body_bytes: int,
        content_security_policy: str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        upload_paths: frozenset[str] = frozenset(),
        upload_max_body_bytes: int = 2097152,
    ):
        self.app, self.max_body_bytes = app, max_body_bytes
        self.upload_paths = upload_paths
        self.upload_max_body_bytes = upload_max_body_bytes
        # API services retain the deny-all default. A web adapter may explicitly
        # allow its own static assets without enabling inline or remote code.
        self.content_security_policy = content_security_policy.encode("ascii")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # A plain dict() over the raw header list silently keeps the *last*
        # duplicate while Starlette's own lookup returns the *first*. That
        # disagreement lets a request be validated on one Content-Type and parsed
        # as another, so a repeated framing header is rejected outright instead.
        raw_headers = scope.get("headers", [])
        for name in (b"content-type", b"content-encoding"):
            if sum(1 for key, _ in raw_headers if key == name) > 1:
                return await JSONResponse({"detail": "ambiguous request framing"}, status_code=400)(
                    scope, receive, send
                )
        headers = dict(raw_headers)
        if headers.get(b"content-encoding", b"identity") != b"identity":
            return await JSONResponse({"detail": "unsupported encoding"}, status_code=415)(
                scope, receive, send
            )
        is_upload = scope.get("path") in self.upload_paths
        content_type = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
        if scope["method"] in {"POST", "PUT", "PATCH"}:
            allowed = {b"multipart/form-data"} if is_upload else {b"application/json"}
            if content_type not in allowed:
                return await JSONResponse({"detail": "JSON required"}, status_code=415)(scope, receive, send)
        messages = []
        total = 0
        body_limit = self.upload_max_body_bytes if is_upload else self.max_body_bytes
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > body_limit:
                return await JSONResponse({"detail": "request too large"}, status_code=413)(
                    scope, receive, send
                )
            messages.append(message)
            if not message.get("more_body", False):
                break
        position = 0

        async def replay():
            nonlocal position
            if position < len(messages):
                message = messages[position]
                position += 1
                return message
            return await receive()

        async def secure_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"x-frame-options", b"DENY"),
                    (
                        b"content-security-policy",
                        self.content_security_policy,
                    ),
                ]
            await send(message)

        await self.app(scope, replay, secure_send)
