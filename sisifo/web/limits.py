"""Bound request bodies before multipart parsing; reject excessive login attempts."""

import threading
import time

from starlette.responses import JSONResponse


class BodyTooLarge(Exception):
    pass


class RequestLimits:
    def __init__(self, app):
        self.app = app
        self._lock = threading.Lock()
        self._attempts = []

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = 21 * 1024 * 1024 if scope["path"] == "/api/import-nmap" else 128 * 1024
        lengths = [v for k, v in scope.get("headers", []) if k.lower() == b"content-length"]
        try:
            excessive = any(int(value) > limit or int(value) < 0 for value in lengths)
        except ValueError:
            excessive = True
        if excessive:
            return await JSONResponse({"detail": "Corpo da requisição excede o limite."}, 413)(scope, receive, send)
        if scope["path"] == "/login" and scope["method"] == "POST":
            with self._lock:
                now = time.monotonic()
                self._attempts[:] = [t for t in self._attempts if now - t < 60]
                throttled = len(self._attempts) >= 10
                if not throttled:
                    self._attempts.append(now)
            if throttled:
                return await JSONResponse({"detail": "Aguarde antes de tentar novamente."}, 429)(scope, receive, send)
        size = 0
        async def limited_receive():
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > limit:
                raise BodyTooLarge()
            return message
        try:
            await self.app(scope, limited_receive, send)
        except BodyTooLarge:
            await JSONResponse({"detail": "Corpo da requisição excede o limite."}, 413)(scope, receive, send)
