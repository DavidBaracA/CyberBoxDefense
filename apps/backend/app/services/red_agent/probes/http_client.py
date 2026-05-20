"""Small dependency-free async HTTP client for safe bounded probes."""

from __future__ import annotations

import asyncio
from typing import Mapping, Optional
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import HttpResponse


class NoRedirectHandler(HTTPRedirectHandler):
    """Return redirect responses to callers instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibAsyncHttpClient:
    """Async wrapper around urllib with redirects disabled by default."""

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: float = 5.0,
        follow_redirects: bool = False,
    ) -> HttpResponse:
        return await asyncio.to_thread(
            self._request_sync,
            method,
            url,
            dict(headers or {}),
            body,
            timeout,
            follow_redirects,
        )

    def _request_sync(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[bytes],
        timeout: float,
        follow_redirects: bool,
    ) -> HttpResponse:
        opener = build_opener() if follow_redirects else build_opener(NoRedirectHandler)
        request = Request(url=url, data=body, headers=headers, method=method.upper())
        try:
            with opener.open(request, timeout=timeout) as response:
                content = response.read()
                return HttpResponse(
                    status_code=int(response.status),
                    url=response.geturl(),
                    headers={key: value for key, value in response.headers.items()},
                    text=content.decode("utf-8", errors="replace"),
                    content=content,
                )
        except HTTPError as exc:
            content = exc.read()
            return HttpResponse(
                status_code=int(exc.code),
                url=url,
                headers={key: value for key, value in exc.headers.items()},
                text=content.decode("utf-8", errors="replace"),
                content=content,
            )
