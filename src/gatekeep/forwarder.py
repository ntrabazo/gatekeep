"""Forward the (possibly rewritten) request upstream. The proxy holds no API key —
the client's x-api-key and anthropic-version headers pass through verbatim.
host and content-length are stripped: host must match upstream, and content-length
is stale once the body has been rewritten."""

import httpx

UPSTREAM_URL = "https://api.anthropic.com/v1/messages"
_STRIP = {"host", "content-length"}


async def forward(content: bytes, headers: dict) -> httpx.Response:
    out_headers = {k: v for k, v in headers.items() if k.lower() not in _STRIP}
    async with httpx.AsyncClient(timeout=120.0) as client:
        return await client.post(UPSTREAM_URL, content=content, headers=out_headers)
