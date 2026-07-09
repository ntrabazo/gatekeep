# Integration

Gatekeep speaks the Anthropic Messages API verbatim. Adopting it means pointing your
existing client at the proxy's address instead of `api.anthropic.com`. No code changes
beyond that one line, no SDK subclass, no custom transport.

Assume the proxy is running at `http://127.0.0.1:8100` (see the README quickstart or
[deployment.md](deployment.md) for a real host).

## Python (Anthropic SDK)

```python
import anthropic

client = anthropic.Anthropic(
    base_url="http://127.0.0.1:8100",   # the only change
    api_key="sk-ant-...",               # your real key — forwarded, never stored by the proxy
)

resp = client.messages.create(
    model="claude-haiku-4-5-20251001",
    max_tokens=256,
    messages=[{"role": "user", "content": "Summarize this ticket."}],
)
print(resp.content[0].text)
```

If a prompt trips a **block** rule, the SDK raises `anthropic.APIStatusError` with
`status_code == 403` and a message like `Gatekeep policy violation: secret`. If it trips
a **redact** rule, the call succeeds normally — the model simply received
`[REDACTED:...]` in place of the sensitive span.

## curl / any HTTP client

Because it's a transparent proxy, anything that can POST to the Messages API works —
any language, any framework. Just change the host:

```bash
curl http://127.0.0.1:8100/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-haiku-4-5-20251001",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

## Node / TypeScript

```ts
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  baseURL: "http://127.0.0.1:8100",
  apiKey: process.env.ANTHROPIC_API_KEY,
});
```

## What to tell your users

When a request is blocked, your app receives a `403`. Surface a clear message ("This
request was blocked because it contained a credential") rather than a raw error, so the
user knows to remove the sensitive value and retry.

## Reading the audit trail

Every decision is queryable over HTTP:

```bash
curl "http://127.0.0.1:8100/audit?action=block&limit=20"
```

Filters: `action` (`allow` / `redact` / `block` / `reject_stream`), `since` (ISO-8601 UTC
timestamp), `limit`. Rows contain metadata only — never the sensitive text. See
[architecture.md](architecture.md#the-never-log-rule).

## Known limitations to design around

- **Streaming is not supported.** Requests with `stream: true` get a `400`. If your app
  streams, disable it for traffic routed through Gatekeep, or keep streaming on a separate
  path (v1 scans complete request bodies, not token streams).
- **Responses are not scanned** — only the prompts you send.
