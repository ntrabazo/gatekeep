# Gatekeep

**A prompt firewall for the Anthropic API.** Gatekeep is a drop-in reverse proxy that scans
every prompt *before* it reaches the model — blocking secrets, redacting personal data, and
audit-logging every decision — without ever storing the sensitive text it catches.

Point your app at Gatekeep instead of `api.anthropic.com` (one line), and every request your
team sends to Claude passes through a policy checkpoint you control.

```python
client = anthropic.Anthropic(base_url="http://127.0.0.1:8100", api_key=...)  # the only change
```

---

## Why

Anyone can paste an AWS key, a customer's SSN, or a signing token straight into an AI chat
tool — and today nothing stops it, and nothing records that it happened. Data-loss prevention
for the AI era has to live in the request path: after the user hits send, before the API sees
a byte. That's what Gatekeep does.

- **Secrets** (API keys, tokens, private keys) → **blocked**. The request never reaches the model.
- **Personal data** (SSNs, credit cards, emails, phones) → **redacted**. The rest of the request still goes through.
- **Everything else** → **allowed**, untouched.
- **Every decision** → **audit-logged** (hashes and categories only, never the raw text).

All of it is governed by a single YAML file, not code.

## Live demo

Open [`demo/index.html`](demo/index.html) in a browser — the full detection pipeline,
ported to JavaScript, running entirely client-side. Type a prompt, watch it get blocked,
redacted, or allowed, and see the audit trail fill in. No API key, no server. The port is
parity-tested against the Python engine on the whole red-team corpus
(see [demo/README.md](demo/README.md)).

## Quickstart

**With Docker:**

```bash
docker compose up --build          # serves on http://127.0.0.1:8100
```

**Or directly (Python 3.12):**

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip install -r requirements.txt
.venv/bin/uvicorn gatekeep.main:app --app-dir src --host 0.0.0.0 --port 8100
```

Then point any Anthropic client at it — see **[docs/integration.md](docs/integration.md)**.
The proxy holds **no API key of its own**; it forwards whatever key each client already sends.

Try it end to end against the real model:

```bash
cp .env.example .env               # add your ANTHROPIC_API_KEY (for the demo client only)
python harness/run_harness.py      # offline test suite — no API calls, exit 0 = green
python harness/demo.py             # live demo through the proxy
```

## Documentation

| Doc | What's in it |
|---|---|
| **[docs/integration.md](docs/integration.md)** | Point your app at the proxy — Python, curl, Node, any HTTP client |
| **[docs/configuration.md](docs/configuration.md)** | The full `policies.yaml` schema and tuning recipes |
| **[docs/deployment.md](docs/deployment.md)** | Docker, running as a service, production hardening |
| **[docs/architecture.md](docs/architecture.md)** | How the request pipeline and detection layers work internally |

## How detection works

Hybrid by design — explainable rules first, ML only where rules can't reach:

- **Named regexes** for known credential formats (AWS, GitHub, Slack, PEM keys, JWTs).
- **Shannon-entropy fallback** for opaque high-randomness secrets no pattern recognizes.
- **Validated PII detectors** — SSNs checked against issuance rules, credit cards against the
  Luhn checksum, so `1234-5678-...` test numbers and invalid SSNs don't cause false alarms.
- **Optional [Presidio](https://github.com/microsoft/presidio) NER layer** for names and
  locations regex can't see — off by default.

Every threshold lives in [`policies.yaml`](policies.yaml). Full reference in
[docs/configuration.md](docs/configuration.md).

## Proof it works

An offline harness scores a labeled adversarial corpus — real secrets, real PII, and clean
"trap" prompts designed to trigger false positives (git SHAs, UUIDs, base64 fragments,
Luhn-invalid cards, invalid SSNs, code snippets):

```
GATEKEEP RED-TEAM HARNESS (offline)
category   total   hit  miss
secret        15    15     0
pii           15    15     0
clean         20    20     0

CATCH RATE 30/30 (100.0%)
FALSE-POSITIVE BLOCKS 0
RESULT: PASS
```

Scoring is strict: the decided action must match the expected action exactly. And it holds
live, through the proxy, using the stock SDK:

```
[aws key]      Deploy using access key AKIAIOSFODNN7EXAMPLE right away.
               VERDICT: BLOCK   → HTTP 403 - Gatekeep policy violation: secret
[credit card]  Repeat back exactly: charge card 4111111111111111 for renewal
               VERDICT: REDACT  → model received "charge card [REDACTED:PII] for renewal"
[clean]        Say OK and nothing else.
               VERDICT: ALLOW   → OK
```

The credit-card line is the proof: the model's own echo shows it received `[REDACTED:PII]`,
not the real number. The proxy adds ~0.2 ms of local decision latency per request.

## Limitations (v1, by design)

- **Inbound only** — prompts are scanned, model responses are not.
- **No streaming** — `stream: true` returns a structured `400` (input is still scanned/blocked first).
- **Anthropic Messages API only** — transparent passthrough, no OpenAI-format translation.
- **No built-in auth** — front it with a real gateway for authn/TLS/multi-tenancy (see [docs/deployment.md](docs/deployment.md)).

## License

MIT — see [LICENSE](LICENSE).
