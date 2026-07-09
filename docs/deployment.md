# Deployment

Gatekeep is a stateless FastAPI app (aside from the local audit database). Run it anywhere
that runs a Python ASGI app or a container.

## Option 1 — Docker (recommended)

```bash
docker compose up --build
```

That builds the lean core image and serves the proxy on `http://127.0.0.1:8100`.
`policies.yaml` is mounted read-only, so you can edit rules and just restart:

```bash
# edit policies.yaml, then:
docker compose restart
```

Without compose:

```bash
docker build -t gatekeep .
docker run -p 8100:8100 gatekeep
```

## Option 2 — Directly with uvicorn

```bash
python -m venv .venv                 # Python 3.12
.venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
.venv/bin/uvicorn gatekeep.main:app --app-dir src --host 0.0.0.0 --port 8100
```

Run from the project root — the app loads `policies.yaml` from the working directory.

## Enabling the optional Presidio layer

The base image and core install deliberately exclude Presidio (it pulls in spaCy and is
heavy). To turn on name/location detection:

```bash
pip install -r requirements-optional.txt
python -m spacy download en_core_web_sm
# then set presidio.enabled: true in policies.yaml
```

For Docker, add those two lines to the `Dockerfile` after the core `pip install` and
rebuild.

## Production considerations

Gatekeep v1 is intentionally minimal. For real production traffic, put it behind
infrastructure that handles the concerns it deliberately doesn't:

- **TLS.** The proxy serves plain HTTP. Terminate TLS at a real reverse proxy (nginx,
  Caddy, a cloud load balancer) in front of it — never expose it directly to the internet.
- **Authentication.** Gatekeep has no built-in authn/multi-tenancy. Restrict who can reach
  it at the network layer or via the fronting gateway. Each client still sends its own
  Anthropic `x-api-key`, which the proxy forwards untouched.
- **Audit persistence.** The audit database is written to `audit.db` in the working
  directory. In a container that's ephemeral — mount a volume (or bind-mount a host path)
  at the working directory if you need the audit trail to survive restarts.
- **Scaling.** The app is stateless per request; run multiple replicas behind a load
  balancer. If you need a shared audit trail across replicas, point them at shared storage
  or forward audit rows to a central log store.
- **Health checks.** `GET /health` returns `{"status":"ok"}` — wire it into your
  orchestrator's liveness/readiness probes (the bundled `docker-compose.yml` already does).

## Verifying a deployment

Once it's up, from anywhere that can reach it:

```bash
curl -s http://<host>:8100/health          # -> {"status":"ok"}
python harness/demo.py                       # end-to-end proof against the live model
```

Point `demo.py` at a non-local host by editing its `PROXY` constant, or run the harness
locally against your deployed instance.
