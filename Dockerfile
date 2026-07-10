# Gatekeep proxy — lean core image (no optional Presidio layer).
# To include Presidio, add `requirements-optional.txt` + the spaCy model download
# below; see docs/deployment.md.
FROM python:3.12-slim

WORKDIR /app

# Install core dependencies first so this layer caches across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code + default policy.
COPY src/ ./src/
COPY policies.yaml .

# Drop root: nothing here needs it. The unprivileged user owns /app so the audit
# SQLite DB (audit.db + its WAL sidecars) is writable at runtime.
RUN useradd --create-home --uid 10001 gatekeep && chown -R gatekeep:gatekeep /app
USER gatekeep

# Gatekeep listens on 8100. Bind 0.0.0.0 so it's reachable from outside the container.
EXPOSE 8100
CMD ["uvicorn", "gatekeep.main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8100"]
