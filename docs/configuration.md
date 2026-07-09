# Configuration

All of Gatekeep's behavior is defined in `policies.yaml` — the governance contract. Nothing
tunable lives in code. Edit this file, restart the proxy, and the new policy is live.

## Full schema

```yaml
version: 1

# What to do when a request body can't be parsed for scanning: block | allow
on_parse_failure: block

# Shannon-entropy fallback for opaque secrets no named pattern recognizes.
entropy:
  min_length: 20      # ignore tokens shorter than this
  threshold: 4.0      # flag mixed-charset tokens at or above this entropy (bits/char)

# Optional Presidio NER layer (names, locations). Requires the optional deps.
presidio:
  enabled: false

# Category -> action. First matching rule wins.
rules:
  - {category: secret, action: block}
  - {category: pii,    action: redact}

# Action when no rule matches: block | redact | allow
default_action: allow

# Optional: swap the target model based on the decision. `when` is matched by exact
# string equality against the decision action (block | redact | allow).
routing:
  - {when: redact, model: claude-haiku-4-5-20251001}
```

## Fields

| Field | Meaning |
|---|---|
| `version` | Schema version. Keep at `1`. |
| `on_parse_failure` | If the JSON body can't be read, `block` (fail closed, recommended) or `allow` (fail open). |
| `entropy.min_length` | Tokens shorter than this are never entropy-flagged. Raise to reduce noise. |
| `entropy.threshold` | Bits-of-entropy-per-character cutoff. Lower = more aggressive (more catches, more false positives). `4.0` is a tuned default. |
| `presidio.enabled` | Turn the NER layer on. Requires `requirements-optional.txt` + the spaCy model. |
| `rules` | Ordered list mapping a finding `category` to an `action`. First match wins. |
| `default_action` | Applied to findings no rule matches. |
| `routing` | Optional model swaps keyed on the decision action. No match = requested model is left unchanged. |

## Categories and actions

- **Categories** produced by the detectors: `secret` (credentials, keys, tokens, high-entropy
  blobs) and `pii` (SSN, credit card, email, phone, and — with Presidio on — names/locations).
- **Actions:** `block` (reject with 403, never reaches the model), `redact` (replace the
  sensitive span with `[REDACTED:CATEGORY]` and forward), `allow` (forward unchanged).

## Common recipes

**Redact secrets instead of blocking them** (let the request through, sanitized):

```yaml
rules:
  - {category: secret, action: redact}
  - {category: pii,    action: redact}
```

**Block everything sensitive** (strictest posture):

```yaml
rules:
  - {category: secret, action: block}
  - {category: pii,    action: block}
```

**Turn on name/location detection:**

```yaml
presidio:
  enabled: true
```
Then install the optional layer — see [deployment.md](deployment.md) or the README.

## Tuning tips

- If clean prompts are being falsely flagged as entropy secrets, raise `entropy.threshold`
  (e.g. `4.2`) or `entropy.min_length`.
- If real secrets are slipping through, lower `entropy.threshold` — then re-run the harness
  (`python harness/run_harness.py`) to confirm you didn't blow up the false-positive count.
- The harness is the feedback loop for any policy change: it scores a labeled corpus and
  exits non-zero if catch rate drops below target or any clean prompt gets blocked.
