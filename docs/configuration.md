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

# Prompt-injection detector. Shadow mode (log-and-allow) is the default and never blocks.
# Full reference: docs/injection.md
injection:
  enabled: true
  mode: shadow          # shadow = log-and-allow (default) | enforce = block at threshold
  block_threshold: 0.8  # enforce mode blocks when the document score is >= this
  judge_enabled: false  # Tier-2 LLM-judge seam — inert in v1
  judge_band: [0.3, 0.7]

# Category -> action. First matching rule wins.
rules:
  - {category: secret, action: block}
  - {category: pii,    action: redact}
  - {category: injection, action: block}   # consulted only in enforce mode, at/above block_threshold

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
| `injection.enabled` | Master switch for the prompt-injection detector. |
| `injection.mode` | `shadow` scores + logs but always allows (default); `enforce` blocks (403) at/above `block_threshold`. |
| `injection.block_threshold` | Document score at/above which `enforce` mode blocks. `0.8` default. |
| `injection.judge_enabled` / `injection.judge_band` | Inert Tier-2 (LLM judge) seam — see [injection.md](injection.md). |
| `rules` | Ordered list mapping a finding `category` to an `action`. First match wins. |
| `default_action` | Applied to findings no rule matches. |
| `routing` | Optional model swaps keyed on the decision action. No match = requested model is left unchanged. |

## Categories and actions

- **Categories** produced by the detectors: `secret` (credentials, keys, tokens, high-entropy
  blobs), `pii` (SSN, credit card, email, phone, and — with Presidio on — names/locations), and
  `injection` (prompt-injection techniques; scored 0–1 and handled mode-aware, see
  [injection.md](injection.md)).
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
