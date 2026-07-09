# Gatekeep live demo

A single-screen static page: type a prompt, watch it hit the checkpoint. Shows the
BLOCK / REDACT / ALLOW verdict, exactly what the model would have received (redactions
highlighted), and a live audit trail with the same columns as the proxy's SQLite table.

Open [`index.html`](index.html) in any browser. It runs entirely client-side: no API key,
no server, nothing leaves the page. That works because the detection engine is fully
offline by design, so it could be ported to JavaScript wholesale.

## Faithfulness

The page does not approximate the engine, it ports it:

- [`gatekeep.js`](gatekeep.js) is a 1:1 port of `src/gatekeep/` (detectors, policy
  engine, router) with the `policies.yaml` values inlined.
- On load, the page replays the full red-team corpus (`harness/corpus.jsonl`) through the
  in-browser engine and shows the result in the SELF-TEST chip.
- [`parity.test.js`](parity.test.js) goes further: it compares the JS port against the
  real Python engine entry by entry — action, redacted text, every finding's span and
  preview, audit CSVs, and SHA-256 — using a golden dump produced by the Python engine.

```bash
node demo/parity.test.js               # exit 0 = JS port matches Python on all 50 entries
```

## Regenerating the derived files

| File | Source of truth | Regenerate with |
|---|---|---|
| `corpus.js` | `harness/corpus.jsonl` | `node demo/build_corpus.js` |
| `expected.json` | the Python engine | `.venv/Scripts/python demo/dump_expected.py` |

Rerun both plus `parity.test.js` after any detector, policy, or corpus change.

## Hosting

The page is three static files: `index.html`, `gatekeep.js`, `corpus.js`. Any static host
works (Cloudflare Pages, GitHub Pages, S3). No build step.
