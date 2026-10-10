# Gatekeep live demo

A single-screen static page: pick an example or type a prompt, watch it hit the checkpoint.
The prompt and its result sit side by side: the blocked / redacted / allowed verdict in
plain language, exactly what the model would have received (redactions highlighted), what
was found, and a live audit trail with the same columns as the proxy's SQLite table. Detector internals (spans, weights, the 403
body, the matched policy rule) sit behind a "Technical details" toggle.

Open [`index.html`](index.html) in any browser. It runs entirely client-side: no API key,
no server, nothing leaves the page. That works because the detection engine is fully
offline by design, so it could be ported to JavaScript wholesale.

## Faithfulness

The page does not approximate the engine, it ports it:

- [`gatekeep.js`](gatekeep.js) is a 1:1 port of `src/gatekeep/` (detectors, policy
  engine, router) with the `policies.yaml` values inlined.
- On load, the page replays both red-team corpora (`harness/corpus.jsonl` and
  `harness/injection_corpus.jsonl`) through the in-browser engine and shows the result in
  the self-test badge in the header. Example prompts are labeled by what they contain,
  never by the expected outcome: the verdict only appears once you send one.
- [`parity.test.js`](parity.test.js) goes further: it compares the JS port against the
  real Python engine entry by entry — action, redacted text, every finding's span and
  preview, audit CSVs, and SHA-256 — using a golden dump produced by the Python engine.

```bash
node demo/parity.test.js               # exit 0 = JS port matches Python on all 209 entries
                                       # (+ 4,196 real benchmark texts when harness/data/ is cached)
```

## Regenerating the derived files

| File | Source of truth | Regenerate with |
|---|---|---|
| `corpus.js` | `harness/corpus.jsonl` | `node demo/build_corpus.js` |
| `expected.json`, `expected_injection.json` | the Python engine | `.venv/Scripts/python demo/dump_expected.py` |
| `injection_patterns.js` | `src/gatekeep/detectors/injection.py` (`RAW_PATTERNS`) | same command — never hand-edit; CI runs `--check` |
| `eval_results.js` | held-out benchmarks | `.venv/Scripts/python harness/run_injection_eval.py` |

Rerun both plus `parity.test.js` after any detector, policy, or corpus change.

## Hosting

The page is six static files: `index.html`, `injection_patterns.js`, `gatekeep.js`,
`corpus.js`, `injection_corpus.js`, `eval_results.js`, plus `og.png` (the link-preview image,
rendered from `og/og-card.html` with headless Edge). Any static host
works (Cloudflare Pages, GitHub Pages, S3). No build step.
