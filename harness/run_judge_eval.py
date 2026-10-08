"""Fill the Tier-2 judge cache (LIVE API calls — the only harness script that makes any).

Judges every held-out text that Tier-1 does not already block (Tier-1 score < block_threshold),
and stores each verdict in harness/data/judge_cache.jsonl keyed by SHA-256 + model + rubric
version — never the text. run_injection_eval.py then reads the cache OFFLINE, so the eval card
stays reproducible without a key once the cache exists.

    .venv\\Scripts\\python harness\\run_judge_eval.py --env-file C:\\path\\to\\.env
    .venv\\Scripts\\python harness\\run_judge_eval.py --dev 60      # rubric sanity check on TRAIN rows only

Cost: Haiku 5.5 at max_tokens=64 — roughly $0.10-0.30 for the full held-out suite.
"""

import argparse
import hashlib
import json
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "harness"))

from benchmarks import DATA, TRAIN_FILES, _read, load_heldout  # noqa: E402
from gatekeep.config import load_policies  # noqa: E402
from gatekeep.detectors.injection import document_score, scan  # noqa: E402
from gatekeep.detectors.injection_judge import JUDGE_MODEL, RUBRIC_VERSION, judge  # noqa: E402

CACHE = DATA / "judge_cache.jsonl"


def cache_key(text: str) -> str:
    return f"{hashlib.sha256(text.encode('utf-8')).hexdigest()}:{JUDGE_MODEL}:{RUBRIC_VERSION}"


def load_cache() -> dict[str, dict]:
    if not CACHE.exists():
        return {}
    out = {}
    for line in CACHE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            out[row["key"]] = row
    return out


def _load_env_file(path: str) -> None:
    """Read ANTHROPIC_API_KEY from a dotenv file without echoing it."""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("ANTHROPIC_API_KEY="):
            os.environ.setdefault("ANTHROPIC_API_KEY", line.split("=", 1)[1].strip().strip('"').strip("'"))


def run(texts: list[str], workers: int) -> dict[str, int]:
    cache = load_cache()
    done = {k for k, v in cache.items() if v.get("skipped") is None}  # skipped verdicts are retried
    todo = sorted({t for t in texts if cache_key(t) not in done})
    stats = {"cached": len(set(texts)) - len(todo), "judged": 0, "skipped": 0}
    print(f"{len(set(texts))} unique texts, {stats['cached']} already cached, {len(todo)} to judge")
    with ThreadPoolExecutor(max_workers=workers) as pool, CACHE.open("a", encoding="utf-8") as f:
        for text, v in zip(todo, pool.map(judge, todo)):
            row = {"key": cache_key(text), "injection": v.injection, "confidence": v.confidence,
                   "score": v.score, "latency_ms": round(v.latency_ms, 1), "skipped": v.skipped}
            f.write(json.dumps(row) + "\n")
            stats["skipped" if v.skipped else "judged"] += 1
            if v.skipped:
                print(f"  skipped: {v.skipped}")
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", help="dotenv file holding ANTHROPIC_API_KEY (never printed)")
    ap.add_argument("--dev", type=int, metavar="N", help="judge N random TRAIN rows (rubric sanity) instead")
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    if args.env_file:
        _load_env_file(args.env_file)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("no ANTHROPIC_API_KEY (env or --env-file) — nothing judged; the eval stays Tier-1 only")
        return 1

    threshold = load_policies(ROOT / "policies.yaml").injection.block_threshold
    if args.dev:
        rows = [r for name in TRAIN_FILES for r in _read(name)]
        random.Random(7).shuffle(rows)
        rows = [r for r in rows if document_score(scan(r["text"])) < threshold][: args.dev]
        print(run([r["text"] for r in rows], args.workers))
        cache = load_cache()
        right = sum(((cache[cache_key(r["text"])]["score"] >= threshold) == (r["label"] == 1))
                    for r in rows if cache.get(cache_key(r["text"]), {}).get("score") is not None)
        print(f"DEV (train rows Tier-1 missed or would allow): judge agrees with the label on {right}/{len(rows)}")
        return 0

    benches = load_heldout()
    if benches is None:
        print("held-out datasets missing — run harness/fetch_datasets.py first")
        return 1
    texts = [t for b in benches.values() for t in b.attacks + b.benign
             if document_score(scan(t)) < threshold]  # Tier-1 already blocks the rest
    print(run(texts, args.workers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
