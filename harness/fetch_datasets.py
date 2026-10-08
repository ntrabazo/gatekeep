"""Idempotent fetch of the public eval datasets into harness/data/ (gitignored).

Runs online only on the first fetch; re-runs are a no-op once the cached JSONL exists with
a sane row count (the eval stays offline afterward). A cached file with an implausible row
count is treated as a partial/corrupt download — it is re-fetched, and the public metrics are
refused rather than computed on garbage (PLAN-injection.md Chunk 5 / self red-team M2).

Split discipline (PLAN-injection.md §17): `*_train` files are the DEV sets the Tier-1 patterns
are tuned against; `*_test` files plus NotInject and the Dolly sample are HELD OUT and only
ever scored. The eval card reports held-out numbers only.

Datasets (metrics-only use, not redistributed — harness/data/ is gitignored):
  - deepset/prompt-injections          (Apache-2.0)   train = dev, test = held out
  - Lakera/gandalf_ignore_instructions (MIT)          train = dev, test = held out
  - jackhhao/jailbreak-classification  (Apache-2.0)   train = dev, test = held out
  - leolee99/NotInject                 (MIT)          held out (hard-benign FPR), never tuned
  - databricks/databricks-dolly-15k    (CC-BY-SA-3.0) fixed 1,000-row sample, held out, never tuned
"""

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "harness" / "data"

DOLLY_SAMPLE = 1000
DOLLY_SEED = 1337

# name -> (repo_id, license, expected_rows, tolerance)
SPECS = {
    "deepset_train": ("deepset/prompt-injections", "Apache-2.0", 546, 10),
    "deepset_test": ("deepset/prompt-injections", "Apache-2.0", 116, 10),
    "gandalf_train": ("Lakera/gandalf_ignore_instructions", "MIT", 777, 10),
    "gandalf_test": ("Lakera/gandalf_ignore_instructions", "MIT", 112, 10),
    "jailbreak_train": ("jackhhao/jailbreak-classification", "Apache-2.0", 1044, 10),
    "jailbreak_test": ("jackhhao/jailbreak-classification", "Apache-2.0", 262, 10),
    "notinject": ("leolee99/NotInject", "MIT", 339, 15),
    "dolly_sample": ("databricks/databricks-dolly-15k", "CC-BY-SA-3.0", DOLLY_SAMPLE, 0),
}


def _sane(path: Path, expected: int, tol: int) -> bool:
    if not path.exists():
        return False
    n = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    return abs(n - expected) <= tol


def _dump(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")  # ASCII-escaped: a raw U+2028 would split a row under splitlines()


def _deepset(split: str):
    def write(path: Path) -> None:
        from datasets import load_dataset
        ds = load_dataset("deepset/prompt-injections")[split]
        # label: "1"/1 = injection, "0"/0 = legit
        _dump(path, ({"text": r["text"], "label": int(r["label"])} for r in ds))
    return write


def _gandalf(split: str):
    def write(path: Path) -> None:
        from datasets import load_dataset
        ds = load_dataset("Lakera/gandalf_ignore_instructions")[split]
        # Every row is a real player's attack on the Gandalf password game.
        _dump(path, ({"text": r["text"], "label": 1} for r in ds))
    return write


def _jailbreak(split: str):
    def write(path: Path) -> None:
        from datasets import load_dataset
        ds = load_dataset("jackhhao/jailbreak-classification")[split]
        _dump(path, ({"text": r["prompt"], "label": int(r["type"] == "jailbreak")} for r in ds))
    return write


def _write_notinject(path: Path) -> None:
    from datasets import load_dataset
    ds = load_dataset("leolee99/NotInject")  # 3 hard-benign splits, column "prompt"
    _dump(path, ({"text": r["prompt"], "split": s} for s in ds for r in ds[s]))


def _write_dolly(path: Path) -> None:
    """Fixed-seed sample of ordinary instructions; a context passage, when present, rides along
    so long benign documents are exercised too."""
    from datasets import load_dataset
    ds = load_dataset("databricks/databricks-dolly-15k")["train"]
    idx = sorted(random.Random(DOLLY_SEED).sample(range(ds.num_rows), DOLLY_SAMPLE))
    rows = []
    for i in idx:
        r = ds[i]
        text = r["instruction"] + (f"\n\n{r['context']}" if r["context"].strip() else "")
        rows.append({"text": text, "label": 0, "category": r["category"]})
    _dump(path, rows)


WRITERS = {
    "deepset_train": _deepset("train"),
    "deepset_test": _deepset("test"),
    "gandalf_train": _gandalf("train"),
    "gandalf_test": _gandalf("test"),
    "jailbreak_train": _jailbreak("train"),
    "jailbreak_test": _jailbreak("test"),
    "notinject": _write_notinject,
    "dolly_sample": _write_dolly,
}


def fetch_all() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    incomplete = []
    for name, (repo, lic, expected, tol) in SPECS.items():
        path = DATA / f"{name}.jsonl"
        if _sane(path, expected, tol):
            print(f"[cached]   {name:<16} {repo:<36} ({lic}) — {expected}~ rows, skipping")
            continue
        print(f"[fetching] {name:<16} {repo:<36} ({lic}) ...")
        WRITERS[name](path)
        if not _sane(path, expected, tol):
            n = sum(1 for _ in path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0
            print(f"  !! {name}: got {n} rows, expected ~{expected} — dataset incomplete, re-fetch")
            incomplete.append(name)
        else:
            n = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            print(f"  ok {name}: {n} rows cached -> {path.relative_to(ROOT)}")

    if incomplete:
        print(f"\nINCOMPLETE: {', '.join(incomplete)} — public metrics will be refused until re-fetched")
        return 1
    print("\nall datasets present and sane (offline from here on)")
    return 0


if __name__ == "__main__":
    sys.exit(fetch_all())
