"""Idempotent fetch of the public eval datasets into harness/data/ (gitignored).

Runs online only on the first fetch; re-runs are a no-op once the cached JSONL exists with
a sane row count (the eval stays offline afterward). A cached file with an implausible row
count is treated as a partial/corrupt download — it is re-fetched, and the public metrics are
refused rather than computed on garbage (PLAN-injection.md Chunk 5 / self red-team M2).

Datasets (metrics-only use, not redistributed — harness/data/ is gitignored):
  - deepset/prompt-injections  (license: Apache-2.0)  -> catch rate on the test split
  - leolee99/NotInject         (license: MIT)         -> hard-benign false-positive rate
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "harness" / "data"

# name -> (repo_id, license, expected_rows, tolerance)
SPECS = {
    "deepset_test": ("deepset/prompt-injections", "Apache-2.0", 116, 10),
    "notinject": ("leolee99/NotInject", "MIT", 339, 15),
}


def _sane(path: Path, expected: int, tol: int) -> bool:
    if not path.exists():
        return False
    n = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    return abs(n - expected) <= tol


def _write_deepset(path: Path) -> None:
    from datasets import load_dataset
    ds = load_dataset("deepset/prompt-injections")["test"]
    with path.open("w", encoding="utf-8") as f:
        for row in ds:
            # label: "1"/1 = injection, "0"/0 = legit
            f.write(json.dumps({"text": row["text"], "label": int(row["label"])}) + "\n")


def _write_notinject(path: Path) -> None:
    from datasets import load_dataset
    ds = load_dataset("leolee99/NotInject")  # 3 hard-benign splits, column "prompt"
    with path.open("w", encoding="utf-8") as f:
        for split in ds:
            for row in ds[split]:
                f.write(json.dumps({"text": row["prompt"], "split": split}) + "\n")


WRITERS = {"deepset_test": _write_deepset, "notinject": _write_notinject}


def fetch_all() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    incomplete = []
    for name, (repo, lic, expected, tol) in SPECS.items():
        path = DATA / f"{name}.jsonl"
        if _sane(path, expected, tol):
            print(f"[cached]   {name:<14} {repo:<28} ({lic}) — {expected}~ rows, skipping")
            continue
        print(f"[fetching] {name:<14} {repo:<28} ({lic}) ...")
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
