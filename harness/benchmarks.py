"""Held-out benchmark registry shared by run_injection_eval.py and run_judge_eval.py.

Split discipline (PLAN-injection.md §17): Tier-1 patterns were tuned on the `*_train` splits
only. Everything loaded here is HELD OUT. Any held-out row whose text also appears in a train
split is dropped (jackhhao ships 7 such duplicates), so no reported number is measured on
text the patterns were tuned against.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "harness" / "data"
SCOPE = ROOT / "harness" / "deepset_scope.json"
TRAIN_FILES = ("deepset_train", "gandalf_train", "jailbreak_train")

# key -> (cache file, expected rows, tolerance, title, license, what it measures, ever tuned on?)
HELDOUT = {
    "gandalf": ("gandalf_test", 112, 10, "Lakera Gandalf — real players' attacks (test split)", "MIT",
                "catch rate on real human direct-injection attempts", "train split only"),
    "jailbreak": ("jailbreak_test", 262, 10, "jackhhao jailbreak-classification (test split)", "Apache-2.0",
                  "catch rate on jailbreak prompts + FPR on its benign prompts", "train split only"),
    "deepset": ("deepset_test", 116, 10, "deepset prompt-injections (test split)", "Apache-2.0",
                "catch rate (raw + security-scoped) + FPR on its legit rows", "train split only"),
    "notinject": ("notinject", 339, 15, "NotInject — hard benigns with trigger words", "MIT",
                  "FPR on benign text built to look like attacks", "never"),
    "dolly": ("dolly_sample", 1000, 0, "Databricks Dolly-15k — ordinary instructions (fixed 1,000-row sample)",
              "CC-BY-SA-3.0", "FPR on everyday traffic", "never"),
}


@dataclass
class Bench:
    key: str
    title: str
    license: str
    measures: str
    tuned: str
    attacks: list[str] = field(default_factory=list)
    benign: list[str] = field(default_factory=list)
    attacks_scoped: list[str] | None = None  # deepset only: rows with an injection mechanism
    dropped_dupes: int = 0


def _norm(t: str) -> str:
    return " ".join(t.lower().split())


def _read(name: str) -> list[dict]:
    path = DATA / f"{name}.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_heldout() -> dict[str, Bench] | None:
    """All held-out benchmarks, or None if any cached file is missing or implausibly sized."""
    import hashlib

    train = {_norm(r["text"]) for name in TRAIN_FILES for r in _read(name)}
    scope = json.loads(SCOPE.read_text(encoding="utf-8")) if SCOPE.exists() else {"excluded": []}
    excluded = {e["sha256"] for e in scope["excluded"]}

    out: dict[str, Bench] = {}
    for key, (fname, expected, tol, title, lic, measures, tuned) in HELDOUT.items():
        rows = _read(fname)
        if abs(len(rows) - expected) > tol or not rows:
            return None  # partial download -> refuse to compute metrics on garbage
        b = Bench(key, title, lic, measures, tuned)
        for r in rows:
            if _norm(r["text"]) in train:
                b.dropped_dupes += 1
                continue
            (b.attacks if r.get("label", 0) == 1 else b.benign).append(r["text"])
        if key == "deepset":
            b.attacks_scoped = [t for t in b.attacks
                                if hashlib.sha256(t.encode("utf-8")).hexdigest() not in excluded]
        out[key] = b
    return out
