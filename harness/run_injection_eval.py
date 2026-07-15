"""Offline prompt-injection eval — Tier-1 only, zero network calls.

Scores the hand-built corpus (and, when present + sane, the cached public datasets from
fetch_datasets.py) and prints a metric table annotated meets/below the reference targets.

Exit 0 whenever it RAN and produced numbers (PLAN-injection.md P2) — the reference targets
are informational, never a build blocker. `--strict` opts into gating exit on the targets.
Chunk 5 wires in the public benchmarks + EVAL_CARD.md generation.
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gatekeep.config import load_policies
from gatekeep.detectors.injection import document_score, scan

# Reference targets (informational — annotated meets/below, never gate the default run).
TARGETS = {
    "catch_rate": ("catch rate", 0.85, "ge"),
    "benign_fpr": ("benign FPR", 0.05, "le"),
    "notinject_fpr": ("NotInject hard-benign FPR", 0.10, "le"),
    "p95_ms": ("Tier-1 latency p95 (ms)", 100.0, "le"),
}


def _score_one(text: str) -> tuple[float, float]:
    """Return (document_score, elapsed_ms) for one text — Tier-1 only."""
    t0 = time.perf_counter()
    s = document_score(scan(text))
    return s, (time.perf_counter() - t0) * 1000


def score_corpus(entries: list[dict], threshold: float) -> dict:
    """Score a labelled corpus; return catch/FPR/latency + per-technique breakdown."""
    latencies: list[float] = []
    attacks_total = attacks_caught = 0
    benign_total = benign_fp = 0
    by_tech: dict[str, dict] = {}
    fp_examples: list[str] = []

    for e in entries:
        s, ms = _score_one(e["text"])
        latencies.append(ms)
        flagged = s >= threshold
        if e["label"] == "injection":
            attacks_total += 1
            tech = e.get("technique", "unknown")
            bucket = by_tech.setdefault(tech, {"total": 0, "caught": 0})
            bucket["total"] += 1
            if flagged:
                attacks_caught += 1
                bucket["caught"] += 1
        else:
            benign_total += 1
            if flagged:
                benign_fp += 1
                fp_examples.append(e.get("trigger", "?"))

    return {
        "attacks_total": attacks_total,
        "attacks_caught": attacks_caught,
        "catch_rate": attacks_caught / attacks_total if attacks_total else 0.0,
        "benign_total": benign_total,
        "benign_fp": benign_fp,
        "benign_fpr": benign_fp / benign_total if benign_total else 0.0,
        "p50_ms": statistics.median(latencies) if latencies else 0.0,
        "p95_ms": _percentile(latencies, 95) if latencies else 0.0,
        "by_technique": by_tech,
        "fp_triggers": fp_examples,
    }


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    k = (len(ordered) - 1) * (pct / 100)
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _meets(value: float, target: float, direction: str) -> bool:
    return value >= target if direction == "ge" else value <= target


def load_corpus(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def print_report(result: dict, threshold: float) -> None:
    print(f"\nGATEKEEP INJECTION EVAL (Tier-1, offline)  |  block_threshold = {threshold}")
    print(f"hand corpus: {result['attacks_total']} attacks, {result['benign_total']} benigns\n")

    rows = [
        ("catch_rate", result["catch_rate"], f"{result['attacks_caught']}/{result['attacks_total']}"),
        ("benign_fpr", result["benign_fpr"], f"{result['benign_fp']}/{result['benign_total']}"),
        ("p95_ms", result["p95_ms"], f"p50 {result['p50_ms']:.2f}ms"),
    ]
    print(f"{'metric':<28} {'value':>10} {'target':>10} {'meets':>7}   detail")
    for key, value, detail in rows:
        label, target, direction = TARGETS[key]
        meets = "yes" if _meets(value, target, direction) else "NO"
        vfmt = f"{value*100:.1f}%" if key.endswith(("rate", "fpr")) else f"{value:.2f}"
        tfmt = f"{target*100:.0f}%" if key.endswith(("rate", "fpr")) else f"{target:.0f}"
        cmp = ">=" if direction == "ge" else "<="
        print(f"{label:<28} {vfmt:>10} {cmp+tfmt:>10} {meets:>7}   {detail}")

    print("\nper-technique catch:")
    for tech, b in sorted(result["by_technique"].items()):
        print(f"  {tech:<24} {b['caught']}/{b['total']}")
    if result["fp_triggers"]:
        print(f"\nfalse positives on triggers: {', '.join(result['fp_triggers'])}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="gate exit on reference targets (for tuning)")
    args = ap.parse_args()

    policies = load_policies(ROOT / "policies.yaml")
    threshold = policies.injection.block_threshold
    entries = load_corpus(ROOT / "harness" / "injection_corpus.jsonl")
    result = score_corpus(entries, threshold)
    print_report(result, threshold)

    if args.strict:
        ok = (_meets(result["catch_rate"], *TARGETS["catch_rate"][1:])
              and _meets(result["benign_fpr"], *TARGETS["benign_fpr"][1:])
              and _meets(result["p95_ms"], *TARGETS["p95_ms"][1:]))
        print(f"\nSTRICT: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    print("\nreport-only run (exit 0 on producing numbers; use --strict to gate on targets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
