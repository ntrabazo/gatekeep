"""Gatekeep red-team harness — fully OFFLINE (detectors + policy only, no API calls).

Exit 0 iff: catch rate on dirty prompts >= 90% AND zero clean prompts were blocked.
A "catch" means the decided action STRICTLY equals the expected action
(expected redact but got block = miss). clean->redact is a warning, not fatal.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gatekeep.config import load_policies
from gatekeep.detectors import run_all
from gatekeep.policy import decide

CATCH_TARGET = 0.90


def main() -> int:
    policies = load_policies(ROOT / "policies.yaml")
    entries = [json.loads(line) for line in (ROOT / "harness" / "corpus.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]

    stats = defaultdict(lambda: {"total": 0, "hit": 0})
    misses: list[str] = []
    fp_blocks = 0
    clean_redact_warnings = 0

    for i, e in enumerate(entries, 1):
        findings = run_all(e["text"], policies)
        got = decide([e["text"]], [findings], policies).action
        label, expect = e["label"], e["expect"]
        stats[label]["total"] += 1
        if got == expect:
            stats[label]["hit"] += 1
        else:
            detectors = ",".join(sorted({f.detector for f in findings})) or "-"
            misses.append(f"  #{i:02d} [{label}] expected {expect!r} got {got!r} (detectors: {detectors})")
            if label == "clean" and got == "block":
                fp_blocks += 1
            if label == "clean" and got == "redact":
                clean_redact_warnings += 1

    print("GATEKEEP RED-TEAM HARNESS (offline)")
    print(f"{'category':<10} {'total':>5} {'hit':>5} {'miss':>5}")
    for label in ("secret", "pii", "clean"):
        s = stats[label]
        print(f"{label:<10} {s['total']:>5} {s['hit']:>5} {s['total'] - s['hit']:>5}")

    dirty_total = stats["secret"]["total"] + stats["pii"]["total"]
    dirty_hit = stats["secret"]["hit"] + stats["pii"]["hit"]
    rate = dirty_hit / dirty_total if dirty_total else 0.0

    if misses:
        print("\nmisses:")
        print("\n".join(misses))

    print(f"\nCATCH RATE {dirty_hit}/{dirty_total} ({rate * 100:.1f}%)")
    print(f"FALSE-POSITIVE BLOCKS {fp_blocks}")
    if clean_redact_warnings:
        print(f"WARNING: {clean_redact_warnings} clean prompt(s) were redacted (non-fatal)")

    ok = rate >= CATCH_TARGET and fp_blocks == 0
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
