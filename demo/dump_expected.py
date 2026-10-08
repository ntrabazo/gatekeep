"""Dump the Python engine's decisions to demo/expected.json (harness corpus)
and demo/expected_injection.json (injection corpus).

parity.test.js compares the JS port against these dumps entry by entry (action,
redacted text, findings, scores, categories/detectors CSVs, sha256). Regenerate
after any detector or policy change:

    .venv\\Scripts\\python demo\\dump_expected.py
    .venv\\Scripts\\python demo\\dump_expected.py --check   # CI: fail if injection_patterns.js is stale

It also GENERATES demo/injection_patterns.js from the Python pattern table
(gatekeep.detectors.injection.RAW_PATTERNS + the normalizer's typo keywords), so the
browser engine runs the exact same regexes as the proxy, and — when the public datasets
are cached locally — demo/expected_heldout.json (gitignored), which parity.test.js uses
to compare scores on ~4,000 real benchmark texts.
"""

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gatekeep.config import load_policies
from gatekeep.detectors import normalize as norm_mod
from gatekeep.detectors import run_all
from gatekeep.detectors.injection import OBFUSCATION_WEIGHT, RAW_PATTERNS, document_score, scan
from gatekeep.policy import decide

PATTERNS_JS = Path(__file__).parent / "injection_patterns.js"


def patterns_js() -> str:
    table = {
        "patterns": {tech: [[src, w, flags] for src, w, flags in rows] for tech, rows in RAW_PATTERNS.items()},
        "typoKeywords": list(norm_mod.TYPO_KEYWORDS),
        "typoStoplist": sorted(norm_mod._TYPO_STOPLIST),
        "obfuscationWeight": OBFUSCATION_WEIGHT,
    }
    payload = json.dumps(table, indent=1)
    return f"""/*
 * GENERATED from src/gatekeep/detectors/injection.py (RAW_PATTERNS) and normalize.py
 * (typo keywords) by demo/dump_expected.py — do not edit by hand. Python compiles these
 * with re.ASCII, so \\b and \\w behave exactly as they do in JavaScript.
 */
(function (root, factory) {{
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.GatekeepInjectionPatterns = factory();
}})(typeof self !== "undefined" ? self : this, function () {{
  "use strict";
  return {payload};
}});
"""


def dump_heldout() -> None:
    """Local-only parity data: score every cached benchmark text (output is gitignored)."""
    data = ROOT / "harness" / "data"
    names = ["deepset_train", "deepset_test", "gandalf_train", "gandalf_test", "jailbreak_train",
             "jailbreak_test", "notinject", "dolly_sample"]
    if not all((data / f"{n}.jsonl").exists() for n in names):
        print("public datasets not cached — skipped demo/expected_heldout.json")
        return
    out = []
    for n in names:
        for i, line in enumerate((data / f"{n}.jsonl").read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            findings = scan(json.loads(line)["text"])
            out.append({"file": n, "line": i, "score": round(document_score(findings), 6),
                        "detectors": sorted({f.detector for f in findings})})
    (Path(__file__).parent / "expected_heldout.json").write_text(json.dumps(out), encoding="utf-8")
    print(f"wrote {len(out)} benchmark scores to demo/expected_heldout.json (local parity only)")


def _load(name: str) -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / "harness" / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> None:
    if "--check" in sys.argv:
        current = PATTERNS_JS.read_text(encoding="utf-8") if PATTERNS_JS.exists() else ""
        if current != patterns_js():
            print("demo/injection_patterns.js is STALE — run: python demo/dump_expected.py")
            sys.exit(1)
        print("demo/injection_patterns.js matches the Python pattern table")
        return

    PATTERNS_JS.write_text(patterns_js(), encoding="utf-8", newline="\n")
    print("wrote demo/injection_patterns.js")
    policies = load_policies(ROOT / "policies.yaml")

    out = []
    for e in _load("corpus.jsonl"):
        findings = run_all(e["text"], policies)
        decision = decide([e["text"]], [findings], policies)
        out.append({
            "text": e["text"],
            "label": e["label"],
            "expect": e["expect"],
            "action": decision.action,
            "redacted": decision.redacted_texts[0],
            "categories": ",".join(sorted({f.category for f in findings})),
            "detectors": ",".join(sorted({f.detector for f in findings})),
            "sha256": hashlib.sha256(e["text"].encode()).hexdigest(),
            "findings": [
                {"category": f.category, "detector": f.detector, "span": list(f.span),
                 "preview": f.preview, "score": f.score}
                for f in findings
            ],
        })

    (Path(__file__).parent / "expected.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    print(f"wrote {len(out)} entries to demo/expected.json")

    # Injection corpus: full-pipeline decisions in BOTH modes, so the JS port's
    # mode-aware path (shadow log-and-allow vs enforce block-at-threshold) is pinned.
    enforce = copy.deepcopy(policies)
    enforce.injection.mode = "enforce"

    inj_out = []
    for e in _load("injection_corpus.jsonl"):
        findings = run_all(e["text"], policies)
        shadow_d = decide([e["text"]], [findings], policies)
        enforce_d = decide([e["text"]], [findings], enforce)
        inj = [f for f in findings if f.category == "injection"]
        inj_out.append({
            "text": e["text"],
            "label": e["label"],
            "expect_flag": e["expect_flag"],
            "document_score": round(document_score(inj), 6),
            "injection_score": round(shadow_d.injection_score, 6),
            "injection_categories": shadow_d.injection_categories,
            "action_shadow": shadow_d.action,
            "action_enforce": enforce_d.action,
            "matched_shadow": shadow_d.matched_rules,
            "matched_enforce": enforce_d.matched_rules,
            "findings": [
                {"category": f.category, "detector": f.detector, "span": list(f.span),
                 "preview": f.preview, "score": f.score}
                for f in findings
            ],
        })

    (Path(__file__).parent / "expected_injection.json").write_text(
        json.dumps(inj_out, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    print(f"wrote {len(inj_out)} entries to demo/expected_injection.json")
    dump_heldout()


if __name__ == "__main__":
    main()
