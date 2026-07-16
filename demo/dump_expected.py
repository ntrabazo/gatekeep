"""Dump the Python engine's decisions to demo/expected.json (harness corpus)
and demo/expected_injection.json (injection corpus).

parity.test.js compares the JS port against these dumps entry by entry (action,
redacted text, findings, scores, categories/detectors CSVs, sha256). Regenerate
after any detector or policy change:

    .venv\\Scripts\\python demo\\dump_expected.py
"""

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gatekeep.config import load_policies
from gatekeep.detectors import run_all
from gatekeep.detectors.injection import document_score
from gatekeep.policy import decide


def _load(name: str) -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / "harness" / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> None:
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


if __name__ == "__main__":
    main()
