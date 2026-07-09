"""Dump the Python engine's decisions on the harness corpus to demo/expected.json.

parity.test.js compares the JS port against this dump entry by entry (action,
redacted text, findings, categories/detectors CSVs, sha256). Regenerate after
any detector or policy change:

    .venv\\Scripts\\python demo\\dump_expected.py
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gatekeep.config import load_policies
from gatekeep.detectors import run_all
from gatekeep.policy import decide


def main() -> None:
    policies = load_policies(ROOT / "policies.yaml")
    entries = [
        json.loads(line)
        for line in (ROOT / "harness" / "corpus.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    out = []
    for e in entries:
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
                {"category": f.category, "detector": f.detector, "span": list(f.span), "preview": f.preview}
                for f in findings
            ],
        })

    (Path(__file__).parent / "expected.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    print(f"wrote {len(out)} entries to demo/expected.json")


if __name__ == "__main__":
    main()
