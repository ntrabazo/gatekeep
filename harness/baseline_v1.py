"""Score the v1 Tier-1 detector (straight from git) on today's held-out rows -> harness/v1_baseline.json.

The eval card's "Versus v1" table reads that file, so the before/after comparison is reproducible
rather than hand-typed: same rows, same dedupe, same scope file, only the detector differs.

    .venv\\Scripts\\python harness\\baseline_v1.py            # default ref: 920f2dd (v1 merge)
"""

import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
from benchmarks import load_heldout  # noqa: E402

REF = sys.argv[1] if len(sys.argv) > 1 else "920f2dd"
FILES = {"__init__.py": "src/gatekeep/detectors/__init__.py",
         "normalize.py": "src/gatekeep/detectors/normalize.py",
         "injection.py": "src/gatekeep/detectors/injection.py"}


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gatekeep_v1_"))
    pkg = tmp / "v1det"
    pkg.mkdir()
    for name, src in FILES.items():
        blob = subprocess.run(["git", "show", f"{REF}:{src}"], cwd=ROOT, capture_output=True, check=True).stdout
        (pkg / name).write_bytes(blob)
    sys.path.insert(0, str(tmp))
    inj = importlib.import_module("v1det.injection")
    flagged = lambda t: inj.document_score(inj.scan(t)) >= 0.8  # noqa: E731

    b = load_heldout()
    if b is None:
        print("held-out datasets missing — run harness/fetch_datasets.py first")
        return 1
    benign = {"NotInject": b["notinject"].benign, "Dolly-15k sample": b["dolly"].benign,
              "jackhhao benign": b["jailbreak"].benign, "deepset legit": b["deepset"].benign}
    benign["**All benign, pooled**"] = [t for ts in list(benign.values()) for t in ts]
    attacks = {"Gandalf (Lakera)": b["gandalf"].attacks, "jackhhao jailbreaks": b["jailbreak"].attacks,
               "deepset, security-scoped": b["deepset"].attacks_scoped, "deepset, raw": b["deepset"].attacks}
    rows = {name: [sum(map(flagged, ts)), len(ts)] for name, ts in {**benign, **attacks}.items()}
    commit = subprocess.run(["git", "rev-parse", "--short", REF], cwd=ROOT, capture_output=True,
                            text=True, check=True).stdout.strip()
    out = ROOT / "harness" / "v1_baseline.json"
    out.write_text(json.dumps({"commit": commit, "rows": rows}, indent=1) + "\n", encoding="utf-8")
    for name, (k, n) in rows.items():
        print(f"  {name.strip('*'):<26} {k}/{n}")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
