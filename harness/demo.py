"""Gatekeep live demo — a stock `anthropic` SDK client pointed at the proxy via
base_url ONLY. No SDK subclassing, no custom transport: that one-line swap is the
whole adoption story.

Six canned prompts (clean / AWS key / SSN / credit card / JWT / entropy blob) run
through the live proxy, then the audit trail is queried for the blocks.

The VERDICT / WHAT-THE-MODEL-SAW lines are computed locally with the same policy
engine the proxy runs (display only); the live proof is each RESPONSE/BLOCKED line.
The SSN and credit-card prompts ask the model to echo its input back, so the
response itself shows the model received [REDACTED:PII], not the real value.
"""

import os
import sys
from pathlib import Path

import anthropic
import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from gatekeep.config import load_policies
from gatekeep.detectors import run_all
from gatekeep.policy import decide

PROXY = "http://127.0.0.1:8100"
MODEL = "claude-haiku-4-5-20251001"

PROMPTS = [
    ("clean", "Say OK and nothing else."),
    ("aws key", "Deploy using access key AKIAIOSFODNN7EXAMPLE right away."),
    ("ssn", "Repeat the following text back exactly, word for word: my ssn is 219-09-9999"),
    ("credit card", "Repeat the following text back exactly, word for word: charge card 4111111111111111 for renewal"),
    ("jwt", "Debug why eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U is rejected."),
    ("entropy blob", "The signing secret is 9fK2mQ8xW3nR7pL5vB1zT6hY4cJ0sD8gA2eU5iO7 rotate it monthly."),
]


def read_key() -> str:
    """Resolve the client's Anthropic key: environment variable first, then a local
    .env file in the project root. The proxy itself never needs a key — this is only
    for the demo client that talks THROUGH the proxy to the real API."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    env_path = ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(
        "ANTHROPIC_API_KEY is not set. Export it as an environment variable, or copy "
        ".env.example to .env and fill it in. See README.md > Quickstart."
    )


def main() -> None:
    policies = load_policies(ROOT / "policies.yaml")
    client = anthropic.Anthropic(base_url=PROXY, api_key=read_key())

    for name, prompt in PROMPTS:
        decision = decide([prompt], [run_all(prompt, policies)], policies)
        if decision.action == "block":
            model_saw = "(nothing - request stopped at the proxy)"
        elif decision.action == "redact":
            model_saw = decision.redacted_texts[0]
        else:
            model_saw = prompt

        print("=" * 78)
        print(f"[{name}]")
        print(f"  PROMPT:             {prompt}")
        print(f"  VERDICT:            {decision.action.upper()}")
        print(f"  WHAT THE MODEL SAW: {model_saw}")
        try:
            msg = client.messages.create(
                model=MODEL, max_tokens=64,
                messages=[{"role": "user", "content": prompt}],
            )
            print(f"  RESPONSE:           {msg.content[0].text.strip()}")
        except anthropic.APIStatusError as e:
            detail = e.body["error"]["message"] if isinstance(e.body, dict) else str(e)
            print(f"  BLOCKED:            HTTP {e.status_code} - {detail}")

    print("=" * 78)
    print("AUDIT TRAIL - GET /audit?action=block")
    rows = httpx.get(f"{PROXY}/audit", params={"action": "block", "limit": 10}).json()
    for r in rows:
        print(
            f"  #{r['id']} {r['ts_utc']} action={r['action']} "
            f"categories={r['categories']} detectors={r['detectors']} "
            f"sha256={r['prompt_sha256'][:16]}... latency_ms={r['latency_ms']:.2f}"
        )
    print("  (hashes and categories only - the audit DB never stores prompt text)")


if __name__ == "__main__":
    main()
