"""Policy engine: map findings to a single Decision via policies.yaml rules.
Severity order is block > redact > allow across all findings in the request."""

from dataclasses import dataclass, field
from typing import Literal

from .config import Policies
from .detectors import Finding

_SEVERITY = {"allow": 0, "redact": 1, "block": 2}


@dataclass
class Decision:
    action: Literal["block", "redact", "allow"]
    redacted_texts: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)  # "category:action" per finding


def _action_for(finding: Finding, policies: Policies) -> str:
    for rule in policies.rules:  # first match wins
        if rule.category == finding.category:
            return rule.action
    return policies.default_action


def _redact(text: str, findings: list[Finding], policies: Policies) -> str:
    """Replace redact-mapped finding spans right-to-left so earlier offsets stay valid."""
    for f in sorted(findings, key=lambda f: f.span[0], reverse=True):
        if _action_for(f, policies) == "redact":
            start, end = f.span
            text = text[:start] + f"[REDACTED:{f.category.upper()}]" + text[end:]
    return text


def decide(texts: list[str], findings_per_text: list[list[Finding]], policies: Policies) -> Decision:
    action = "allow"
    matched: list[str] = []
    for findings in findings_per_text:
        for f in findings:
            fa = _action_for(f, policies)
            matched.append(f"{f.category}:{fa}")
            if _SEVERITY[fa] > _SEVERITY[action]:
                action = fa

    redacted = list(texts)
    if action == "redact":
        redacted = [_redact(t, fs, policies) for t, fs in zip(texts, findings_per_text)]
    return Decision(action=action, redacted_texts=redacted, matched_rules=matched)
