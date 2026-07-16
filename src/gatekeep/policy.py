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
    injection_score: float = 0.0                            # max score across injection findings
    injection_categories: list[str] = field(default_factory=list)  # distinct techniques


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

    # Injection findings are handled out of band: scored + mode-aware, and kept away
    # from _redact (their spans are normalized-text offsets — see detectors/injection.py).
    base_per_text = [[f for f in fs if f.category != "injection"] for fs in findings_per_text]
    injection_findings = [f for fs in findings_per_text for f in fs if f.category == "injection"]

    for findings in base_per_text:
        for f in findings:
            fa = _action_for(f, policies)
            matched.append(f"{f.category}:{fa}")
            if _SEVERITY[fa] > _SEVERITY[action]:
                action = fa

    injection_score = max((f.score for f in injection_findings), default=0.0)
    injection_categories = sorted({f.detector for f in injection_findings})
    if injection_findings:
        cfg = policies.injection
        if cfg.mode == "enforce" and injection_score >= cfg.block_threshold:
            fa = _action_for(injection_findings[0], policies)  # the policies.yaml injection rule
            matched.append(f"injection:{fa}")
            if _SEVERITY[fa] > _SEVERITY[action]:
                action = fa
        else:
            matched.append("injection:shadow")  # shadow / below threshold: log-and-allow

    redacted = list(texts)
    if action == "redact":
        redacted = [_redact(t, fs, policies) for t, fs in zip(texts, base_per_text)]
    return Decision(action=action, redacted_texts=redacted, matched_rules=matched,
                    injection_score=injection_score, injection_categories=injection_categories)
