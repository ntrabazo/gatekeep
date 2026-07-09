"""PII detectors: SSN (with invalid-prefix rejection), credit card (digit runs + Luhn),
email, US phone. Validation beyond the regex keeps false positives down."""

import re

from . import Finding, make_preview

# SSN dddd-dd-dddd; capture groups let us reject structurally-invalid numbers below.
_SSN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
# Credit card: contiguous 13-19 digit run; only a Finding if it passes Luhn.
_CC_RUN = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# US phone: requires formatting (separators, parens, or +1) so bare 10-digit IDs don't match.
_PHONE = re.compile(r"(?<!\d)(?:\+1[-. ]?)?(?:\(\d{3}\)\s?|\d{3}[-. ])\d{3}[-. ]\d{4}(?!\d)")


def luhn_check(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ssn_valid(area: str, group: str, serial: str) -> bool:
    # SSA never issues: area 000/666/900-999, group 00, serial 0000.
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _SSN.finditer(text):
        if _ssn_valid(*m.groups()):
            findings.append(Finding("pii", "ssn", (m.start(), m.end()), make_preview(m.group())))
    for m in _CC_RUN.finditer(text):
        if luhn_check(m.group()):
            findings.append(Finding("pii", "credit_card", (m.start(), m.end()), make_preview(m.group())))
    for m in _EMAIL.finditer(text):
        findings.append(Finding("pii", "email", (m.start(), m.end()), make_preview(m.group())))
    for m in _PHONE.finditer(text):
        findings.append(Finding("pii", "phone", (m.start(), m.end()), make_preview(m.group())))
    return findings
