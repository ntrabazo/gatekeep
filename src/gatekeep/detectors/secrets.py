"""Secret detectors: named regexes for known token formats + Shannon-entropy fallback
for opaque high-randomness blobs the regexes don't know about."""

import math
import re
from collections import Counter

from . import Finding, make_preview

PATTERNS: list[tuple[str, re.Pattern]] = [
    # AWS access key ID: literal "AKIA" + 16 uppercase alphanumerics (IAM unique-ID format)
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # GitHub tokens: ghp_ (PAT) / gho_ (OAuth) / ghu_ ghs_ (app) / ghr_ (refresh) + 36+ base62 chars
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    # Slack tokens: xoxb- (bot) / xoxp- (user) / xoxa- xoxr- xoxs- prefixes
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    # PEM private-key header: RSA / EC / OPENSSH qualified or bare
    ("private_key", re.compile(r"-----BEGIN( RSA| EC| OPENSSH)? PRIVATE KEY-----")),
    # JWT: three dot-separated base64url segments; header always starts eyJ ('{"' encoded)
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
]

# Candidate tokens for the entropy check: unbroken runs of base64ish characters.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

_HAS_ALPHA = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"[0-9]")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def scan(text: str, entropy_min_length: int = 20, entropy_threshold: float = 4.0) -> list[Finding]:
    findings: list[Finding] = []
    for name, pattern in PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding("secret", name, (m.start(), m.end()), make_preview(m.group())))

    # Entropy fallback: skip anything already covered by a named regex above.
    taken = [f.span for f in findings]
    for m in _TOKEN.finditer(text):
        token = m.group()
        if len(token) < entropy_min_length:
            continue
        if any(m.start() < end and m.end() > start for start, end in taken):
            continue
        # Mixed charset: pure-alpha words and pure-digit runs are never entropy secrets.
        if not (_HAS_ALPHA.search(token) and _HAS_DIGIT.search(token)):
            continue
        if shannon_entropy(token) >= entropy_threshold:
            findings.append(Finding("secret", "entropy", (m.start(), m.end()), make_preview(token)))
    return findings
