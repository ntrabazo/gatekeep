"""Tier-1 heuristic prompt-injection detector (pure stdlib, offline, deterministic).

Patterns are STRUCTURE-KEYED — verb + object shape, never bare trigger words — because
hard-benign false positives (NotInject-style text that merely contains "ignore" or
"system prompt") are the make-or-break metric, not catch rate.

Spans reference NORMALIZED-text offsets (see normalize.py); raw-offset remapping is
deliberately out of scope for v1 and documented on /v1/screen.

Tier-2 (LLM judge) is designed in PLAN-injection.md §16 and ships in v2 — nothing here
makes a network call.
"""

import re

from . import Finding, make_preview
from .normalize import normalize

_I = re.IGNORECASE

# Instruction-like object nouns an override verb must target to count.
_NOUNS = r"(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?|commands?|context|programming|training)"
_LEAK_VERBS = r"(?:print|show|reveal|repeat|output|display|disclose|leak|expose|share|tell\s+me|give\s+me|recite|dump|paste)"
_EXFIL_VERBS = r"(?:send|forward|post|upload|email|exfiltrate|transmit|leak|submit)"
_EXFIL_PAYLOAD = (
    r"(?:conversation|chat\s+history|message\s+history|(?:this|the|our)\s+(?:chat|conversation|thread|context)"
    r"|secrets?|credentials?|api\s+keys?|passwords?|tokens?|everything\s+above|the\s+above)"
)

# technique -> [(compiled regex, weight)]
PATTERNS: dict[str, list[tuple[re.Pattern, float]]] = {
    "instruction_override": [
        (re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|discard|drop)\b[^.?!\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|preceding|initial|original|all|any|your|these|those|system|the)\b"
            r"[^.?!\n]{0,40}\b" + _NOUNS + r"\b", _I), 0.85),
        (re.compile(r"\b(?:ignore|disregard|forget)\b[^.?!\n]{0,20}\babove\b[^.?!\n]{0,20}\b(?:and|instead)\b", _I), 0.85),
        (re.compile(r"\bnew\s+(?:instructions?|rules?|directives?)\s*:", _I), 0.8),
        # Reset idiom: "forget everything we discussed", "disregard all that came before".
        (re.compile(
            r"\b(?:forget|disregard|ignore)\s+(?:about\s+)?(?:everything|all)\b[^.?!\n]{0,40}"
            r"\b(?:before|above|previous|prior|so\s+far|earlier|that\s+(?:came|was)\s+before"
            r"|we(?:'ve|\s+have)?\s+(?:just\s+)?(?:talked|discussed|said|covered))\b", _I), 0.85),
        (re.compile(
            r"\b(?:do\s+not|don'?t|stop|refuse\s+to)\s+(?:follow(?:ing)?|obey(?:ing)?|listen\s+to|comply\s+with)\b"
            r"[^.?!\n]{0,40}\b(?:instructions?|rules?|guidelines?|directives?|commands?|orders?|programming"
            r"|system|above|previous|original)\b", _I), 0.8),
        # German coverage: deepset/prompt-injections carries German attack rows.
        (re.compile(
            r"\b(?:ignorier\w*|vergiss|vergesse?n?)\b[^.?!\n]{0,50}"
            r"\b(?:alles|anweisung\w*|instruktion\w*|vorherig\w*|obig\w*|regeln)\b", _I), 0.85),
    ],
    "role_manipulation": [
        # Persona/capability reassignment — structure-keyed so "you are now logged in" is spared.
        (re.compile(
            r"\byou\s+are\s+now\s+(?:a\s+|an\s+|the\s+)?(?:[a-z]+\s+){0,3}?"
            r"(?:ai|assistant|bot|model|chatbot|dan|hacker|persona|character|entity"
            r"|unrestricted|unfiltered|uncensored|jailbroken)\b", _I), 0.8),
        (re.compile(
            r"\byou\s+are\s+no\s+longer\s+(?:bound|restricted|limited|required|obligated|constrained"
            r"|subject\s+to|claude|an?\s+ai)\b", _I), 0.8),
        (re.compile(r"\bfrom\s+now\s+on\b[^.?!\n]{0,60}\b(?:you\s+(?:are|will|must|can|should)|you'?re)\b", _I), 0.8),
        (re.compile(
            r"\b(?:act|pretend|behave|roleplay)\b[^.?!\n]{0,30}\b(?:as\s+if|as\s+though|like|as)\b[^.?!\n]{0,50}"
            r"\b(?:no\s+(?:rules|restrictions?|limitations?|filters?|guidelines?)|unrestricted|unfiltered|uncensored"
            r"|jailbro\w+|DAN|evil|without\s+(?:any\s+)?(?:rules|restrictions?|limitations?|filters?|ethic\w*))", _I), 0.85),
        (re.compile(r"\b(?:DAN\s+mode|jailbreak|jailbroken)\b", _I), 0.8),
        # "developer/god mode" only when being activated or declared on — spares "Chrome's developer mode".
        (re.compile(
            r"\b(?:enter|enable|activ\w+|turn\s+on|switch\s+(?:to|into)|go\s+into|unlock)\b"
            r"[^.?!\n]{0,20}\b(?:developer|god|dan)\s+mode\b", _I), 0.8),
        (re.compile(r"\b(?:developer|god|dan)\s+mode\s+(?:enabled|activated|unlocked|is\s+(?:now\s+)?on)\b", _I), 0.8),
        # "no ethical guidelines", "no moral or ethical guidelines", "without safety and content filters"
        (re.compile(
            r"\b(?:no|without|free\s+(?:of|from))\s+(?:(?:ethical|moral|safety|content)\b[\s,]+(?:or\s+|and\s+)?){1,3}"
            r"(?:guidelines?|restrictions?|filters?|constraints?|policies|rules?)\b", _I), 0.8),
    ],
    "system_prompt_leak": [
        (re.compile(
            r"\b" + _LEAK_VERBS + r"\b[^.?!\n]{0,40}"
            r"\b(?:system\s+prompt|system\s+message|initial\s+(?:prompt|instructions?)"
            r"|hidden\s+(?:prompt|instructions?)|pre.?prompt|original\s+instructions?)\b", _I), 0.85),
        (re.compile(
            r"\b" + _LEAK_VERBS + r"\b[^.?!\n]{0,30}"
            r"\byour\s+(?:instructions?|prompt|rules|guidelines|directives|configuration|programming)\b", _I), 0.8),
        (re.compile(
            r"\bwhat\s+(?:is|are|was|were)\s+(?:your|the)\s+"
            r"(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|original\s+prompt)\b", _I), 0.8),
        # "print the above prompt", "spell-check and print above prompt" (deepset END-marker idiom).
        (re.compile(
            r"\b(?:print|repeat|output|display|reproduce)\b[^.?!\n]{0,25}"
            r"\b(?:the\s+)?above\s+(?:prompt|instructions?|input|system\s+prompt)\b", _I), 0.8),
    ],
    "delimiter_injection": [
        (re.compile(r"</?\s*(?:system|sys|assistant|instructions?|admin)\s*>", _I), 0.8),
        (re.compile(r"\[\s*/?\s*(?:SYSTEM|INST|ADMIN)\s*\]", _I), 0.8),
        (re.compile(r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext)\s*\|?>", _I), 0.8),
        (re.compile(r"<<\s*/?\s*SYS\s*>>", _I), 0.8),
        (re.compile(r"(?:^|\s)(?:#{2,}|={3,}|-{3,})\s*(?:system|admin|new\s+instructions?)\b", _I), 0.75),
        (re.compile(r"\bBEGIN\s+(?:SYSTEM|ADMIN|NEW)\s+(?:PROMPT|INSTRUCTIONS?|MESSAGE)\b", _I), 0.8),
    ],
    "exfiltration": [
        (re.compile(
            r"\b" + _EXFIL_VERBS + r"\b[^.?!\n]{0,60}\b" + _EXFIL_PAYLOAD + r"\b[^.?!\n]{0,80}\b(?:to|at)\b", _I), 0.8),
        (re.compile(
            r"\b" + _EXFIL_VERBS + r"\b[^.?!\n]{0,80}\bto\s+(?:https?://\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+)", _I), 0.75),
        # Markdown image with a query string: the classic zero-click exfil channel.
        (re.compile(r"!\[[^\]]{0,80}\]\(\s*https?://[^)\s]{1,200}[?&=][^)\s]*\)", _I), 0.8),
    ],
}

OBFUSCATION_WEIGHT = 0.4


def scan(text: str) -> list[Finding]:
    """Scan one text; return injection Findings with 0-1 scores (normalized-text spans)."""
    normalized, obfuscation_present = normalize(text)
    findings: list[Finding] = []
    for technique, patterns in PATTERNS.items():
        for rx, weight in patterns:
            for m in rx.finditer(normalized):
                findings.append(Finding("injection", technique, m.span(), make_preview(m.group()), weight))
    if obfuscation_present:
        findings.append(Finding("injection", "obfuscation", (0, len(normalized)), "…", OBFUSCATION_WEIGHT))
    return findings


def document_score(findings: list[Finding]) -> float:
    """Aggregate injection findings to one document score: 1 - Π(1 - w_i), capped at 1.0."""
    p = 1.0
    for f in findings:
        if f.category == "injection":
            p *= 1.0 - min(f.score, 1.0)
    return min(1.0, 1.0 - p)
