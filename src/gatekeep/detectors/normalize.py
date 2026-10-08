"""Normalization pre-pass for the injection detector.

Best-effort by design: the map below will never cover every lookalike, so the
`obfuscation_present` flag — not perfect folding — is the durable signal. A lookalike
outside the map still trips the flag via the NFC/NFKC comparison or leaves the pattern
unmatched, in which case the flag is what the scorer leans on (PLAN-injection.md D7).
"""

import re
import unicodedata

# Zero-width and direction-control characters attackers lace into trigger words.
_ZERO_WIDTH = {
    "​", "‌", "‍", "‎", "‏",  # ZWSP / ZWNJ / ZWJ / LRM / RLM
    "‪", "‫", "‬", "‭", "‮",  # directional embedding/override
    "⁠", "﻿",                                # word joiner, BOM / ZWNBSP
}

# Small documented map of common Cyrillic/Greek Latin-lookalikes. Not exhaustive.
_HOMOGLYPHS = str.maketrans({
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek lowercase
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})

_WS_RUN = re.compile(r"\s+")

# Typo folding: a one-edit misspelling of a pattern keyword ("intructions", "ingore",
# "previus") is folded back to the keyword so the structure-keyed patterns still see it.
# Real attackers misspell, by accident and to dodge keyword filters. Guards against
# false folds: same first letter, exactly one edit (OSA: insert/delete/substitute/swap),
# never an inflection of the keyword ("ignored", "prompts"), never a listed real word.
TYPO_KEYWORDS = ("ignore", "disregard", "instructions", "instruction", "previous",
                 "guidelines", "directions", "prompt", "system")
_TYPO_STOPLIST = frozenset({"pervious"})  # the only real one-edit neighbour of a keyword
_WORD = re.compile(r"[A-Za-z]+")


def _osa_distance(a: str, b: str) -> int:
    """Optimal-string-alignment edit distance (Levenshtein + adjacent transposition)."""
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


def _fold_word(m: re.Match) -> str:
    word = m.group()
    low = word.lower()
    if len(low) < 5 or low in TYPO_KEYWORDS or low in _TYPO_STOPLIST:
        return word
    for kw in TYPO_KEYWORDS:
        if (low[0] == kw[0] and abs(len(low) - len(kw)) <= 1 and not low.startswith(kw)
                and _osa_distance(low, kw) == 1):
            return kw
    return word


def fold_typos(text: str) -> str:
    return _WORD.sub(_fold_word, text)


def normalize(text: str) -> tuple[str, bool]:
    """Return (normalized_text, obfuscation_present).

    NFKC-normalize, strip zero-width/direction controls, fold known homoglyphs,
    collapse whitespace runs, fold one-edit typos of pattern keywords.
    obfuscation_present is True when compatibility characters, zero-width characters,
    or homoglyphs were found — plain NFD→NFC composition of accented text does NOT
    count (keeps accented benigns clean), and neither do typos (benign text has them).
    """
    nfkc = unicodedata.normalize("NFKC", text)
    compat_changed = nfkc != unicodedata.normalize("NFC", text)

    without_zw = "".join(c for c in nfkc if c not in _ZERO_WIDTH)
    zw_found = len(without_zw) != len(nfkc)

    collapsed = _WS_RUN.sub(" ", without_zw).strip()
    folded = " ".join(_fold_homoglyphs(tok) for tok in collapsed.split(" "))
    fold_found = folded != collapsed

    return fold_typos(folded), bool(compat_changed or zw_found or fold_found)


def _fold_homoglyphs(token: str) -> str:
    """Fold lookalikes only inside MIXED-script words ("іgnore": Cyrillic і + Latin gnore).
    A wholly Cyrillic or Greek word is just Russian or Greek, not an obfuscation attempt."""
    return token.translate(_HOMOGLYPHS) if _LATIN.search(token) else token


_LATIN = re.compile(r"[A-Za-z]")
