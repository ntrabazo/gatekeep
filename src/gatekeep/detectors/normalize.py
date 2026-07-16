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


def normalize(text: str) -> tuple[str, bool]:
    """Return (normalized_text, obfuscation_present).

    NFKC-normalize, strip zero-width/direction controls, fold known homoglyphs,
    collapse whitespace runs. obfuscation_present is True when compatibility
    characters, zero-width characters, or homoglyphs were found — plain NFD→NFC
    composition of accented text does NOT count (keeps accented benigns clean).
    """
    nfkc = unicodedata.normalize("NFKC", text)
    compat_changed = nfkc != unicodedata.normalize("NFC", text)

    without_zw = "".join(c for c in nfkc if c not in _ZERO_WIDTH)
    zw_found = len(without_zw) != len(nfkc)

    folded = without_zw.translate(_HOMOGLYPHS)
    fold_found = folded != without_zw

    collapsed = _WS_RUN.sub(" ", folded).strip()
    return collapsed, bool(compat_changed or zw_found or fold_found)
