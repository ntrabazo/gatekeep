"""Detector registry. Every detector returns Findings; raw matched text never leaves this layer."""

from dataclasses import dataclass


@dataclass
class Finding:
    category: str          # "secret" | "pii" | "injection"
    detector: str          # e.g. "aws_access_key", "ssn", "entropy", "instruction_override"
    span: tuple[int, int]  # (start, end) offsets in the scanned text (injection: normalized text)
    preview: str           # first 4 chars + ellipsis — never the full match
    score: float = 1.0     # confidence 0-1; secrets/PII stay certain at the default


def make_preview(match: str) -> str:
    return match[:4] + "…"


def run_all(text: str, cfg=None) -> list[Finding]:
    """Run every enabled detector over one text. cfg is the Policies object;
    None falls back to built-in entropy defaults.

    Note: cfg=None also SKIPS every config-gated detector (presidio, injection) by
    design, not by accident — those layers key off their cfg flags."""
    from . import pii, secrets

    min_length, threshold = 20, 4.0
    if cfg is not None:
        min_length = cfg.entropy.min_length
        threshold = cfg.entropy.threshold

    findings = secrets.scan(text, entropy_min_length=min_length, entropy_threshold=threshold)
    findings += pii.scan(text)
    if cfg is not None and cfg.presidio.enabled:
        from . import presidio_layer  # lazy: never imported while the flag is off
        findings += presidio_layer.analyze(text)
    if cfg is not None and cfg.injection.enabled:
        from . import injection
        findings += injection.scan(text)
    return findings
