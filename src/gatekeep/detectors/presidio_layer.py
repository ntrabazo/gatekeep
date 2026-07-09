"""Optional Presidio second layer (presidio.enabled in policies.yaml, off by default).
Imports are lazy and module-local: with the flag off this module is never imported,
so the base proxy carries zero Presidio/spaCy weight."""

from . import Finding, make_preview

_analyzer = None

# NER entities the hand-rolled regexes can't see; both map to the existing pii category
# so policy rules need no changes when the flag flips on.
_ENTITY_MAP = {"PERSON": "pii", "LOCATION": "pii"}


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Pin to en_core_web_sm: AnalyzerEngine() defaults to en_core_web_lg and will
        # download 400MB at runtime if it's missing.
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        _analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
    return _analyzer


def analyze(text: str) -> list[Finding]:
    results = _get_analyzer().analyze(text=text, entities=list(_ENTITY_MAP), language="en")
    return [
        Finding(
            _ENTITY_MAP[r.entity_type],
            f"presidio_{r.entity_type.lower()}",
            (r.start, r.end),
            make_preview(text[r.start:r.end]),
        )
        for r in results
    ]
