"""PII Detector — public interface: detect(blocks, config) -> list[PIIEntity].

Uses Presidio AnalyzerEngine with spaCy local NER backend and custom recognizers.
Recall-biased: thresholds are configured to prefer false positives.
"""

from __future__ import annotations

from typing import Any

from tprm.common.logging import get_logger
from tprm.common.models import Block, PIIEntity
from tprm.pii.recognizers import build_custom_recognizers

log = get_logger(__name__)

# Default entities to detect (superset; Presidio will only return what recognizers support)
_DEFAULT_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    "CREDIT_CARD",
    "US_SSN",
    "US_PASSPORT",
    "IP_ADDRESS",
    "MAC_ADDRESS",
    "CREDENTIAL_URL",
    "API_KEY",
    "PEM_PRIVATE_KEY",
    "INTERNAL_HOSTNAME",
    "PERSON",
    "ORG",
    "LOCATION",
    "EMPLOYEE_ID",
    "CONTRACT_NUMBER",
    "BANK_ACCOUNT",
    "NRP",
    "URL",
]

_ANALYZER_SINGLETON: Any = None


class _PatternOnlyNlpEngine:
    """Small Presidio-compatible NLP engine for recognizer-only scanning."""

    def __init__(self) -> None:
        import spacy

        from presidio_analyzer.nlp_engine import NlpArtifacts

        self._nlp = spacy.blank("en")
        self._artifacts_type = NlpArtifacts

    def load(self) -> None:
        return None

    def is_loaded(self) -> bool:
        return True

    def process_text(self, text: str, language: str) -> Any:
        doc = self._nlp(text)
        return self._artifacts_type(
            entities=[],
            tokens=doc,
            tokens_indices=[token.idx for token in doc],
            lemmas=[token.text for token in doc],
            nlp_engine=self,
            language=language,
        )

    def process_batch(self, texts: Any, language: str, **kwargs: Any) -> Any:
        return ((text, self.process_text(text, language)) for text in texts)

    def is_stopword(self, word: str, language: str) -> bool:
        return False

    def is_punct(self, word: str, language: str) -> bool:
        return False

    def get_supported_entities(self) -> list[str]:
        return []


def _get_analyzer(
    thresholds: dict[str, float] | None = None,
    org_domains: list[str] | None = None,
) -> Any:
    """Build and cache the Presidio AnalyzerEngine.

    Prefers spaCy NER if a model is already installed locally.
    Falls back to NoOpNlpEngine (pattern-only, no network call) when no
    spaCy model is available.
    """
    global _ANALYZER_SINGLETON  # noqa: PLW0603

    if _ANALYZER_SINGLETON is not None:
        return _ANALYZER_SINGLETON

    try:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry  # type: ignore[import-untyped]
        from presidio_analyzer.nlp_engine import NlpEngineProvider  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError("presidio-analyzer is not installed") from exc

    # ── Try to load a locally-installed spaCy model (no auto-download) ───────
    nlp_engine = None
    try:
        import spacy  # type: ignore[import-untyped]
        for model_name in ("en_core_web_lg", "en_core_web_sm"):
            if spacy.util.is_package(model_name):
                try:
                    provider = NlpEngineProvider(nlp_configuration={
                        "nlp_engine_name": "spacy",
                        "models": [{"lang_code": "en", "model_name": model_name}],
                    })
                    nlp_engine = provider.create_engine()
                    log.info("spacy_nlp_loaded", model=model_name)
                    break
                except Exception:
                    pass
    except ImportError:
        pass

    # ── Build registry ────────────────────────────────────────────────────────
    registry = RecognizerRegistry()

    if nlp_engine is not None:
        # Full mode: load all predefined recognizers (includes NER-backed ones)
        try:
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)
        except Exception as exc:
            log.warning("presidio_predefined_load_failed", error=str(exc)[:100])
    else:
        # Pattern-only mode: manually register pattern-based built-ins
        log.warning("spacy_model_not_found_using_pattern_only_pii")
        nlp_engine = _PatternOnlyNlpEngine()
        try:
            from presidio_analyzer.predefined_recognizers import (  # type: ignore[import-untyped]
                CreditCardRecognizer, EmailRecognizer, IpRecognizer,
                PhoneRecognizer, UsSsnRecognizer,
            )
            for RecClass in (
                EmailRecognizer, PhoneRecognizer, IpRecognizer,
                CreditCardRecognizer, UsSsnRecognizer,
            ):
                try:
                    registry.add_recognizer(RecClass())
                except Exception:
                    pass
        except ImportError:
            pass

    # ── Add TPRM custom recognizers ───────────────────────────────────────────
    for rec in build_custom_recognizers(org_domains=org_domains):
        registry.add_recognizer(rec)

    analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine)
    _ANALYZER_SINGLETON = analyzer
    return analyzer


def reset_analyzer() -> None:
    """Reset the cached analyzer singleton (for testing with different configs)."""
    global _ANALYZER_SINGLETON  # noqa: PLW0603
    _ANALYZER_SINGLETON = None


def detect(
    blocks: list[Block],
    thresholds: dict[str, float] | None = None,
    org_domains: list[str] | None = None,
) -> list[PIIEntity]:
    """Detect PII entities in a list of blocks.

    Args:
        blocks: Parsed document blocks.
        thresholds: Per-entity-type minimum score. Defaults from policy.yaml.
        org_domains: Known internal org domains for hostname recognizer.

    Returns:
        List of PIIEntity, with overlapping spans resolved (longest/highest score wins).
    """
    if thresholds is None:
        thresholds = {}

    analyzer = _get_analyzer(thresholds=thresholds, org_domains=org_domains)
    all_entities: list[PIIEntity] = []

    for block in blocks:
        if not block.text.strip():
            continue

        try:
            results = analyzer.analyze(
                text=block.text,
                language="en",
                entities=_DEFAULT_ENTITIES,
                score_threshold=0.0,  # We filter by per-type threshold below
            )
        except Exception as exc:
            log.warning("pii_detection_error", block_id=block.id, error=str(exc))
            results = []

        block_entities: list[PIIEntity] = []
        for result in results:
            min_score = thresholds.get(result.entity_type, 0.35)
            if result.score < min_score:
                continue
            entity = PIIEntity(
                block_id=block.id,
                start=result.start,
                end=result.end,
                entity_type=result.entity_type,
                text=block.text[result.start : result.end],  # raw value — never logged
                score=result.score,
                recognizer=result.recognition_metadata.get("recognizer_name", "unknown")
                if result.recognition_metadata
                else "unknown",
            )
            block_entities.append(entity)

        # Resolve overlaps: longest span wins; ties broken by highest score
        resolved = _resolve_overlaps(block_entities)
        all_entities.extend(resolved)

        if resolved:
            # Log only counts, never entity text
            counts: dict[str, int] = {}
            for e in resolved:
                counts[e.entity_type] = counts.get(e.entity_type, 0) + 1
            log.debug("pii_detected", block_id=block.id, counts=counts)

    log.info(
        "pii_detection_complete",
        block_count=len(blocks),
        entity_count=len(all_entities),
    )
    return all_entities


def _resolve_overlaps(entities: list[PIIEntity]) -> list[PIIEntity]:
    """Remove overlapping entity spans, keeping the longest (or highest-score) span."""
    if len(entities) <= 1:
        return entities

    # Sort by span length desc, then score desc
    sorted_entities = sorted(entities, key=lambda e: (e.end - e.start, e.score), reverse=True)
    kept: list[PIIEntity] = []

    for candidate in sorted_entities:
        # Check if this candidate overlaps with any already-kept entity
        overlaps = any(
            not (candidate.end <= kept_e.start or candidate.start >= kept_e.end)
            for kept_e in kept
        )
        if not overlaps:
            kept.append(candidate)

    # Return in original text order
    return sorted(kept, key=lambda e: e.start)
