"""Risk extractor: normalise and deduplicate RawRisk items from LLM output."""

from __future__ import annotations

from tprm.common.logging import get_logger
from tprm.common.models import AIRiskResult, RawRisk, SanitizedBlock

log = get_logger(__name__)

_SIMILARITY_THRESHOLD = 0.85  # title similarity above which items are merged


class NormalisedRisk:
    """A deduplicated, validated risk item."""

    def __init__(self, raw: RawRisk, valid_block_ids: set[str]) -> None:
        self.id = raw.id
        self.title = raw.title.strip()
        self.description = raw.description.strip()
        self.evidence_block_ids = [
            bid for bid in raw.evidence_block_ids if bid in valid_block_ids
        ]
        self.claimed_category = raw.claimed_category
        self.confidence = raw.confidence
        # LLM-assessed scoring signals (None when the LLM did not return them)
        self.likelihood = raw.likelihood
        self.impact = raw.impact
        self.gap_status = raw.gap_status


def extract(
    result: AIRiskResult,
    blocks: list[SanitizedBlock],
) -> list[NormalisedRisk]:
    """Extract, validate, and deduplicate risks from AI output.

    Args:
        result: AIRiskResult from the LLM.
        blocks: Sanitized blocks (used to validate evidence block IDs).

    Returns:
        List of NormalisedRisk with validated evidence IDs and merged duplicates.
    """
    valid_block_ids = {b.block_id for b in blocks}

    normalised: list[NormalisedRisk] = []
    for item in result.items:
        risk = NormalisedRisk(item, valid_block_ids)
        if not risk.evidence_block_ids:
            log.warning("risk_no_valid_evidence", risk_id=item.id, title=item.title[:50])
            continue
        normalised.append(risk)

    deduplicated = _deduplicate(normalised)
    log.info("risk_extracted", raw_count=len(result.items), deduped_count=len(deduplicated))
    return deduplicated


def _deduplicate(risks: list[NormalisedRisk]) -> list[NormalisedRisk]:
    """Merge risks with similar titles (simple word-overlap similarity)."""
    if len(risks) <= 1:
        return risks

    unique: list[NormalisedRisk] = []
    for candidate in risks:
        merged = False
        for existing in unique:
            if _title_similarity(candidate.title, existing.title) >= _SIMILARITY_THRESHOLD:
                # Merge: keep higher confidence, combine evidence
                if candidate.confidence > existing.confidence:
                    existing.confidence = candidate.confidence
                    existing.description = candidate.description
                existing.evidence_block_ids = list(
                    set(existing.evidence_block_ids + candidate.evidence_block_ids)
                )
                merged = True
                break
        if not merged:
            unique.append(candidate)

    return unique


def _title_similarity(a: str, b: str) -> float:
    """Simple Jaccard word overlap similarity."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)
