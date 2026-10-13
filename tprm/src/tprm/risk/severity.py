"""Severity scorer: compute normalized 0-100 score and severity label."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from tprm.common.config import get_settings
from tprm.common.logging import get_logger
from tprm.risk.extractor import NormalisedRisk

log = get_logger(__name__)

SeverityLabel = Literal["Low", "Medium", "High", "Critical"]


@dataclass
class SeverityScore:
    score: int  # 0-100
    label: SeverityLabel
    factors: dict[str, float]


def score_severity(
    risk: NormalisedRisk,
    category: str,
    gap_status: str = "missing",
    vendor_criticality: float = 1.0,
    audit_boosters: list[str] | None = None,
) -> SeverityScore:
    """Compute severity score for a risk.

    LLM-assessed values (risk.likelihood, risk.impact, risk.gap_status) take
    priority over the YAML taxonomy defaults when present.  YAML values are used
    only as a fallback for fields the LLM did not return.

    Formula: score = clamp(likelihood * impact * control_gap_factor * vendor_criticality * 100, 0, 100)
    Plus audit qualification boosters.

    Args:
        risk: The normalised risk item.
        category: Risk category ID (for impact/likelihood weight lookup when LLM
            values are absent).
        gap_status: Fallback gap status from control-mapping heuristics.  Ignored
            when risk.gap_status is set by the LLM.
        vendor_criticality: 0.8–1.5 (from assessment metadata)
        audit_boosters: List of booster keys (e.g. ["soc2_exception"])

    Returns:
        SeverityScore with numeric score and label.
    """
    settings = get_settings()
    taxonomy = settings.risk_taxonomy

    # ── Resolve per-category YAML defaults (used only as fallback) ────────────
    categories = {c["id"]: c for c in taxonomy.get("categories", [])}
    cat_data = categories.get(category, {})

    yaml_likelihood_default: float = cat_data.get("likelihood_default", 0.5)
    yaml_impact_default: float = cat_data.get("impact_default", 0.6)

    # ── Prefer LLM-assessed values; fall back to YAML defaults ────────────────
    if risk.likelihood is not None:
        likelihood = risk.likelihood
        likelihood_source = "llm"
    else:
        likelihood = yaml_likelihood_default * risk.confidence
        likelihood_source = "yaml_default"

    if risk.impact is not None:
        impact = risk.impact
        impact_source = "llm"
    else:
        impact = yaml_impact_default
        impact_source = "yaml_default"

    # LLM gap_status overrides the heuristic from map_controls()
    effective_gap_status = risk.gap_status if risk.gap_status is not None else gap_status
    gap_status_source = "llm" if risk.gap_status is not None else "heuristic"

    gap_factors = taxonomy.get("control_gap_factors", {
        "satisfied": 1.0, "partial": 1.3, "missing": 1.6,
    })
    control_gap_factor = gap_factors.get(effective_gap_status, 1.6)

    raw_score = likelihood * impact * control_gap_factor * vendor_criticality * 100

    # ── Audit boosters ─────────────────────────────────────────────────────────
    booster_total = 0
    booster_config = taxonomy.get("audit_boosters", {})
    for booster_key in (audit_boosters or []):
        booster_total += booster_config.get(booster_key, 0)

    final_score = min(int(raw_score) + booster_total, 100)
    final_score = max(final_score, 0)

    thresholds = taxonomy.get("severity_thresholds", {
        "Critical": 75, "High": 50, "Medium": 25, "Low": 0,
    })
    label = _score_to_label(final_score, thresholds)

    log.debug(
        "severity_scored",
        risk_id=risk.id,
        score=final_score,
        label=label,
        category=category,
        likelihood_source=likelihood_source,
        impact_source=impact_source,
        gap_status_source=gap_status_source,
        effective_gap_status=effective_gap_status,
    )

    return SeverityScore(
        score=final_score,
        label=label,
        factors={
            "likelihood": likelihood,
            "impact": impact,
            "control_gap_factor": control_gap_factor,
            "vendor_criticality": vendor_criticality,
            "booster": float(booster_total),
        },
    )


def _score_to_label(score: int, thresholds: dict[str, int]) -> SeverityLabel:
    if score >= thresholds.get("Critical", 75):
        return "Critical"
    if score >= thresholds.get("High", 50):
        return "High"
    if score >= thresholds.get("Medium", 25):
        return "Medium"
    return "Low"
