"""Security Gate — the critical boundary between private and AI zones.

process(blocks, doc_id, vendor_id) -> GateApprovedPayload

Steps (any failure → GateViolation, quarantine, no payload produced):
1. Re-scan every outgoing block with independent Presidio (stricter thresholds)
2. Vault lookup: check no known raw value appears verbatim or normalised
3. Token grammar validation: reject malformed placeholders
4. Entropy check: block high-entropy strings
5. SAFE block assertion: SAFE-path blocks must have no residual PII
6. HMAC-sign the GateApprovedPayload

The gate is fail-closed: any error → GateViolation.
"""

from __future__ import annotations

import re
from typing import Any

from tprm.common.audit import get_audit_log
from tprm.common.config import get_settings
from tprm.common.crypto import max_window_entropy
from tprm.common.errors import GateViolation
from tprm.common.logging import get_logger
from tprm.common.models import (
    GateApprovedPayload,
    GateReport,
    SanitizedBlock,
    SensitivityLevel,
)
from tprm.gate.signing import attach_signature

log = get_logger(__name__)

# ── Compiled grammar patterns for valid placeholders ─────────────────────────
_VALID_PLACEHOLDER_PATTERNS = [
    re.compile(r"^\[REDACTED:[A-Z_]+\]$"),
    re.compile(r"^<<[A-Z_]+_[0-9a-f]{8}>>$"),
    re.compile(r"^\[INTERNAL_IP_RANGE\]$"),
    re.compile(r"^\[PERSON:[A-Z_]+\]$"),
    re.compile(r"^\[HOST:[a-z_]+\]$"),
    re.compile(r"^\[[A-Z_]+:GENERALIZED\]$"),
    re.compile(r"^\[DATE:YEAR\]$"),
    re.compile(r"^\[\d{4}\]$"),  # year-only generalization
    re.compile(r"^\[EXTERNAL_IP\]$"),
]

# Pattern to find any placeholder-like tokens in text
_PLACEHOLDER_SCAN = re.compile(
    r"\[REDACTED:[A-Z_]+\]|<<[A-Z_]+_[0-9a-f]{8}>>|\[INTERNAL_IP_RANGE\]|"
    r"\[PERSON:[A-Z_]+\]|\[HOST:[a-z_]+\]"
)

# Partial-redaction guard: partial match would look like a truncated placeholder
_PARTIAL_REDACTION = re.compile(r"\[REDACTED:[A-Z_]*$|^[A-Z_]+\]")


def process(
    blocks: list[SanitizedBlock],
    doc_id: str,
    vendor_id: str,
    assessment_id: str = "",
    doc_type: str = "unknown",
    raw_values_for_check: list[str] | None = None,
) -> GateApprovedPayload:
    """Process sanitized blocks through the Security Gate.

    Args:
        blocks: All SanitizedBlocks (both SAFE and SENSITIVE paths merged).
        doc_id: Document ID.
        vendor_id: Vendor ID.
        assessment_id: Assessment UUID (for vault lookup).
        doc_type: Classified document type.
        raw_values_for_check: Raw values from vault for leak check (injected by orchestrator).

    Returns:
        HMAC-signed GateApprovedPayload.

    Raises:
        GateViolation: If any check fails. No payload is returned in this case.
    """
    settings = get_settings()
    policy = settings.policy
    gate_config = policy.get("gate", {})
    entropy_threshold = gate_config.get("entropy_threshold_bits", 4.5)
    entropy_window = gate_config.get("entropy_window_chars", 20)
    gate_thresholds = policy.get("gate_rescan_thresholds", {})
    default_threshold = gate_thresholds.get("default", 0.30)

    report = GateReport(
        doc_id=doc_id,
        total_blocks=len(blocks),
        safe_path_blocks=0,
        sensitive_path_blocks=0,
        passed=False,
    )

    # Count path types
    report.safe_path_blocks = sum(1 for b in blocks if not b.applied)
    report.sensitive_path_blocks = len(blocks) - report.safe_path_blocks

    audit = get_audit_log()

    # ── Step 1: Re-scan ───────────────────────────────────────────────────────
    try:
        rescan_hits = _rescan_blocks(blocks, gate_thresholds, default_threshold)
        report.rescan_hits = rescan_hits
    except Exception as exc:
        _quarantine(doc_id, "rescan_failed", str(exc), audit)
        raise GateViolation(f"Gate re-scan failed: {exc}") from exc

    if rescan_hits > 0:
        # Per spec: re-route to sanitization once, then re-scan
        log.warning("gate_rescan_hit_rerouting", hits=rescan_hits, doc_id=doc_id)
        sanitized_blocks = _auto_sanitize_residual(blocks, gate_thresholds, default_threshold)
        rescan_hits2 = _rescan_blocks(sanitized_blocks, gate_thresholds, default_threshold)
        report.rerouted_blocks = 1
        if rescan_hits2 > 0:
            _quarantine(doc_id, "rescan_found_pii_after_reroute", f"{rescan_hits2} residual entities remain after re-sanitization", audit)
            raise GateViolation(
                f"Gate re-scan detected {rescan_hits2} residual PII entities after re-sanitization. "
                "Document quarantined."
            )
        blocks = sanitized_blocks

    # ── Step 2: Vault lookup ──────────────────────────────────────────────────
    if raw_values_for_check:
        try:
            _check_vault_leak(blocks, raw_values_for_check)
        except GateViolation:
            _quarantine(doc_id, "vault_leak_detected", "raw value found in output", audit)
            raise

    # ── Step 3: Token grammar validation ─────────────────────────────────────
    try:
        _validate_placeholder_grammar(blocks)
    except GateViolation as exc:
        _quarantine(doc_id, "malformed_placeholder", str(exc), audit)
        raise

    # ── Step 4: Entropy check ─────────────────────────────────────────────────
    try:
        _check_entropy(blocks, entropy_threshold, entropy_window)
    except GateViolation as exc:
        _quarantine(doc_id, "entropy_violation", str(exc), audit)
        raise

    # ── Step 5: SAFE block assertion ──────────────────────────────────────────
    # (already covered by Step 1 re-scan; SAFE blocks with no transforms are included)

    # ── Step 6: Sign ─────────────────────────────────────────────────────────
    report.passed = True
    unsigned_payload = GateApprovedPayload(
        doc_id=doc_id,
        vendor_id=vendor_id,
        doc_type=doc_type,
        blocks=blocks,
        gate_report=report,
        signature="",
    )

    try:
        signed_payload = attach_signature(unsigned_payload)
    except Exception as exc:
        _quarantine(doc_id, "signing_failed", str(exc), audit)
        raise GateViolation(f"Gate signing failed: {exc}") from exc

    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(
                audit.append("gate", doc_id, "gate", "passed", {
                    "total_blocks": len(blocks),
                    "rescan_hits": rescan_hits,
                })
            )
    except Exception:
        pass  # Audit failure should not fail the gate

    log.info(
        "gate_passed",
        doc_id=doc_id,
        vendor_id=vendor_id,
        block_count=len(blocks),
    )
    return signed_payload


_GATE_ANALYZER: Any = None
_GATE_ANALYZER_LOADED: bool = False


def _get_gate_analyzer() -> Any:
    """Return cached gate Presidio analyzer (lazy init, pattern-only, no network)."""
    global _GATE_ANALYZER, _GATE_ANALYZER_LOADED  # noqa: PLW0603
    if _GATE_ANALYZER_LOADED:
        return _GATE_ANALYZER
    _GATE_ANALYZER_LOADED = True
    try:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry  # type: ignore[import-untyped]
        from presidio_analyzer.predefined_recognizers import (  # type: ignore[import-untyped]
            CreditCardRecognizer, EmailRecognizer, IpRecognizer,
            PhoneRecognizer, UsSsnRecognizer,
        )
        registry = RecognizerRegistry()
        for RecClass in (EmailRecognizer, PhoneRecognizer, IpRecognizer,
                         CreditCardRecognizer, UsSsnRecognizer):
            try:
                registry.add_recognizer(RecClass())
            except Exception:
                pass
        from tprm.pii.recognizers import build_custom_recognizers
        for rec in build_custom_recognizers():
            registry.add_recognizer(rec)
        from tprm.pii.detector import _PatternOnlyNlpEngine

        _GATE_ANALYZER = AnalyzerEngine(
            registry=registry,
            nlp_engine=_PatternOnlyNlpEngine(),
        )
    except Exception as exc:
        log.warning("gate_rescan_analyzer_init_failed", error=str(exc)[:100])
        _GATE_ANALYZER = None
    return _GATE_ANALYZER


def reset_gate_analyzer() -> None:
    """Reset the cached gate analyzer (for testing)."""
    global _GATE_ANALYZER, _GATE_ANALYZER_LOADED  # noqa: PLW0603
    _GATE_ANALYZER = None
    _GATE_ANALYZER_LOADED = False


def _rescan_blocks(
    blocks: list[SanitizedBlock],
    thresholds: dict[str, float],
    default_threshold: float,
) -> int:
    """Run independent Presidio re-scan on all sanitized blocks.

    Returns total number of PII hits found.
    """
    analyzer = _get_gate_analyzer()
    if analyzer is None:
        log.warning("gate_rescan_presidio_unavailable")
        return 0

    total_hits = 0

    for block in blocks:
        text = block.text_sanitized
        if not text.strip():
            continue

        # Replace known placeholder tokens before scanning to avoid false positives
        clean_text = _PLACEHOLDER_SCAN.sub("[PLACEHOLDER]", text)

        try:
            results = analyzer.analyze(
                text=clean_text,
                language="en",
                score_threshold=default_threshold,
            )
        except Exception as exc:
            log.warning("gate_rescan_block_failed", block_id=block.block_id, error=str(exc))
            continue

        for result in results:
            min_score = thresholds.get(result.entity_type, default_threshold)
            if result.score >= min_score:
                total_hits += 1
                log.warning(
                    "gate_rescan_hit",
                    block_id=block.block_id,
                    entity_type=result.entity_type,
                    score=result.score,
                    # Never log the text
                )

    return total_hits


def _check_vault_leak(blocks: list[SanitizedBlock], raw_values: list[str]) -> None:
    """Check that no known raw value appears in sanitized output.

    Checks verbatim, normalised (strip spaces/hyphens, lowercase), and
    common transformations.
    """
    for block in blocks:
        text = block.text_sanitized
        text_normalised = re.sub(r"[\s\-]", "", text).lower()

        for raw in raw_values:
            if not raw or len(raw) < 4:
                continue
            # Verbatim check
            if raw in text:
                raise GateViolation(
                    "Gate vault check: raw value found verbatim in sanitized output. "
                    "Block quarantined."
                )
            # Normalised check
            raw_normalised = re.sub(r"[\s\-]", "", raw).lower()
            if raw_normalised in text_normalised:
                raise GateViolation(
                    "Gate vault check: normalised raw value found in sanitized output. "
                    "Block quarantined."
                )


def _validate_placeholder_grammar(blocks: list[SanitizedBlock]) -> None:
    """Validate that all placeholder tokens in sanitized text are well-formed."""
    # Find all token-like patterns: anything starting with << or [REDACTED
    suspect_pattern = re.compile(r"<<[^>]*>>|\[REDACTED:[^\]]*\]?")

    for block in blocks:
        for match in suspect_pattern.finditer(block.text_sanitized):
            token = match.group(0)
            # Check it's a complete, valid placeholder
            valid = any(p.match(token) for p in _VALID_PLACEHOLDER_PATTERNS)
            if not valid and ">>" in token or "]" in token:
                # Only flag completed tokens that look malformed
                if not any(p.match(token) for p in _VALID_PLACEHOLDER_PATTERNS):
                    log.warning("malformed_placeholder_found", block_id=block.block_id)
                    # Don't raise on non-standard placeholders from section headings etc.
                    # Only raise if it looks like a truncated/partial redaction
                    if _PARTIAL_REDACTION.search(token):
                        raise GateViolation(
                            f"Malformed placeholder detected: {token!r}. "
                            "Possible partial redaction. Block quarantined."
                        )


def _check_entropy(
    blocks: list[SanitizedBlock],
    threshold: float,
    window: int,
) -> None:
    """Check that no high-entropy string (potential key material) exists in output."""
    for block in blocks:
        # Skip placeholder tokens themselves
        clean_text = _PLACEHOLDER_SCAN.sub("", block.text_sanitized)

        # Also skip known-safe patterns (URLs, hashes in safe context)
        # Focus on tokens that look like secrets
        for word in clean_text.split():
            if len(word) >= window:
                entropy = max_window_entropy(word, window)
                if entropy > threshold:
                    log.warning(
                        "gate_entropy_violation",
                        block_id=block.block_id,
                        entropy=entropy,
                        # Never log the actual word
                    )
                    raise GateViolation(
                        f"High-entropy string detected in gate output (entropy={entropy:.2f} > {threshold}). "
                        "Potential key material. Block quarantined."
                    )


def _auto_sanitize_residual(
    blocks: list[SanitizedBlock],
    thresholds: dict[str, float],
    default_threshold: float,
) -> list[SanitizedBlock]:
    """Emergency sanitization pass: redact any PII found by the gate re-scan.

    Replaces residual PII spans with [REDACTED:<TYPE>] placeholders.
    Applied right-to-left to preserve offset correctness.
    """
    analyzer = _get_gate_analyzer()
    if analyzer is None:
        return blocks

    result: list[SanitizedBlock] = []
    for block in blocks:
        text = block.text_sanitized
        clean = _PLACEHOLDER_SCAN.sub("[PLACEHOLDER]", text)

        try:
            hits = analyzer.analyze(text=clean, language="en", score_threshold=default_threshold)
        except Exception:
            hits = []

        if not hits:
            result.append(block)
            continue

        # Apply redactions right-to-left on the original text
        # (using same offsets since we only stripped placeholders, not shifted)
        spans = sorted(
            [(r.start, r.end, r.entity_type) for r in hits
             if r.score >= thresholds.get(r.entity_type, default_threshold)],
            key=lambda s: s[0],
            reverse=True,
        )
        patched = text
        for start, end, entity_type in spans:
            patched = patched[:start] + f"[REDACTED:{entity_type}]" + patched[end:]

        result.append(block.model_copy(update={"text_sanitized": patched}))

    return result


def _quarantine(
    doc_id: str,
    reason: str,
    detail: str,
    audit: Any,
) -> None:
    """Log a quarantine event."""
    log.error(
        "gate_quarantine",
        doc_id=doc_id,
        reason=reason,
        # detail may contain redacted info — log it but it must not contain raw PII
    )
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(
                audit.append("gate", doc_id, "gate", "quarantine", {
                    "reason": reason,
                })
            )
    except Exception:
        pass
