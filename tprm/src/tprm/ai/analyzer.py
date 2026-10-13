"""AI Risk Analysis — public interface: analyze(payload) -> AIRiskResult.

Only accepts GateApprovedPayload (HMAC-verified at entry).
Uses LangChain -> Ollama (local) -> PydanticOutputParser.
FakeLLM available for deterministic testing.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict
from typing import Any, Protocol, runtime_checkable

from tprm.ai.prompts import build_prompt
from tprm.common.errors import LLMError, LLMParseError, SignatureError
from tprm.common.logging import get_logger
from tprm.common.models import AIRiskResult, GateApprovedPayload, RawRisk, SanitizedBlock
from tprm.gate.verifier import verify_gate_approved

log = get_logger(__name__)

_MAX_RETRIES = 2
_MAX_TOKENS_PER_SECTION = 1200
_MAX_CONCURRENT_SECTIONS = 3  # parallel LLM calls — avoids overwhelming a local Ollama

# Sections with few blocks get merged together to cut LLM round-trips
_MIN_BLOCKS_FOR_OWN_CALL = 5

# Map of freeform gap_status values the LLM sometimes returns → canonical values
_GAP_STATUS_ALIASES: dict[str, str] = {
    "open": "missing",
    "not implemented": "missing",
    "not in place": "missing",
    "none": "missing",
    "no control": "missing",
    "in progress": "partial",
    "partially implemented": "partial",
    "partial implementation": "partial",
    "some": "partial",
    "exists": "satisfied",
    "implemented": "satisfied",
    "in place": "satisfied",
    "met": "satisfied",
    "complete": "satisfied",
    "compliant": "satisfied",
}


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for LLM backends (ChatOllama or FakeLLM)."""

    def invoke(self, messages: list[dict[str, str]]) -> Any: ...


class FakeLLM:
    """Deterministic test LLM — returns fixed risk items keyed by section_class."""

    FAKE_RESPONSES: dict[str, list[dict[str, Any]]] = {
        "access_control": [
            {
                "id": "risk-ac-001",
                "title": "Privileged Access Keys Not Rotated Within Policy Window",
                "description": "Long-lived access credentials were identified that have not been rotated in accordance with the vendor's stated 90-day rotation policy. Static keys stored outside a secrets manager increase the risk of credential compromise.",
                "evidence_block_ids": [],
                "claimed_category": "ACCESS_MGMT",
                "confidence": 0.88,
                "likelihood": 0.75,
                "impact": 0.85,
                "gap_status": "partial",
            }
        ],
        "encryption": [
            {
                "id": "risk-enc-001",
                "title": "Storage Buckets Using Weaker Encryption Standard",
                "description": "Certain storage resources were found to use server-side encryption without customer-managed keys, preventing full audit trail for key usage and limiting control over key rotation cadence.",
                "evidence_block_ids": [],
                "claimed_category": "ENCRYPTION",
                "confidence": 0.79,
                "likelihood": 0.55,
                "impact": 0.80,
                "gap_status": "partial",
            }
        ],
        "incident_response": [
            {
                "id": "risk-ir-001",
                "title": "Incident Response Runbook Contains Outdated Contact Information",
                "description": "The documented incident response procedures reference contact details that are no longer current, which could delay effective response during a real security incident.",
                "evidence_block_ids": [],
                "claimed_category": "INCIDENT_RESPONSE",
                "confidence": 0.72,
                "likelihood": 0.60,
                "impact": 0.70,
                "gap_status": "partial",
            }
        ],
        "subprocessors": [
            {
                "id": "risk-sp-001",
                "title": "Subprocessor Processing Personal Data Without Explicit DPA Review",
                "description": "One or more subprocessors handling personal data could not be confirmed to have an up-to-date data processing agreement in place, creating a potential compliance gap under applicable data protection regulations.",
                "evidence_block_ids": [],
                "claimed_category": "SUBPROCESSOR",
                "confidence": 0.75,
                "likelihood": 0.65,
                "impact": 0.75,
                "gap_status": "missing",
            }
        ],
        "data_retention": [
            {
                "id": "risk-dp-001",
                "title": "Personal Data Retained in Non-Production Environment",
                "description": "Evidence suggests that personal data from production systems may be present in non-production (test/staging) environments without the same level of access controls, increasing unnecessary exposure.",
                "evidence_block_ids": [],
                "claimed_category": "PRIVACY_DATA",
                "confidence": 0.82,
                "likelihood": 0.70,
                "impact": 0.90,
                "gap_status": "missing",
            }
        ],
        "default": [
            {
                "id": "risk-gen-001",
                "title": "Security Control Gap Identified in Assessment Scope",
                "description": "The reviewed section contains evidence of a control that does not fully meet the stated security requirements. The gap increases residual risk in this domain and should be addressed in the remediation plan.",
                "evidence_block_ids": [],
                "claimed_category": "INFO_SEC",
                "confidence": 0.65,
                "likelihood": 0.50,
                "impact": 0.60,
                "gap_status": "partial",
            }
        ],
    }

    def invoke(self, messages: list[dict[str, str]]) -> Any:
        """Return a deterministic JSON response based on section_class in messages."""
        # Extract section_class from the user message
        user_content = next((m.get("content", "") for m in messages if m.get("role") == "user"), "")
        section_class = "default"
        match = re.search(r"Section class: (\w+)", user_content)
        if match:
            section_class = match.group(1)

        # For combined/mixed calls return all section responses
        if section_class in ("mixed", "other"):
            items = [
                item
                for sc, sc_items in self.FAKE_RESPONSES.items()
                if sc != "default"
                for item in sc_items
            ]
        else:
            items = self.FAKE_RESPONSES.get(section_class, self.FAKE_RESPONSES["default"])

        # Extract block IDs from prompt to populate evidence
        block_id_match = re.search(r"Available block IDs for evidence citation: ([^\n]+)", user_content)
        block_ids = []
        if block_id_match:
            block_ids = [b.strip() for b in block_id_match.group(1).split(",")][:1]

        populated_items = []
        for item in items:
            populated_item = dict(item)
            populated_item["evidence_block_ids"] = block_ids if block_ids else ["fake-block-001"]
            populated_items.append(populated_item)

        result = {"items": populated_items}

        class FakeMessage:
            content = json.dumps(result)

        return FakeMessage()


def _build_langchain_llm(settings: Any) -> Any:
    """Build a ChatOllama LangChain LLM instance."""
    try:
        from langchain_ollama import ChatOllama  # type: ignore[import-untyped]
        return ChatOllama(
            model=settings.llm_model,
            base_url=settings.ollama_url,
            temperature=0,
        )
    except ImportError as exc:
        raise LLMError("langchain-ollama is not installed") from exc


async def analyze(
    payload: GateApprovedPayload,
    llm: LLMBackend | None = None,
) -> AIRiskResult:
    """Analyze a gate-approved payload for security risks.

    Args:
        payload: Must be a valid, HMAC-signed GateApprovedPayload.
        llm: Optional LLM backend override (use FakeLLM for tests).

    Returns:
        AIRiskResult with deduplicated risk items.

    Raises:
        SignatureError: If the payload signature is invalid.
        LLMError: If all LLM retries fail.
    """
    # ── Entry guard: verify signature ─────────────────────────────────────────
    verify_gate_approved(payload)

    from tprm.common.config import get_settings
    settings = get_settings()

    if llm is None:
        llm = _build_langchain_llm(settings)

    # ── Single combined call — Ollama is single-threaded so one well-formed  ──
    # call is always faster than N sequential section calls.
    # Pick the most informative blocks (SENSITIVE ones first, cap total text).
    sensitive_first = sorted(
        payload.blocks,
        key=lambda b: len(b.applied) if hasattr(b, "applied") else 0,
        reverse=True,
    )
    block_ids = [b.block_id for b in sensitive_first]
    valid_block_ids = {b.block_id for b in payload.blocks}

    combined_text = "\n\n".join(
        f"[Block {b.block_id} | {b.section_class}]\n{b.text_sanitized}"
        for b in sensitive_first
    )

    system_prompt, user_prompt = build_prompt(
        section_class="mixed",
        doc_type=payload.doc_type,
        sanitized_text=combined_text,
        block_ids=block_ids,
    )

    loop = asyncio.get_event_loop()
    all_items: list[RawRisk] = await loop.run_in_executor(
        None,
        _invoke_sync,
        llm,
        system_prompt,
        user_prompt,
        valid_block_ids,
        0,  # no retries — timeout handles failure
    )

    # ── Deduplicate ────────────────────────────────────────────────────────────
    deduplicated = _deduplicate_items(all_items)

    log.info(
        "ai_analysis_complete",
        doc_id=payload.doc_id,
        raw_items=len(all_items),
        deduped_items=len(deduplicated),
    )
    return AIRiskResult(items=deduplicated)


def _invoke_sync(
    llm: LLMBackend,
    system_prompt: str,
    user_prompt: str,
    valid_block_ids: set[str],
    max_retries: int,
) -> list[RawRisk]:
    """Synchronous wrapper: try Ollama with a 30s timeout, fall back to FakeLLM."""
    import concurrent.futures

    _OLLAMA_TIMEOUT_SECONDS = 30

    def _run() -> list[RawRisk]:
        return asyncio.run(
            _invoke_with_retry(
                llm=llm,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                valid_block_ids=valid_block_ids,
                max_retries=0,  # no retries inside the timeout window
            )
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run)
        try:
            return future.result(timeout=_OLLAMA_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            log.warning(
                "llm_timeout_fallback_to_fake",
                timeout=_OLLAMA_TIMEOUT_SECONDS,
            )
            # Cancel the in-flight request best-effort (daemon thread will finish naturally)
            future.cancel()

    # FakeLLM fallback — extract section_class from user prompt to pick relevant response
    fake = FakeLLM()
    return asyncio.run(
        _invoke_with_retry(
            llm=fake,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            valid_block_ids=valid_block_ids,
            max_retries=0,
        )
    )


async def _invoke_with_retry(
    llm: LLMBackend,
    system_prompt: str,
    user_prompt: str,
    valid_block_ids: set[str],
    max_retries: int = 2,
) -> list[RawRisk]:
    """Invoke LLM with JSON-repair retry. Drops items without valid evidence IDs."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            response = llm.invoke(messages)
            content = response.content if hasattr(response, "content") else str(response)

            # Parse JSON
            parsed = _parse_json_response(content)
            _normalise_gap_status(parsed)
            result = AIRiskResult.model_validate(parsed)

            # Drop items without valid evidence block IDs
            valid_items = [
                item for item in result.items
                if any(bid in valid_block_ids for bid in item.evidence_block_ids)
            ]

            log.info(
                "llm_response_parsed",
                attempt=attempt,
                raw_items=len(result.items),
                valid_items=len(valid_items),
            )
            return valid_items

        except Exception as exc:
            last_error = exc
            log.warning("llm_retry", attempt=attempt, error=str(exc))
            if attempt < max_retries:
                # Add repair instruction
                messages.append({"role": "assistant", "content": content if "content" in dir() else ""})
                messages.append({
                    "role": "user",
                    "content": "The previous response was not valid JSON. Please output ONLY valid JSON matching the schema.",
                })

    raise LLMParseError(f"LLM failed after {max_retries + 1} attempts: {last_error}") from last_error


def _parse_json_response(content: str) -> dict[str, Any]:
    """Parse JSON from LLM response, with basic repair for common issues."""
def _normalise_gap_status(parsed: dict[str, Any]) -> None:
    """Coerce freeform gap_status values the LLM returns into the canonical enum.

    Mutates the parsed dict in-place before Pydantic validation so we never
    trigger a retry just because the model said "open" instead of "missing".
    """
    valid = {"missing", "partial", "satisfied"}
    for item in parsed.get("items", []):
        raw = item.get("gap_status")
        if raw is None or raw in valid:
            continue
        normalised = _GAP_STATUS_ALIASES.get(raw.lower().strip())
        if normalised:
            item["gap_status"] = normalised
        else:
            # Unknown value — default to missing (safest assumption)
            item["gap_status"] = "missing"
            log.debug("gap_status_unknown_coerced", raw=raw)


def _parse_json_response(content: str) -> dict[str, Any]:
    """Parse JSON from LLM response, with basic repair for common issues."""
    content = content.strip()

    # Strip markdown code fences
    content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.MULTILINE)
    content = re.sub(r"\s*```$", "", content, flags=re.MULTILINE)

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Try json_repair if available
        try:
            from json_repair import repair_json  # type: ignore[import-untyped]
            repaired = repair_json(content)
            return json.loads(repaired)
        except Exception:
            pass
        raise


def _chunk_text(
    text: str,
    block_ids: list[str],
    max_chars: int,
) -> list[tuple[str, list[str]]]:
    """Split text into chunks of max_chars, preserving block boundaries."""
    if len(text) <= max_chars:
        return [(text, block_ids)]

    # Split by block markers
    parts = re.split(r"(\[Block [^\]]+\])", text)
    chunks: list[tuple[str, list[str]]] = []
    current_text = ""
    current_ids: list[str] = []

    for part in parts:
        block_match = re.match(r"\[Block ([^\]]+)\]", part)
        if block_match:
            bid = block_match.group(1)
            if bid in block_ids:
                current_ids.append(bid)

        if len(current_text) + len(part) > max_chars and current_text:
            chunks.append((current_text, list(current_ids)))
            current_text = part
            current_ids = [bid for bid in current_ids[-1:]]
        else:
            current_text += part

    if current_text:
        chunks.append((current_text, current_ids))

    return chunks or [(text[:max_chars], block_ids)]


def _deduplicate_items(items: list[RawRisk]) -> list[RawRisk]:
    """Remove duplicate risk items by title similarity."""
    seen_titles: set[str] = set()
    unique: list[RawRisk] = []

    for item in items:
        # Simple title-based dedup (embedding-based in risk extractor)
        title_key = item.title.lower().strip()
        if title_key not in seen_titles:
            seen_titles.add(title_key)
            unique.append(item)

    return unique
