"""Orchestrator: runs the full TPRM pipeline end-to-end.

Public interface: run_assessment(file_path, vendor_id) -> AssessmentResult

Enforces idempotency on (vendor_id, sha256).
Emits audit events per stage.
Records per-stage timing.
"""

from __future__ import annotations

import io
import time
import uuid
from pathlib import Path
from typing import Any

from tprm.ai.analyzer import FakeLLM, LLMBackend, _build_langchain_llm, analyze
from tprm.common.audit import get_audit_log
from tprm.common.config import get_settings
from tprm.common.errors import GateViolation, SanitizationError
from tprm.common.logging import get_logger
from tprm.common.models import (
    AssessmentResult,
    ClassifiedBlock,
    DetectedPII,
    Finding,
    SanitizedBlock,
    SensitivityLevel,
)
from tprm.gate.gate import process as gate_process
from tprm.ingestion.parser import parse
from tprm.nlp.classifier import classify_doc, classify_section
from tprm.nlp.context import build_context, update_context_with_classification
from tprm.nlp.relations import build_relations, get_canonical_ids
from tprm.onetrust.mapper import map_finding_to_onetrust
from tprm.onetrust.mock import MockOneTrustClient
from tprm.pii.detector import detect
from tprm.policy.engine import PolicyEngine
from tprm.risk.categorizer import categorize
from tprm.risk.controls import map_controls
from tprm.risk.extractor import NormalisedRisk, extract
from tprm.risk.recommender import recommend
from tprm.risk.severity import score_severity
from tprm.sanitize.pipeline import sanitize_pipeline
from tprm.sanitize.vault import get_vault
from tprm.sensitivity.levels import score_block, score_document
from tprm.sensitivity.scorer import route
from tprm.workflow.state_machine import WorkflowStateMachine

log = get_logger(__name__)


def _preview_highlight_color(severity: str) -> tuple[float, float, float]:
    """Return a visible highlight color based on finding criticality."""
    return {
        "Critical": (0.95, 0.25, 0.25),
        "High": (1.0, 0.55, 0.1),
        "Medium": (1.0, 0.85, 0.2),
        "Low": (0.35, 0.8, 0.45),
    }.get(severity, (1.0, 0.85, 0.2))


def _build_pdf_preview(
    file_path: Path,
    blocks: list[Any],
    entities: list[Any],
    findings: list[Finding],
) -> bytes | None:
    """Create a PDF preview with severity-colored highlights."""
    try:
        import fitz

        severity_by_block: dict[str, str] = {}
        for finding in findings:
            for block_id in finding.evidence_block_ids:
                current = severity_by_block.get(block_id)
                priorities = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
                if current is None or priorities.get(finding.severity, 0) > priorities.get(current, 0):
                    severity_by_block[block_id] = finding.severity

        preview = fitz.open(stream=file_path.read_bytes(), filetype="pdf")
        for entity in entities:
            block = next((b for b in blocks if b.id == entity.block_id), None)
            if not block or block.page < 0 or block.page >= len(preview):
                continue
            page = preview[block.page]
            for rect in page.search_for(entity.text):
                color = _preview_highlight_color(
                    severity_by_block.get(entity.block_id, "Medium")
                )
                highlight = page.add_highlight_annot(rect)
                highlight.set_colors(stroke=color)
                highlight.update()
                overlay = page.add_rect_annot(rect)
                overlay.set_colors(stroke=color, fill=color)
                overlay.set_opacity(0.28)
                overlay.update()
        output = io.BytesIO()
        preview.save(output)
        preview.close()
        return output.getvalue()
    except (OSError, ValueError, RuntimeError) as exc:
        log.warning("pdf_preview_generation_failed", error=str(exc))
        return None


def _build_masked_pdf_preview(
    file_path: Path,
    blocks: list[Any],
    entities: list[Any],
) -> bytes | None:
    """Create a copy with detected values replaced by safe demonstration data."""
    replacements = {
        "EMAIL_ADDRESS": "demo@example.com",
        "PHONE_NUMBER": "000-000-0000",
        "IP_ADDRESS": "192.0.2.1",
        "INTERNAL_HOSTNAME": "demo.internal",
        "API_KEY": "DEMO_API_KEY",
        "US_SSN": "000-00-0000",
        "CREDIT_CARD": "4111-1111-1111-1111",
        "IBAN_CODE": "GB00 DEMO 0000 0000",
        "EMPLOYEE_ID": "DEMO-0000",
        "PERSON": "Demo Person",
        "DATE_OF_BIRTH": "01/01/2000",
    }
    try:
        import fitz

        masked = fitz.open(stream=file_path.read_bytes(), filetype="pdf")
        changed_rects: list[tuple[int, Any]] = []
        for entity in entities:
            block = next((b for b in blocks if b.id == entity.block_id), None)
            if not block or block.page < 0 or block.page >= len(masked):
                continue
            page = masked[block.page]
            replacement = replacements.get(entity.entity_type, "[DEMO DATA]")
            for rect in page.search_for(entity.text):
                changed_rects.append((block.page, rect))
                page.add_redact_annot(rect, text=replacement, fill=(1, 1, 0.75))
        for page in masked:
            page.apply_redactions()
        for page_number, rect in changed_rects:
            overlay = masked[page_number].add_rect_annot(rect)
            overlay.set_colors(stroke=(0.95, 0.65, 0.05), fill=(1.0, 0.85, 0.2))
            overlay.set_opacity(0.35)
            overlay.update()
        output = io.BytesIO()
        masked.save(output)
        masked.close()
        return output.getvalue()
    except (OSError, ValueError, RuntimeError) as exc:
        log.warning("masked_pdf_generation_failed", error=str(exc))
        return None


async def run_assessment(
    file_path: Path,
    vendor_id: str,
    display_filename: str | None = None,
    assessment_id: str | None = None,
    llm: LLMBackend | None = None,
    use_fake_llm: bool = False,
) -> AssessmentResult:
    """Run the full TPRM pipeline for a vendor document.

    Args:
        file_path: Path to the vendor document (PDF/DOCX/XLSX).
        vendor_id: The vendor being assessed.
        assessment_id: Optional pre-assigned UUID (for idempotency checks).
        llm: Optional LLM backend override.
        use_fake_llm: If True, use FakeLLM instead of real Ollama.

    Returns:
        AssessmentResult with findings, gate report, and workflow state.
    """
    if assessment_id is None:
        assessment_id = str(uuid.uuid4())

    audit = get_audit_log()
    timings: dict[str, float] = {}
    settings = get_settings()

    if use_fake_llm:
        llm = llm or FakeLLM()
    elif llm is None:
        llm = _build_langchain_llm(settings)

    log.info(
        "assessment_start",
        assessment_id=assessment_id,
        vendor_id=vendor_id,
        file=file_path.name,
        llm_backend="fake" if use_fake_llm else "ollama",
        llm_model=settings.llm_model,
    )

    # ── Stage 1: Document Ingestion ───────────────────────────────────────────
    t0 = time.time()
    doc = parse(file_path, vendor_id=vendor_id)
    timings["ingestion"] = time.time() - t0
    await audit.append("ingestion", doc.doc_id, "orchestrator", "parsed", {
        "block_count": len(doc.blocks),
        "format": doc.meta.doc_format,
    })

    # ── Stage 2: PII Detection ────────────────────────────────────────────────
    t0 = time.time()
    policy_cfg = settings.policy
    thresholds = policy_cfg.get("recognizer_thresholds", {})
    org_domains = policy_cfg.get("org", {}).get("domains", [])
    entities = detect(doc.blocks, thresholds=thresholds, org_domains=org_domains)
    timings["pii_detection"] = time.time() - t0
    entity_counts: dict[str, int] = {}
    for e in entities:
        entity_counts[e.entity_type] = entity_counts.get(e.entity_type, 0) + 1
    await audit.append("pii", doc.doc_id, "orchestrator", "detected", entity_counts)

    preview_content: bytes | None = None
    masked_preview_content: bytes | None = None

    # ── Stage 3: Local NLP ────────────────────────────────────────────────────
    t0 = time.time()
    relations = build_relations(doc.blocks, entities)
    canonical_ids = get_canonical_ids(entities)
    doc_text = " ".join(b.text[:200] for b in doc.blocks[:10])
    doc_classification = classify_doc(doc_text)
    timings["nlp"] = time.time() - t0
    await audit.append("nlp", doc.doc_id, "orchestrator", "classified", {
        "doc_type": doc_classification.label,
        "confidence": round(doc_classification.confidence, 2),
    })

    # ── Stage 4 & 5: Policy Engine + Sensitivity ──────────────────────────────
    t0 = time.time()
    policy_engine = PolicyEngine()
    classified_blocks: list[ClassifiedBlock] = []

    entities_by_block: dict[str, list[Any]] = {}
    for entity in entities:
        entities_by_block.setdefault(entity.block_id, []).append(entity)

    for block in doc.blocks:
        block_entities = entities_by_block.get(block.id, [])
        ctx = build_context(block, block_entities, doc)
        section_class = classify_section(block.text)
        ctx = update_context_with_classification(
            ctx,
            doc_type=doc_classification.label,
            doc_type_confidence=doc_classification.confidence,
            section_class=section_class.label,
            section_class_confidence=section_class.confidence,
        )
        ctx = ctx.model_copy(update={
            "relations": relations,
            "entity_canonical_ids": canonical_ids,
        })

        decisions = [
            policy_engine.decide(entity, ctx, block)
            for entity in block_entities
        ]

        cb = ClassifiedBlock(block=block, entities=block_entities, ctx=ctx, decisions=decisions)
        cb = score_block(cb)
        classified_blocks.append(cb)

    doc_sensitivity = score_document(classified_blocks)
    timings["policy_sensitivity"] = time.time() - t0
    await audit.append("policy", doc.doc_id, "orchestrator", "classified", {
        "doc_sensitivity": doc_sensitivity.name,
        "total_blocks": len(classified_blocks),
    })

    # ── Stage 6: Sanitization ─────────────────────────────────────────────────
    t0 = time.time()
    sanitized_blocks = sanitize_pipeline(classified_blocks, assessment_id, vendor_id)
    timings["sanitization"] = time.time() - t0
    await audit.append("sanitize", doc.doc_id, "orchestrator", "sanitized", {
        "sanitized_blocks": sum(1 for b in sanitized_blocks if b.applied),
    })

    # ── Stage 7: Security Gate ────────────────────────────────────────────────
    t0 = time.time()
    vault = get_vault()
    raw_values = vault.lookup_raw_values(assessment_id)

    try:
        gate_payload = gate_process(
            blocks=sanitized_blocks,
            doc_id=doc.doc_id,
            vendor_id=vendor_id,
            assessment_id=assessment_id,
            doc_type=doc_classification.label,
            raw_values_for_check=raw_values,
        )
    except GateViolation:
        await audit.append("gate", doc.doc_id, "orchestrator", "quarantine", {})
        raise
    timings["gate"] = time.time() - t0

    # ── Stage 8: AI Risk Analysis ─────────────────────────────────────────────
    t0 = time.time()
    ai_result = await analyze(gate_payload, llm=llm)
    timings["ai_analysis"] = time.time() - t0
    await audit.append("ai", doc.doc_id, "orchestrator", "analyzed", {
        "risk_items": len(ai_result.items),
    })

    # ── Stage 9: Risk Engine ──────────────────────────────────────────────────
    t0 = time.time()
    normalised_risks = extract(ai_result, sanitized_blocks)
    findings: list[Finding] = []

    # Build lookup: block_id -> (section_path, section_class, entity_types_found)
    block_index: dict[str, SanitizedBlock] = {b.block_id: b for b in sanitized_blocks}
    source_block_index = {b.id: b for b in doc.blocks}
    source_block_position = {b.id: i for i, b in enumerate(doc.blocks)}
    # Map block_id -> list of entity types that were actually detected there
    block_entity_types: dict[str, list[str]] = {}
    for cb in classified_blocks:
        if cb.entities:
            block_entity_types[cb.block.id] = list({e.entity_type for e in cb.entities})

    for risk in normalised_risks:
        category = categorize(risk)

        # Find the best evidence block — the one with the most entity types detected.
        # Also search any block in the same section_class if direct evidence blocks
        # don't carry entity types (common when FakeLLM returns generic block IDs).
        best_block: SanitizedBlock | None = None
        best_entity_types: list[str] = []
        for bid in risk.evidence_block_ids:
            sb = block_index.get(bid)
            if sb:
                etypes = block_entity_types.get(bid, [])
                if len(etypes) > len(best_entity_types):
                    best_block = sb
                    best_entity_types = etypes
                elif best_block is None:
                    best_block = sb

        # Fallback 1: collect entity types from classified blocks in the same section_class
        if not best_entity_types and best_block:
            same_class = best_block.section_class
            for cb in classified_blocks:
                if cb.ctx and cb.ctx.section_class == same_class and cb.entities:
                    for e in cb.entities:
                        if e.entity_type not in best_entity_types:
                            best_entity_types.append(e.entity_type)

        # Do not borrow entity types from unrelated sections. A finding must
        # only display sensitive data that belongs to its evidence section.
        evidence_block_ids = [
            bid for bid in risk.evidence_block_ids
            if bid in block_index and bid in source_block_index
        ]
        if best_block:
            same_section_entity_ids = [
                cb.block.id
                for cb in classified_blocks
                if cb.entities
                and cb.ctx
                and cb.ctx.section_class == best_block.section_class
            ]
            for bid in same_section_entity_ids:
                if bid not in evidence_block_ids:
                    evidence_block_ids.append(bid)
        evidence_block_ids.sort(
            key=lambda bid: (
                source_block_index[bid].page,
                source_block_position[bid],
            )
        )

        section_class = best_block.section_class if best_block else "unknown"
        section_path  = best_block.section_path  if best_block else []

        controls = map_controls(risk, section_class, category)
        gap_status = controls[0].gap_status if controls else "missing"
        severity = score_severity(
            risk,
            category,
            gap_status=gap_status,
            vendor_criticality=doc.meta.vendor_criticality,
        )

        # Generate a section-aware, explicit description
        explicit_desc, section_label_str = _build_explicit_description(
            risk_title=risk.title,
            section_path=section_path,
            section_class=section_class,
            entity_types=best_entity_types,
            category=category,
            original_description=risk.description,
        )

        finding = Finding(
            assessment_id=assessment_id,
            vendor_id=vendor_id,
            risk_category=category,
            severity=severity.label,
            score=severity.score,
            score_factors=severity.factors,
            controls=controls,
            evidence_block_ids=evidence_block_ids,
            title=risk.title,
            description=explicit_desc,
            section_label=section_label_str,
            entity_types_found=best_entity_types,
            exposure_count=sum(
                len(entities_by_block.get(bid, []))
                for bid in evidence_block_ids
            ),
            evidence_passages=[
                {
                    "block_id": bid,
                    "page": source_block_index[bid].page,
                    "section_label": " > ".join(source_block_index[bid].section_path),
                    "text": block_index[bid].text_sanitized,
                    "entity_types": block_entity_types.get(bid, []),
                    "detected_entities": [
                        {
                            "entity_type": entity.entity_type,
                            "value": entity.text,
                        }
                        for entity in entities_by_block.get(bid, [])
                    ],
                }
                for bid in evidence_block_ids
                if bid in block_index and bid in source_block_index
            ],
        )
        finding.recommendation = recommend(finding)
        findings.append(finding)

    timings["risk_engine"] = time.time() - t0
    await audit.append("risk", doc.doc_id, "orchestrator", "findings_generated", {
        "finding_count": len(findings),
    })

    if doc.meta.doc_format == "pdf":
        preview_content = _build_pdf_preview(file_path, doc.blocks, entities, findings)
        masked_preview_content = _build_masked_pdf_preview(file_path, doc.blocks, entities)

    # ── Stage 10: Workflow ────────────────────────────────────────────────────
    state_machine = WorkflowStateMachine()
    for finding in findings:
        from tprm.workflow.escalation import check_escalation
        check_escalation(finding, state_machine)

    workflow_status = "Draft"
    if findings:
        workflow_status = state_machine.get_status(findings[0].id)

    # ── Stage 11: OneTrust outbox ─────────────────────────────────────────────
    ot_client = MockOneTrustClient()
    ot_vendor_id = await ot_client.upsert_vendor(vendor_id, {"name": vendor_id})
    ot_assessment_id = await ot_client.create_assessment(ot_vendor_id, {
        "externalId": assessment_id,
        "documentFormat": doc.meta.doc_format,
    })
    ot_findings = [map_finding_to_onetrust(f) for f in findings]
    if ot_findings:
        await ot_client.push_findings(ot_assessment_id, ot_findings)
    await ot_client.update_status(ot_assessment_id, workflow_status)

    result = AssessmentResult(
        assessment_id=assessment_id,
        vendor_id=vendor_id,
        doc_id=doc.doc_id,
        filename=display_filename or file_path.name,
        document_sensitivity=doc_sensitivity,
        gate_report=gate_payload.gate_report,
        findings=findings,
        pii_exposure_count=len(entities),
        preview_content=preview_content,
        masked_preview_content=masked_preview_content,
        workflow_status=workflow_status,
        stage_timings=timings,
    )

    log.info(
        "assessment_complete",
        assessment_id=assessment_id,
        vendor_id=vendor_id,
        sensitivity=doc_sensitivity.name,
        findings=len(findings),
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Section-aware finding description builder
# ─────────────────────────────────────────────────────────────────────────────

# Maps entity type → plain English label for what was found
_ENTITY_LABELS: dict[str, str] = {
    "EMAIL_ADDRESS":    "an email address",
    "PHONE_NUMBER":     "a phone number",
    "PERSON":           "a person's name",
    "US_SSN":           "a Social Security Number (SSN)",
    "CREDIT_CARD":      "a payment card number",
    "IBAN_CODE":        "a bank account number (IBAN)",
    "BANK_ACCOUNT":     "a bank account number",
    "API_KEY":          "an API key or secret credential",
    "PEM_PRIVATE_KEY":  "a private cryptographic key",
    "CREDENTIAL_URL":   "a URL with embedded credentials",
    "IP_ADDRESS":       "an internal IP address",
    "INTERNAL_HOSTNAME":"an internal server hostname",
    "MAC_ADDRESS":      "a network hardware address (MAC)",
    "EMPLOYEE_ID":      "an employee ID",
    "CONTRACT_NUMBER":  "a contract or purchase order number",
    "DATE_OF_BIRTH":    "a date of birth",
    "ORG":              "an organisation name",
    "LOCATION":         "a location or address",
}

# Why each entity type shouldn't appear in a shared vendor document
_ENTITY_RISK_REASON: dict[str, str] = {
    "EMAIL_ADDRESS":    "Email addresses expose personnel contact details that could be used for targeted phishing or social engineering attacks against your organisation.",
    "PHONE_NUMBER":     "Direct phone numbers for staff expose them to social engineering and should not appear in documents shared outside the organisation.",
    "PERSON":           "Full names of employees can be used to map internal org structure and target individuals for impersonation or social engineering.",
    "US_SSN":           "Social Security Numbers are highly sensitive government identifiers. Their presence in a shared document is a serious data protection violation.",
    "CREDIT_CARD":      "Payment card numbers must never appear in documents — this is a direct PCI DSS violation and creates significant financial fraud risk.",
    "IBAN_CODE":        "Bank account numbers in shared documents create fraud risk and may breach GDPR and financial data regulations.",
    "BANK_ACCOUNT":     "Bank account details in shared documents create fraud risk and may breach financial data regulations.",
    "API_KEY":          "API keys and secrets provide direct programmatic access to systems or cloud services. If exposed, an attacker can immediately use them to access your infrastructure.",
    "PEM_PRIVATE_KEY":  "Private cryptographic keys must never leave their secure storage. Exposure allows impersonation of the system and decryption of protected communications.",
    "CREDENTIAL_URL":   "A URL containing a username and password exposes live credentials. Anyone with this document can authenticate to the referenced system.",
    "IP_ADDRESS":       "Internal IP addresses reveal your network topology. Attackers use this information to plan lateral movement inside your network.",
    "INTERNAL_HOSTNAME":"Internal server names reveal your infrastructure layout and make it easier for attackers to target specific systems.",
    "MAC_ADDRESS":      "Hardware MAC addresses can assist in network reconnaissance and in bypassing MAC-based access controls.",
    "EMPLOYEE_ID":      "Employee IDs can be used to impersonate staff in social engineering attacks or to probe HR and payroll systems.",
    "CONTRACT_NUMBER":  "Contract and purchase order numbers expose commercial relationships and can be used to impersonate vendors in fraud attempts.",
    "DATE_OF_BIRTH":    "Dates of birth are personal data under GDPR/CCPA. Their presence in shared documents creates a compliance obligation and exposure risk.",
    "ORG":              "Organisation names in sensitive context can reveal undisclosed commercial relationships.",
}

# Maps section_class → human-readable section label
_SECTION_LABELS: dict[str, str] = {
    "access_control":         "Access Controls",
    "encryption":             "Encryption & Key Management",
    "incident_response":      "Incident Response",
    "bc_dr":                  "Business Continuity / DR",
    "subprocessors":          "Subprocessors",
    "data_retention":         "Data Retention",
    "audit_scope":            "Audit Scope",
    "exceptions_qualifications": "Audit Exceptions",
    "unknown":                "General Document Body",
    "other":                  "General Document Body",
}

# Maps risk category → what problem class this represents
_CATEGORY_PROBLEM: dict[str, str] = {
    "ACCESS_MGMT":    "an access management issue",
    "ENCRYPTION":     "an encryption gap",
    "INCIDENT_RESPONSE": "an incident response gap",
    "PRIVACY_DATA":   "a personal data exposure",
    "COMPLIANCE_AUDIT": "a compliance finding",
    "SUBPROCESSOR":   "a third-party risk issue",
    "INFO_SEC":       "a security control gap",
    "BC_DR":          "a business continuity gap",
    "AI_MODEL_RISK":  "an AI governance gap",
    "FINANCIAL":      "a financial risk",
    "OPERATIONAL_RESILIENCE": "an operational resilience gap",
}


def _build_explicit_description(
    risk_title: str,
    section_path: list[str],
    section_class: str,
    entity_types: list[str],
    category: str,
    original_description: str,
) -> tuple[str, str]:
    """Build a plain-English description that tells the user exactly:
    1. Which section of the document the issue was found in
    2. What specific sensitive data was found there
    3. Why it shouldn't be in a shared vendor document
    4. What the user should ask the vendor to do

    Returns:
        (description, section_label) — both strings.
    """
    # ── Where was it found? ───────────────────────────────────────────────────
    section_label = _SECTION_LABELS.get(section_class, "the document")

    # Use the deepest heading from section_path if available (most specific)
    if section_path:
        import re as _re
        for raw_heading in reversed(section_path):  # deepest first
            # Clean: strip newlines/tabs, collapse whitespace
            clean = _re.sub(r"\s+", " ", raw_heading).strip()
            # Strip leading numbering like "4.1 " or "4. "
            clean = _re.sub(r"^\d+(\.\d+)*\.?\s*", "", clean).strip()
            # Skip very short or numeric-only values
            if len(clean) < 4 or clean.isdigit():
                continue
            # Skip table-header-like rows (short words, none are section keywords)
            words = clean.split()
            section_keywords = {"access","encrypt","incident","data","scope","security",
                                 "vendor","person","compliance","personnel","protection",
                                 "management","response","subprocessor","retention"}
            if (len(words) <= 3
                    and all(len(w) <= 10 for w in words)
                    and not any(kw in clean.lower() for kw in section_keywords)):
                continue
            section_label = f'"{clean}"'
            break

    location = f"In the {section_label} section of this document"

    # ── What was found? ───────────────────────────────────────────────────────
    # Pick the most sensitive entity types to highlight (prioritise by risk)
    priority_order = [
        "API_KEY", "PEM_PRIVATE_KEY", "CREDENTIAL_URL", "US_SSN", "CREDIT_CARD",
        "IBAN_CODE", "BANK_ACCOUNT", "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON",
        "IP_ADDRESS", "INTERNAL_HOSTNAME", "EMPLOYEE_ID", "CONTRACT_NUMBER",
        "DATE_OF_BIRTH", "MAC_ADDRESS", "ORG", "LOCATION",
    ]
    sorted_types = sorted(
        entity_types,
        key=lambda t: priority_order.index(t) if t in priority_order else 99
    )

    if sorted_types:
        top_type = sorted_types[0]
        found_label = _ENTITY_LABELS.get(top_type, "sensitive information")

        if len(sorted_types) > 1:
            other_labels = [
                _ENTITY_LABELS.get(t, t.lower().replace("_", " "))
                for t in sorted_types[1:3]  # max 2 extras
            ]
            found_str = f"{found_label} (along with {' and '.join(other_labels)})"
        else:
            found_str = found_label

        risk_reason = _ENTITY_RISK_REASON.get(
            top_type,
            "This type of sensitive data should not appear in a shared vendor document."
        )
    else:
        # Fallback: use category-level description
        problem = _CATEGORY_PROBLEM.get(category, "a security concern")
        found_str = problem
        risk_reason = original_description

    # ── Build the full description ─────────────────────────────────────────────
    what_to_do = _get_action_for_entity(sorted_types[0] if sorted_types else "", category)

    description = (
        f"{location}, we found {found_str}. "
        f"{risk_reason} "
        f"{what_to_do}"
    )

    return description, section_label


def _get_action_for_entity(entity_type: str, category: str) -> str:
    """Return a concrete action the user should take."""
    actions: dict[str, str] = {
        "API_KEY":
            "Ask the vendor to immediately rotate this credential and confirm it has been "
            "removed from all shared documents and version control history.",
        "PEM_PRIVATE_KEY":
            "Ask the vendor to revoke and reissue the affected certificate immediately, "
            "and confirm how private keys are stored (should be in a hardware security module or secrets manager, never in documents).",
        "CREDENTIAL_URL":
            "Ask the vendor to rotate the exposed credentials immediately and confirm "
            "that connection strings are stored in a secrets manager, not in documents.",
        "US_SSN":
            "Ask the vendor to remove this document from circulation, confirm who has accessed it, "
            "and provide a redacted version. Report the exposure to your DPO.",
        "CREDIT_CARD":
            "Escalate immediately — this is a potential PCI DSS breach. Ask the vendor to "
            "confirm whether the card number is live, notify the card scheme if so, and provide a forensic summary.",
        "IBAN_CODE":
            "Ask the vendor to remove this document from circulation and confirm the account "
            "details have not been accessed or misused. Notify your DPO.",
        "BANK_ACCOUNT":
            "Ask the vendor to remove this document from circulation and confirm the account "
            "details have not been accessed or misused.",
        "EMAIL_ADDRESS":
            "Ask the vendor to provide a redacted version of this document with staff email "
            "addresses removed. Use role-based addresses (security@vendor.com) instead of personal ones.",
        "PHONE_NUMBER":
            "Ask the vendor to replace direct staff phone numbers with department or role-based "
            "contact numbers in future versions of this document.",
        "PERSON":
            "Ask the vendor to use job titles rather than full names in shared documents, "
            "or to provide a redacted version.",
        "IP_ADDRESS":
            "Ask the vendor to remove internal IP addresses from this document. "
            "References to internal infrastructure should use logical names (e.g. 'primary database') not addresses.",
        "INTERNAL_HOSTNAME":
            "Ask the vendor to remove or mask internal hostnames from shared documents. "
            "Infrastructure details should not be disclosed in third-party assessments.",
        "EMPLOYEE_ID":
            "Ask the vendor to remove employee IDs from shared documents and use job titles or roles instead.",
        "CONTRACT_NUMBER":
            "Ask the vendor to confirm whether contract numbers in shared documents are intentional "
            "disclosures, and redact them if not.",
        "DATE_OF_BIRTH":
            "Ask the vendor to remove dates of birth from this document. This is personal data "
            "under GDPR/CCPA and should not appear in shared security reports.",
    }

    default_by_category: dict[str, str] = {
        "ACCESS_MGMT":
            "Ask the vendor to review and remediate access controls in this area, "
            "and provide evidence of the fix before the next review cycle.",
        "ENCRYPTION":
            "Ask the vendor to confirm their encryption standards meet your requirements "
            "and provide updated documentation showing the gap has been addressed.",
        "INCIDENT_RESPONSE":
            "Ask the vendor to update their incident response documentation and resubmit "
            "the corrected version for your records.",
        "PRIVACY_DATA":
            "Notify your Data Protection Officer and ask the vendor to provide a redacted "
            "document and a summary of who has received the original.",
        "SUBPROCESSOR":
            "Ask the vendor to provide a current list of subprocessors with signed DPAs "
            "and confirm no personal data is shared with undisclosed parties.",
    }

    return (
        actions.get(entity_type)
        or default_by_category.get(category)
        or "Ask the vendor to review and remediate this issue before the next assessment cycle."
    )
