"""REST API routes for TPRM pipeline."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from fastapi.security import APIKeyHeader

from tprm.common.audit import get_audit_log
from tprm.common.config import get_settings
from tprm.common.errors import (
    GateViolation,
    InvalidTransition,
    UnsupportedFormat,
)
from tprm.orchestrator import run_assessment
from tprm.workflow.state_machine import WorkflowStateMachine

if TYPE_CHECKING:
    from tprm.common.models import AssessmentResult

router = APIRouter()
_state_machines: dict[str, WorkflowStateMachine] = {}
_assessments: dict[str, AssessmentResult] = {}
_assessment_files: dict[str, tuple[bytes, bytes, str]] = {}
# Track gate decisions per assessment: {assessment_id: {outcome, reason, ts, ...}}
_gate_decisions: dict[str, dict[str, Any]] = {}

api_key_header = APIKeyHeader(name="X-API-Key")


def _verify_api_key(key: str = Depends(api_key_header)) -> str:
    settings = get_settings()
    if key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return key


# ── Dashboard summary ──────────────────────────────────────────────────────────

@router.get("/dashboard", response_model=dict[str, Any])
async def get_dashboard(
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Return aggregate stats for the overview dashboard."""
    total = len(_assessments)
    in_progress = sum(
        1 for r in _assessments.values()
        if r.workflow_status in ("Draft", "InReview")
    )
    high_critical = sum(
        1 for r in _assessments.values()
        for f in r.findings
        if f.severity in ("High", "Critical")
    )
    quarantined = sum(
        1 for d in _gate_decisions.values()
        if d.get("outcome") == "quarantined"
    )
    awaiting_approval = sum(
        1 for r in _assessments.values()
        if r.workflow_status in ("InReview", "RemediationRequested")
    )

    recent = sorted(
        _assessments.values(),
        key=lambda r: r.findings[0].created_at if r.findings else datetime.min,
        reverse=True,
    )[:10]

    audit = get_audit_log()
    all_events = audit.all_events()
    recent_events = sorted(all_events, key=lambda e: e.ts, reverse=True)[:20]

    return {
        "total_assessments": total,
        "in_progress": in_progress,
        "high_critical_findings": high_critical,
        "quarantined": quarantined,
        "awaiting_approval": awaiting_approval,
        "recent_assessments": [
            {
                "assessment_id": r.assessment_id,
                "vendor_id": r.vendor_id,
                "filename": r.filename,
                "sensitivity": r.document_sensitivity.name,
                "workflow_status": r.workflow_status,
                "finding_count": len(r.findings),
                "high_critical": sum(
                    1 for f in r.findings if f.severity in ("High", "Critical")
                ),
                "created_at": r.findings[0].created_at.isoformat()
                if r.findings else datetime.utcnow().isoformat(),
            }
            for r in recent
        ],
        "recent_audit_events": [
            {
                "ts": e.ts.isoformat(),
                "stage": e.stage,
                "doc_id": e.doc_id,
                "actor": e.actor,
                "action": e.action,
                "counts": e.counts,
            }
            for e in recent_events
        ],
        "services": {
            "api": "ok",
            "gate": "ok",
            "ollama": {
                "configured": bool(get_settings().ollama_url),
                "model": get_settings().llm_model,
            },
            "onetrust": "mock",
            "database": "in-memory",
        },
    }


# ── Assessments list ───────────────────────────────────────────────────────────

@router.get("/assessments", response_model=list[dict[str, Any]])
async def list_assessments(
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """List all assessments."""
    results = sorted(
        _assessments.values(),
        key=lambda r: r.findings[0].created_at if r.findings else datetime.min,
        reverse=True,
    )
    return [
        {
            "assessment_id": r.assessment_id,
            "vendor_id": r.vendor_id,
            "filename": r.filename,
            "sensitivity": r.document_sensitivity.name,
            "workflow_status": r.workflow_status,
            "finding_count": len(r.findings),
            "high_critical": sum(
                1 for f in r.findings if f.severity in ("High", "Critical")
            ),
            "created_at": r.findings[0].created_at.isoformat()
            if r.findings else datetime.utcnow().isoformat(),
            "gate_passed": r.gate_report.passed,
            "stage_timings": r.stage_timings,
        }
        for r in results
    ]


@router.post("/assessments", response_model=dict[str, Any])
async def create_assessment(
    file: UploadFile = File(...),  # noqa: B008
    vendor_id: str = Form("unknown vendor"),
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Upload a vendor document and start an assessment."""
    original_filename = Path(file.filename or "").name
    suffix = Path(original_filename or "uploaded-document").suffix.lower()
    if not original_filename:
        original_filename = f"uploaded-document{suffix}"
    vendor_id = vendor_id.strip() or "unknown vendor"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        result = await run_assessment(
            tmp_path,
            vendor_id=vendor_id,
            display_filename=original_filename,
        )
        _assessments[result.assessment_id] = result
        _assessment_files[result.assessment_id] = (
            result.preview_content or content,
            result.masked_preview_content or result.preview_content or content,
            suffix,
        )
        _state_machines[result.assessment_id] = WorkflowStateMachine()
        _gate_decisions[result.assessment_id] = {
            "outcome": "approved" if result.gate_report.passed else "quarantined",
            "total_blocks": result.gate_report.total_blocks,
            "safe_path_blocks": result.gate_report.safe_path_blocks,
            "sensitive_path_blocks": result.gate_report.sensitive_path_blocks,
            "rescan_hits": result.gate_report.rescan_hits,
            "rerouted_blocks": result.gate_report.rerouted_blocks,
            "ts": datetime.utcnow().isoformat(),
            "vendor_id": vendor_id,
            "doc_id": result.doc_id,
            "assessment_id": result.assessment_id,
            "filename": result.filename,
        }
        return {
            "assessment_id": result.assessment_id,
            "doc_id": result.doc_id,
            "status": result.workflow_status,
            "sensitivity": result.document_sensitivity.name,
            "finding_count": len(result.findings),
            "pii_exposure_count": result.pii_exposure_count,
        }
    except UnsupportedFormat as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except GateViolation as exc:
        raise HTTPException(status_code=422, detail=f"Gate violation: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/assessments/{assessment_id}", response_model=dict[str, Any])
async def get_assessment(
    assessment_id: str,
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Get assessment status and summary."""
    result = _assessments.get(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {
        "assessment_id": result.assessment_id,
        "vendor_id": result.vendor_id,
        "filename": result.filename,
        "sensitivity": result.document_sensitivity.name,
        "workflow_status": result.workflow_status,
        "finding_count": len(result.findings),
        "pii_exposure_count": result.pii_exposure_count,
        "stage_timings": result.stage_timings,
        "gate_report": {
            "passed": result.gate_report.passed,
            "total_blocks": result.gate_report.total_blocks,
            "safe_path_blocks": result.gate_report.safe_path_blocks,
            "sensitive_path_blocks": result.gate_report.sensitive_path_blocks,
            "rescan_hits": result.gate_report.rescan_hits,
            "rerouted_blocks": result.gate_report.rerouted_blocks,
            "quarantined": result.gate_report.quarantined,
        },
    }


@router.get("/assessments/{assessment_id}/findings", response_model=list[dict[str, Any]])
async def get_findings(
    assessment_id: str,
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Get findings for an assessment."""
    result = _assessments.get(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return [
        {
            "id": f.id,
            "severity": f.severity,
            "score": f.score,
            "risk_category": f.risk_category,
            "title": f.title,
            "description": f.description,
            "section_label": f.section_label,
            "entity_types_found": f.entity_types_found,
            "recommendation": f.recommendation,
            "status": f.status,
            "controls": [c.model_dump() for c in f.controls],
            "created_at": f.created_at.isoformat(),
            "vendor_id": f.vendor_id,
            "exposure_count": f.exposure_count,
            "evidence_passages": [p.model_dump() for p in f.evidence_passages],
        }
        for f in result.findings
    ]


@router.delete("/assessments/{assessment_id}", response_model=dict[str, str])
async def delete_assessment(
    assessment_id: str,
    _: str = Depends(_verify_api_key),
) -> dict[str, str]:
    """Delete an assessment and all in-memory document/analysis data."""
    if assessment_id not in _assessments:
        raise HTTPException(status_code=404, detail="Assessment not found")

    del _assessments[assessment_id]
    _assessment_files.pop(assessment_id, None)
    _state_machines.pop(assessment_id, None)
    _gate_decisions.pop(assessment_id, None)
    return {"assessment_id": assessment_id, "status": "deleted"}


@router.get("/assessments/{assessment_id}/document")
async def get_assessment_document(
    assessment_id: str,
    mode: str = "original",
    _: str = Depends(_verify_api_key),
) -> Response:
    """Return the original or masked document preview."""
    if mode not in {"original", "masked"}:
        raise HTTPException(status_code=400, detail="mode must be original or masked")
    document = _assessment_files.get(assessment_id)
    if not document:
        result = _assessments.get(assessment_id)
        if result and result.preview_content:
            document = (
                result.preview_content,
                result.masked_preview_content or result.preview_content,
                Path(result.filename).suffix.lower(),
            )
    if not document:
        raise HTTPException(status_code=404, detail="Document preview not available")
    original, masked, suffix = document
    content = masked if mode == "masked" else original
    media_type = {
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get(suffix, "application/octet-stream")
    return Response(content=content, media_type=media_type)


@router.post("/assessments/{assessment_id}/transition", response_model=dict[str, Any])
async def transition_assessment(
    assessment_id: str,
    body: dict[str, Any],
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Transition assessment workflow state."""
    sm = _state_machines.get(assessment_id)
    if not sm:
        raise HTTPException(status_code=404, detail="Assessment not found")

    to_status = body.get("to_status", "")
    actor_id = body.get("actor_id", "api")
    reason = body.get("reason", "")

    result = _assessments.get(assessment_id)
    finding_id = result.findings[0].id if result and result.findings else assessment_id

    try:
        t = sm.transition(finding_id, to_status, actor_id, reason=reason)
        # Update persisted workflow_status
        if result:
            _assessments[assessment_id] = result.model_copy(
                update={"workflow_status": to_status}
            )
        return {"finding_id": t.finding_id, "from": t.from_status, "to": t.to_status}
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


# ── Gate decisions ─────────────────────────────────────────────────────────────

@router.get("/gate/decisions", response_model=list[dict[str, Any]])
async def get_gate_decisions(
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Return all Security Gate decisions."""
    return sorted(
        _gate_decisions.values(),
        key=lambda d: d.get("ts", ""),
        reverse=True,
    )


@router.get("/gate/decisions/{assessment_id}", response_model=dict[str, Any])
async def get_gate_decision(
    assessment_id: str,
    _: str = Depends(_verify_api_key),
) -> dict[str, Any]:
    """Return the Security Gate decision for a specific assessment."""
    decision = _gate_decisions.get(assessment_id)
    if not decision:
        raise HTTPException(status_code=404, detail="Gate decision not found")
    return decision


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit", response_model=list[dict[str, Any]])
async def get_all_audit_events(
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Return all audit events across all documents, most recent first."""
    audit = get_audit_log()
    events = sorted(audit.all_events(), key=lambda e: e.ts, reverse=True)
    return [
        {
            "ts": e.ts.isoformat(),
            "stage": e.stage,
            "doc_id": e.doc_id,
            "actor": e.actor,
            "action": e.action,
            "counts": e.counts,
            "hash_prefix": e.hash[:16] + "..." if e.hash else "",
        }
        for e in events
    ]


@router.get("/audit/{doc_id}", response_model=list[dict[str, Any]])
async def get_audit_log_endpoint(
    doc_id: str,
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Get audit log entries for a document."""
    audit = get_audit_log()
    events = audit.events_for_doc(doc_id)
    return [
        {
            "ts": e.ts.isoformat(),
            "stage": e.stage,
            "action": e.action,
            "counts": e.counts,
            "hash": e.hash[:16] + "...",
        }
        for e in events
    ]


# ── Findings across all assessments ───────────────────────────────────────────

@router.get("/findings", response_model=list[dict[str, Any]])
async def list_all_findings(
    _: str = Depends(_verify_api_key),
) -> list[dict[str, Any]]:
    """Return all findings across all assessments."""
    all_findings: list[dict[str, Any]] = []
    for result in _assessments.values():
        for f in result.findings:
            all_findings.append({
                "id": f.id,
                "assessment_id": f.assessment_id,
                "vendor_id": f.vendor_id,
                "severity": f.severity,
                "score": f.score,
                "risk_category": f.risk_category,
                "title": f.title,
                "description": f.description,
                "section_label": f.section_label,
                "entity_types_found": f.entity_types_found,
                "recommendation": f.recommendation,
                "status": f.status,
                "controls": [c.model_dump() for c in f.controls],
                "created_at": f.created_at.isoformat(),
                "filename": result.filename,
            })
    all_findings.sort(key=lambda x: x.get("score", 0), reverse=True)
    return all_findings


# ── Health check ───────────────────────────────────────────────────────────────

@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness check."""
    return {"status": "ok"}
