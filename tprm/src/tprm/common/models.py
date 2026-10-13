"""Core data contracts for the TPRM pipeline.

All stages communicate exclusively through these models.
No stage may define its own cross-stage data types.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Sensitivity Level
# ─────────────────────────────────────────────────────────────────────────────


class SensitivityLevel(IntEnum):
    """Document / block / entity sensitivity classification.

    Integer ordering is intentional: RESTRICTED > CONFIDENTIAL > INTERNAL > PUBLIC.
    Comparisons like ``level >= SensitivityLevel.CONFIDENTIAL`` work correctly.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def from_str(cls, value: str) -> "SensitivityLevel":
        """Parse from uppercase string, e.g. ``'CONFIDENTIAL'``."""
        return cls[value.upper()]


# ─────────────────────────────────────────────────────────────────────────────
# Ingestion models
# ─────────────────────────────────────────────────────────────────────────────


class BoundingBox(BaseModel):
    """Page-relative bounding box (PDF coordinates, points from top-left)."""

    x0: float
    y0: float
    x1: float
    y1: float


class Block(BaseModel):
    """A unit of extracted text from a document.

    ``section_path`` records the heading hierarchy down to this block,
    e.g. ``["2. Security Controls", "2.1 Access Management"]``.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    doc_id: str
    page: int
    section_path: list[str] = Field(default_factory=list)
    text: str
    bbox: BoundingBox | None = None
    source: Literal["native", "ocr", "table_cell"] = "native"
    ocr_conf: float | None = None  # mean word confidence for OCR blocks (0–100)

    def __repr__(self) -> str:  # noqa: D105
        # Never include .text to avoid PII leaking into logs via repr
        return f"Block(id={self.id!r}, doc_id={self.doc_id!r}, page={self.page}, source={self.source!r})"


class DocumentMeta(BaseModel):
    """Non-content metadata for a parsed document."""

    file_size_bytes: int
    page_count: int
    doc_format: Literal["pdf", "docx", "xlsx"]
    has_ocr_pages: bool = False
    has_hidden_sheets: bool = False  # XLSX only
    vendor_criticality: float = 1.0  # 0.8–1.5, set at assessment intake


class Document(BaseModel):
    """Parsed vendor document ready for PII detection."""

    doc_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor_id: str
    filename: str
    sha256: str
    blocks: list[Block] = Field(default_factory=list)
    meta: DocumentMeta

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):  # noqa: SIM910
            raise ValueError("sha256 must be a 64-character lowercase hex string")
        return v

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"Document(doc_id={self.doc_id!r}, vendor_id={self.vendor_id!r}, "
            f"filename={self.filename!r}, blocks={len(self.blocks)})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PII Detection
# ─────────────────────────────────────────────────────────────────────────────


class PIIEntity(BaseModel):
    """A detected PII span within a block."""

    block_id: str
    start: int
    end: int
    entity_type: str
    text: str  # raw value — NEVER log this field
    score: float  # Presidio confidence 0.0–1.0
    recognizer: str

    @model_validator(mode="after")
    def validate_span(self) -> "PIIEntity":
        if self.start >= self.end:
            raise ValueError(f"start ({self.start}) must be < end ({self.end})")
        return self

    def __repr__(self) -> str:  # noqa: D105
        # Deliberately omit .text
        return (
            f"PIIEntity(block_id={self.block_id!r}, entity_type={self.entity_type!r}, "
            f"start={self.start}, end={self.end}, score={self.score:.2f})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# NLP Context
# ─────────────────────────────────────────────────────────────────────────────


class Relation(BaseModel):
    """A directed relationship between two entities."""

    source_entity_id: str
    target_entity_id: str
    relation_type: str  # e.g. "person_role", "person_email", "org_contract", "system_ip"
    block_ids: list[str] = Field(default_factory=list)


class NLPContext(BaseModel):
    """NLP-derived context features for entities within a block."""

    block_id: str
    doc_type: str  # e.g. "soc2_report", "dpa", "unknown"
    doc_type_confidence: float = 0.0
    section_class: str  # e.g. "access_control", "encryption", "unknown"
    section_class_confidence: float = 0.0
    relations: list[Relation] = Field(default_factory=list)
    neighbors_ctx: str = ""  # surrounding text window (sanitized for logging)
    is_example: bool = False  # block contains example/sample markers
    is_negated: bool = False  # entity appears in negation context
    section_sensitivity_floor: SensitivityLevel = SensitivityLevel.INTERNAL
    entity_canonical_ids: dict[str, str] = Field(default_factory=dict)  # entity_id -> canonical_id


# ─────────────────────────────────────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────────────────────────────────────


class PolicyDecision(BaseModel):
    """A single policy decision for one detected entity."""

    entity_ref: str  # PIIEntity.block_id + ":" + str(start) + "-" + str(end)
    entity_type: str
    level: SensitivityLevel
    action: Literal["keep", "redact", "tokenize", "generalize"]
    rule_id: str
    rationale: str


class ClassifiedBlock(BaseModel):
    """A block enriched with PII entities, NLP context, and policy decisions."""

    block: Block
    entities: list[PIIEntity] = Field(default_factory=list)
    ctx: NLPContext | None = None
    decisions: list[PolicyDecision] = Field(default_factory=list)
    block_level: SensitivityLevel = SensitivityLevel.PUBLIC

    @model_validator(mode="after")
    def block_level_monotonic(self) -> "ClassifiedBlock":
        """Block level is the max of all decisions, never less than section floor."""
        if self.decisions:
            max_decision_level = max(d.level for d in self.decisions)
            floor = self.ctx.section_sensitivity_floor if self.ctx else SensitivityLevel.INTERNAL
            self.block_level = max(max_decision_level, floor, self.block_level)
        return self


# ─────────────────────────────────────────────────────────────────────────────
# Sanitization
# ─────────────────────────────────────────────────────────────────────────────


class Transform(BaseModel):
    """Record of a single sanitization transform applied to a span."""

    entity_type: str
    action: Literal["keep", "redact", "tokenize", "generalize"]
    start: int
    end: int
    placeholder: str  # the replacement string (never the original)


class SanitizedBlock(BaseModel):
    """A block after sanitization — contains no raw PII values."""

    block_id: str
    doc_id: str
    section_path: list[str]
    section_class: str
    text_sanitized: str  # sanitized text; may contain placeholders/tokens
    applied: list[Transform] = Field(default_factory=list)

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"SanitizedBlock(block_id={self.block_id!r}, "
            f"section_class={self.section_class!r}, transforms={len(self.applied)})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Security Gate
# ─────────────────────────────────────────────────────────────────────────────


class GateReport(BaseModel):
    """Summary of gate processing for a document."""

    doc_id: str
    total_blocks: int
    safe_path_blocks: int
    sensitive_path_blocks: int
    transforms_by_type: dict[str, int] = Field(default_factory=dict)
    rescan_hits: int = 0
    rerouted_blocks: int = 0
    quarantined: bool = False
    passed: bool = False


class GateApprovedPayload(BaseModel):
    """Signed payload that has cleared the Security Gate.

    Only this type is accepted by the AI analysis stage.
    The ``signature`` field is HMAC-SHA256 over the canonical JSON of this
    model (excluding the signature field itself).
    """

    doc_id: str
    vendor_id: str
    doc_type: str
    blocks: list[SanitizedBlock]
    gate_report: GateReport
    signature: str  # HMAC-SHA256 hex digest

    def canonical_bytes(self) -> bytes:
        """Return deterministic bytes for HMAC computation (excludes signature)."""
        import json

        data = self.model_dump(exclude={"signature"})
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"GateApprovedPayload(doc_id={self.doc_id!r}, vendor_id={self.vendor_id!r}, "
            f"blocks={len(self.blocks)}, passed={self.gate_report.passed})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# AI Risk Analysis
# ─────────────────────────────────────────────────────────────────────────────


class RawRisk(BaseModel):
    """A single risk item as returned by the LLM."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    evidence_block_ids: list[str]
    claimed_category: str
    confidence: float = Field(ge=0.0, le=1.0)
    # LLM-assessed scoring signals — when present these replace YAML taxonomy defaults
    likelihood: float | None = Field(default=None, ge=0.0, le=1.0)
    impact: float | None = Field(default=None, ge=0.0, le=1.0)
    gap_status: Literal["missing", "partial", "satisfied"] | None = None


class AIRiskResult(BaseModel):
    """Aggregated output from AI risk analysis."""

    items: list[RawRisk] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Risk Engine
# ─────────────────────────────────────────────────────────────────────────────


class ControlRef(BaseModel):
    """A reference to a specific control in a compliance framework."""

    control_id: str  # internal CTL-xxx id
    framework: Literal["ISO27001", "SOC2", "NIST_CSF"]
    ref: str  # framework-specific reference, e.g. "A.5.15"
    name: str
    gap_status: Literal["missing", "partial", "satisfied"] = "missing"


class Finding(BaseModel):
    """A normalised, scored risk finding ready for workflow processing."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str
    vendor_id: str
    risk_category: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    score: int = Field(ge=0, le=100)
    score_factors: dict[str, float] = Field(default_factory=dict)
    controls: list[ControlRef] = Field(default_factory=list)
    recommendation: str = ""
    evidence_block_ids: list[str] = Field(default_factory=list)
    status: str = "Draft"
    creator_id: str = "system"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    title: str = ""
    description: str = ""
    section_label: str = ""    # e.g. '"Access Management"' or 'Encryption & Key Management section'
    entity_types_found: list[str] = Field(default_factory=list)  # e.g. ["API_KEY", "EMAIL_ADDRESS"]
    exposure_count: int = 0
    evidence_passages: list["EvidencePassage"] = Field(default_factory=list)

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"Finding(id={self.id!r}, severity={self.severity!r}, "
            f"category={self.risk_category!r}, score={self.score})"
        )


class EvidencePassage(BaseModel):
    """Document passage and the PII spans detected within it."""

    block_id: str
    page: int
    section_label: str = ""
    text: str
    entity_types: list[str] = Field(default_factory=list)
    detected_entities: list["DetectedPII"] = Field(default_factory=list)


class DetectedPII(BaseModel):
    """A detected PII value shown in the authenticated assessment UI."""

    entity_type: str
    value: str


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    """An immutable, hash-chained audit log entry.

    ``counts`` stores entity type counts (e.g. ``{"EMAIL": 3}``), never content.
    ``prev_hash`` and ``hash`` implement the hash chain.
    """

    ts: datetime = Field(default_factory=datetime.utcnow)
    stage: str
    doc_id: str
    actor: str
    action: str
    counts: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 over the canonical string of this event's content fields."""
        import json

        content = json.dumps(
            {
                "prev_hash": self.prev_hash,
                "ts": self.ts.isoformat(),
                "stage": self.stage,
                "doc_id": self.doc_id,
                "actor": self.actor,
                "action": self.action,
                "counts": self.counts,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"AuditEvent(stage={self.stage!r}, doc_id={self.doc_id!r}, "
            f"action={self.action!r}, ts={self.ts.isoformat()})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Assessment result (orchestrator output)
# ─────────────────────────────────────────────────────────────────────────────


class AssessmentResult(BaseModel):
    """Top-level result returned by the orchestrator after a full pipeline run."""

    assessment_id: str
    vendor_id: str
    doc_id: str
    filename: str
    document_sensitivity: SensitivityLevel
    gate_report: GateReport
    findings: list[Finding] = Field(default_factory=list)
    pii_exposure_count: int = 0
    preview_content: bytes | None = Field(default=None, exclude=True, repr=False)
    masked_preview_content: bytes | None = Field(default=None, exclude=True, repr=False)
    workflow_status: str = "Draft"
    stage_timings: dict[str, float] = Field(default_factory=dict)  # stage -> seconds
