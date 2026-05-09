"""Pydantic v2 models for the RuleIQ persistence layer (Phase 2)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

FindingType = Literal[
    "dead_rule", "bypass_candidate", "conflict", "quick_win", "fms_review"
]
Severity = Literal["high", "medium", "low"]
AuditStatus = Literal["pending", "running", "complete", "failed"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _MongoModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class Account(_MongoModel):
    account_id: str
    role_arn: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
    last_audit_at: Optional[datetime] = None


class WasteBreakdownEntry(BaseModel):
    rule_name: str
    monthly_usd: float
    reason: str


class AuditRun(_MongoModel):
    id: str = Field(alias="_id")
    account_id: str
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    region: str = "us-east-1"
    status: AuditStatus = "pending"
    failure_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    web_acl_count: int = 0
    rule_count: int = 0
    log_window_days: int = 30
    estimated_waste_usd: Optional[float] = None
    estimated_waste_breakdown: Optional[List[WasteBreakdownEntry]] = None
    fms_visibility: Optional[bool] = None
    logging_available: Optional[bool] = None
    data_source: Optional[Literal["aws", "fixture", "pending"]] = None
    seed: bool = False


class AuditCreateRequest(BaseModel):
    account_id: str = Field(min_length=12, max_length=12)
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    region: str = "us-east-1"
    log_window_days: int = 30


class Rule(_MongoModel):
    audit_run_id: str
    web_acl_name: str
    rule_name: str
    priority: int
    action: str
    statement_json: Dict[str, Any]
    hit_count: int
    last_fired: Optional[str] = None
    count_mode_hits: int = 0
    sample_uris: List[str] = Field(default_factory=list)
    fms_managed: bool = False
    override_action: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_working: Optional[bool] = None
    ai_concerns: Optional[str] = None


class Finding(_MongoModel):
    audit_run_id: str
    type: FindingType
    severity: Severity
    title: str
    description: str
    recommendation: str
    affected_rules: List[str] = Field(default_factory=list)
    confidence: float
    severity_score: int = 0
    created_at: datetime = Field(default_factory=_utcnow)
