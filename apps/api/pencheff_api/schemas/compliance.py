from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class WorkstationComplianceReport(BaseModel):
    overall_device_score: int = Field(..., ge=0, le=100)
    overall_file_status: str = Field(..., max_length=32)
    device_checks: list[dict[str, Any]] = Field(default_factory=list)
    file_checks: list[dict[str, Any]] = Field(default_factory=list)


class WorkstationComplianceOut(BaseModel):
    user_id: str
    email: str
    name: str | None = None
    role: str
    studio_installed: bool
    monitors_enabled: bool
    overall_device_score: int
    overall_file_status: str
    device_checks_json: list[dict[str, Any]] | dict[str, Any] | None = None
    file_checks_json: list[dict[str, Any]] | dict[str, Any] | None = None
    updated_at: datetime | None = None
