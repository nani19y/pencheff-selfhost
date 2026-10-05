from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ReportCreate(BaseModel):
    format: Literal["docx", "csv", "json", "pdf"] = "docx"


class ReportOut(BaseModel):
    id: str
    scan_id: str
    format: str
    status: str
    bytes: int | None = None
    generated_at: datetime | None = None
    created_at: datetime
    download_url: str | None = None
