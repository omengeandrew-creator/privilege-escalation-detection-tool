# models/finding_models.py
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel

class FindingCreate(BaseModel):
    scan_id: str
    title: str
    description: str
    risk_level: str
    category: str
    evidence: str
    mitigation: str
    cvss_score: float

class FindingResponse(BaseModel):
    finding_id: str
    scan_id: str
    title: str
    description: str
    risk_level: str
    category: str
    evidence: str
    mitigation: str
    cvss_score: float
    status: str
    assigned_to: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    mitigation: Optional[str] = None