# models/scan_models.py
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

class ScanConfig(BaseModel):
    scan_type: str
    target_system: str
    scan_depth: str
    modules: List[str]
    ai_analysis: bool = True
    simulate_attacks: bool = False
    auto_mitigate: bool = False

class ScanCreate(BaseModel):
    initiated_by: str
    target_system: str
    scan_type: str
    scan_config: ScanConfig

class ScanResponse(BaseModel):
    scan_id: str
    initiated_by: str
    target_system: str
    scan_type: str
    status: str
    findings_count: int
    risk_score: float
    start_time: datetime
    end_time: Optional[datetime] = None
    scan_config: Dict[str, Any]