# models/ai_models.py
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum

class ModelType(str, Enum):
    DETECTION = "detection"
    MITIGATION = "mitigation"
    SIMULATION = "simulation"

class ModelStatus(str, Enum):
    TRAINING = "training"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"

class AIModel(BaseModel):
    model_id: str
    name: str
    model_type: ModelType
    version: str
    description: str
    status: ModelStatus
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    training_data_size: int
    features: List[str]
    algorithm: str
    hyperparameters: Dict
    created_at: datetime
    updated_at: datetime
    is_active: bool = False

class TrainingConfig(BaseModel):
    model_type: ModelType
    training_data_path: str
    validation_split: float = 0.2
    batch_size: int = 32
    epochs: int = 100
    learning_rate: float = 0.001
    early_stopping_patience: int = 10

class ModelPrediction(BaseModel):
    model_id: str
    input_data: Dict
    prediction: Dict
    confidence: float
    timestamp: datetime

class ModelTrainingResult(BaseModel):
    model_id: str
    training_config: TrainingConfig
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    final_accuracy: float
    final_loss: float
    training_history: Dict
    validation_history: Dict

class DetectionModel(AIModel):
    """Specialized model for privilege escalation detection"""
    risk_thresholds: Dict[str, float] = {
        'low': 0.3,
        'medium': 0.5,
        'high': 0.7,
        'critical': 0.9
    }
    feature_importance: Optional[Dict[str, float]] = None

class MitigationModel(AIModel):
    """Specialized model for mitigation recommendation"""
    effectiveness_scores: Dict[str, float] = {}
    recommendation_confidence: float = 0.0

class SimulationModel(AIModel):
    """Specialized model for attack simulation"""
    scenario_coverage: float = 0.0
    realism_score: float = 0.0

# Example model instances
DEFAULT_DETECTION_MODEL = DetectionModel(
    model_id="detection_v1",
    name="Privilege Escalation Detector",
    model_type=ModelType.DETECTION,
    version="1.0.0",
    description="Machine learning model for detecting Windows privilege escalation vectors",
    status=ModelStatus.ACTIVE,
    accuracy=0.89,
    precision=0.85,
    recall=0.92,
    f1_score=0.88,
    training_data_size=10000,
    features=["description_length", "has_cve", "cvss_score", "category", "evidence_length"],
    algorithm="random_forest",
    hyperparameters={
        "n_estimators": 100,
        "max_depth": 10,
        "min_samples_split": 2
    },
    created_at=datetime.now(),
    updated_at=datetime.now(),
    is_active=True
)

DEFAULT_MITIGATION_MODEL = MitigationModel(
    model_id="mitigation_v1",
    name="Mitigation Recommender",
    model_type=ModelType.MITIGATION,
    version="1.0.0",
    description="AI model for recommending privilege escalation mitigations",
    status=ModelStatus.ACTIVE,
    accuracy=0.82,
    training_data_size=5000,
    features=["finding_category", "risk_level", "system_type", "existing_controls"],
    algorithm="rule_based",
    hyperparameters={},
    created_at=datetime.now(),
    updated_at=datetime.now(),
    is_active=True
)