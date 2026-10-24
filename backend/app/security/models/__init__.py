"""
AgentShieldAI Multi-Model Threat Detection Package.
Contains:
1. DistilBERT Threat Detector (Prompt Injection, Jailbreaks, Malicious Instructions, Exfiltration)
2. BiLSTM Sequence Threat Detector (Action Sequences, Escalations, Repeated Violations)
3. XGBoost Event Threat Detector (Structured Tabular Event Features with TreeSHAP)
4. Isolation Forest Behavioral Anomaly Detector (Unsupervised Agent Baseline Deviations)
5. Multi-Model Fusion Engine (Validation-tested ensemble combining all 4 models)
"""

from app.security.models.distilbert_detector import DistilBERTThreatDetector
from app.security.models.bilstm_detector import BiLSTMSequenceDetector
from app.security.models.xgboost_detector import XGBoostEventDetector
from app.security.models.isolation_forest_detector import IsolationForestAnomalyDetector
from app.security.models.fusion_engine import MultiModelFusionEngine

__all__ = [
    "DistilBERTThreatDetector",
    "BiLSTMSequenceDetector",
    "XGBoostEventDetector",
    "IsolationForestAnomalyDetector",
    "MultiModelFusionEngine",
]
