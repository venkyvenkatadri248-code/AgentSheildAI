import os
import math
import logging
from typing import Dict, Any, Optional, List, Tuple

from app.security.models.fusion_engine import MultiModelFusionEngine
from app.security.explain.explainer import SecurityThreatExplainer

logger = logging.getLogger("agentshield.deep_learning")


class DeepLearningThreatDetector:
    """
    Unified 4-Model AI-Agent Threat Detection and Explainability Engine.
    
    Integrated Models:
    1. DistilBERT: Text threat detection with Integrated Gradients token attribution.
    2. BiLSTM: Temporal action sequence and repeated policy violation detector.
    3. XGBoost: Structured event feature classification with TreeSHAP.
    4. Isolation Forest: Unsupervised behavioral anomaly detection from baseline.
    
    Fusion & Explainability:
    - MultiModelFusionEngine: Calibrated multi-model consensus.
    - SecurityThreatExplainer: Complete XAI reporting (What, Which models, Evidence, Why, Agreement, Limitations).
    """

    _model_name: str = "AgentShield-Unified-4Model-Ensemble-v1"
    _model_loaded: bool = True

    @classmethod
    def is_available(cls) -> bool:
        return cls._model_loaded

    @classmethod
    def set_model_status(cls, loaded: bool):
        cls._model_loaded = loaded

    @classmethod
    def evaluate(cls, text_evidence: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Runs the full 4-model detection and explanation pipeline.
        """
        context = context or {}
        if not cls._model_loaded:
            return {
                "status": "unavailable",
                "available": False,
                "model_name": cls._model_name,
                "confidence": None,
                "prediction": None,
                "explanation": "Threat detection models are offline. Deterministic policy enforcement is active independently."
            }

        # Format event data for structured models
        current_event = {
            "tool_name": context.get("tool") or context.get("tool_name", ""),
            "agent_key": context.get("agent") or context.get("agent_key", ""),
            "allowed_tools": context.get("allowed_tools", []),
            "arguments": context.get("arguments", {"text": text_evidence}),
            "prior_violations": context.get("prior_violations", 0),
            "user_role": context.get("user_role", "user")
        }

        action_sequence = context.get("action_sequence", [])

        # 1. DETECT: Run Multi-Model Fusion Engine across all 4 models
        fusion_res = MultiModelFusionEngine.fuse(
            text_payload=text_evidence,
            current_event=current_event,
            action_sequence=action_sequence
        )

        # 2. EXPLAIN: Generate structured, evidence-based XAI report
        xai_report = SecurityThreatExplainer.generate_explanation(
            fusion_result=fusion_res,
            actor_email=context.get("actor_email"),
            agent_name=context.get("agent_name"),
            target_resource=context.get("target_resource")
        )

        is_threat = fusion_res["fused_threat_detected"]
        confidence = fusion_res["fused_threat_score"]

        prediction = "THREAT_DETECTED" if is_threat else ("SUSPICIOUS" if confidence >= 0.40 else "BENIGN")

        return {
            "status": "evaluated",
            "available": True,
            "model_name": cls._model_name,
            "confidence": confidence,
            "prediction": prediction,
            "primary_threat_category": fusion_res["primary_threat_category"],
            "explanation": xai_report["what_was_detected"] + " " + xai_report["why_indicates_threat"],
            "agreement_status": fusion_res["agreement_status"],
            "agreement_description": fusion_res["agreement_description"],
            "detecting_models": fusion_res["detecting_models"],
            "individual_models": fusion_res["individual_model_results"],
            "xai_report": xai_report,
            "deep_features": {
                "fused_threat_score": confidence,
                "detecting_count": len(fusion_res["detecting_models"]),
                "models": fusion_res["detecting_models"]
            }
        }


# Backwards compatibility alias
MLThreatEvaluator = DeepLearningThreatDetector


