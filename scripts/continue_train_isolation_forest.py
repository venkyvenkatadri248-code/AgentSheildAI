"""
AgentShieldAI — Step 3: Adaptation & Retraining for Model 4: Isolation Forest (Behavioral Anomaly Detector).
Documents that Isolation Forest does not use gradient-based fine-tuning.
Loads existing baseline, incorporates expanded benign operational telemetry, fits updated forest,
and evaluates original vs. updated on independent evaluation set.
"""

import os
import sys
import json
import time
import joblib
import logging
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("continue_train_if")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")

ORIG_JOBLIB = os.path.join(WEIGHTS_DIR, "original_backup", "isolation_forest.joblib")
UPDATED_JOBLIB = os.path.join(WEIGHTS_DIR, "updated", "isolation_forest.joblib")
UPDATED_JSON = os.path.join(WEIGHTS_DIR, "updated", "isolation_forest_model.json")

def evaluate_if(model, X_eval, y_eval) -> Dict[str, Any]:
    t0 = time.perf_counter()
    # Isolation Forest: -1 is anomaly (1), 1 is normal (0)
    raw_preds = model.predict(X_eval)
    preds = np.where(raw_preds == -1, 1, 0)
    latency = (time.perf_counter() - t0) * 1000 / len(y_eval)
    
    p = float(precision_score(y_eval, preds, zero_division=0))
    r = float(recall_score(y_eval, preds, zero_division=0))
    f1 = float(f1_score(y_eval, preds, zero_division=0))
    cm = confusion_matrix(y_eval, preds).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(latency, 3),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "sample_count": len(y_eval)
    }

def main():
    train_csv = os.path.join(DATA_DIR, "isolation_forest_benign_train.csv")
    eval_csv = os.path.join(DATA_DIR, "isolation_forest_eval.csv")
    schema_json = os.path.join(DATA_DIR, "isolation_forest_schema.json")
    
    with open(schema_json, "r", encoding="utf-8") as f:
        schema = json.load(f)
    feature_cols = schema["features"]
    
    df_train = pd.read_csv(train_csv)
    df_eval = pd.read_csv(eval_csv)
    
    X_train = df_train[feature_cols].values
    X_eval = df_eval[feature_cols].values
    y_eval = df_eval["ground_truth_label"].values if "ground_truth_label" in df_eval.columns else df_eval["label"].values
    
    # 1. Load ORIGINAL model and evaluate
    logger.info(f"Loading ORIGINAL Isolation Forest from: {ORIG_JOBLIB}")
    orig_model = joblib.load(ORIG_JOBLIB)
    orig_metrics = evaluate_if(orig_model, X_eval, y_eval)
    logger.info(f"ORIGINAL Isolation Forest Eval: P={orig_metrics['precision']}, R={orig_metrics['recall']}, F1={orig_metrics['f1_score']}, FPR={orig_metrics['false_positive_rate']}")
    
    # 2. Fit UPDATED model on expanded baseline with calibrated contamination
    logger.info("Fitting UPDATED Isolation Forest with adapted benign baseline distribution...")
    updated_model = IsolationForest(
        n_estimators=100,
        max_samples=256,
        contamination=0.08,  # Calibrated for lower false-positive rate
        random_state=42
    )
    updated_model.fit(X_train)
    
    # 3. Save UPDATED model separately
    os.makedirs(os.path.join(WEIGHTS_DIR, "updated"), exist_ok=True)
    joblib.dump(updated_model, UPDATED_JOBLIB)
    logger.info(f"Saved UPDATED Isolation Forest to: {UPDATED_JOBLIB}")
    
    # Update baseline parameter distribution JSON
    baseline_dist = {}
    for col in feature_cols:
        baseline_dist[col] = {
            "mean": round(float(df_train[col].mean()), 4),
            "std": round(float(df_train[col].std()), 4),
            "min": round(float(df_train[col].min()), 4),
            "max": round(float(df_train[col].max()), 4)
        }
    with open(UPDATED_JSON, "w", encoding="utf-8") as f:
        json.dump(baseline_dist, f, indent=2)
        
    # 4. Evaluate UPDATED model on exact same evaluation set
    updated_metrics = evaluate_if(updated_model, X_eval, y_eval)
    logger.info(f"UPDATED Isolation Forest Eval:   P={updated_metrics['precision']}, R={updated_metrics['recall']}, F1={updated_metrics['f1_score']}, FPR={updated_metrics['false_positive_rate']}")
    
    # Comparison report
    comp = {
        "model_name": "IsolationForest",
        "sample_count": len(y_eval),
        "original_metrics": orig_metrics,
        "updated_metrics": updated_metrics,
        "f1_delta": round(updated_metrics["f1_score"] - orig_metrics["f1_score"], 4),
        "recall_delta": round(updated_metrics["recall"] - orig_metrics["recall"], 4),
        "fpr_delta": round(updated_metrics["false_positive_rate"] - orig_metrics["false_positive_rate"], 4)
    }
    with open(os.path.join(WEIGHTS_DIR, "updated", "isolation_forest_comparison.json"), "w", encoding="utf-8") as f:
        json.dump(comp, f, indent=2)

if __name__ == "__main__":
    main()
