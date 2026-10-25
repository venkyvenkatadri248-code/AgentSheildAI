"""
AgentShieldAI — Step 3: Continued Training for Model 3: XGBoost (Structured Event Detector).
Loads existing booster, preserves 183-dim feature schema, performs continued boosting,
computes TreeSHAP feature attributions, and saves updated model to weights/updated/xgboost_model.json.
Evaluates original vs. updated on independent test set.
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
import xgboost as xgb
import shap
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("continue_train_xgboost")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")

ORIG_JSON = os.path.join(WEIGHTS_DIR, "original_backup", "xgboost_model.json")
UPDATED_JSON = os.path.join(WEIGHTS_DIR, "updated", "xgboost_model.json")
UPDATED_JOBLIB = os.path.join(WEIGHTS_DIR, "updated", "xgboost_model.joblib")

def evaluate_xgb(model, X_test, y_test) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if isinstance(model, xgb.Booster):
        dtest = xgb.DMatrix(X_test)
        probs = model.predict(dtest)
        preds = (probs >= 0.5).astype(int)
    else:
        probs = model.predict_proba(X_test)[:, 1]
        preds = model.predict(X_test)
        
    latency = (time.perf_counter() - t0) * 1000 / len(y_test)
    
    p = float(precision_score(y_test, preds, zero_division=0))
    r = float(recall_score(y_test, preds, zero_division=0))
    f1 = float(f1_score(y_test, preds, zero_division=0))
    cm = confusion_matrix(y_test, preds).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(latency, 3),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "sample_count": len(y_test)
    }

def main():
    train_csv = os.path.join(DATA_DIR, "xgboost_events_train.csv")
    val_csv = os.path.join(DATA_DIR, "xgboost_events_val.csv")
    test_csv = os.path.join(DATA_DIR, "xgboost_events_test.csv")
    schema_json = os.path.join(DATA_DIR, "xgboost_feature_schema.json")
    
    with open(schema_json, "r", encoding="utf-8") as f:
        schema = json.load(f)
    feature_cols = schema["feature_names"]
    
    df_train = pd.read_csv(train_csv)
    df_val = pd.read_csv(val_csv)
    df_test = pd.read_csv(test_csv)
    
    X_train = df_train[feature_cols].values
    y_train = df_train["label"].values
    
    X_val = df_val[feature_cols].values
    y_val = df_val["label"].values
    
    X_test = df_test[feature_cols].values
    y_test = df_test["label"].values
    
    # 1. Load ORIGINAL Booster and evaluate
    logger.info(f"Loading ORIGINAL XGBoost model from: {ORIG_JSON}")
    orig_booster = xgb.Booster()
    orig_booster.load_model(ORIG_JSON)
    
    orig_metrics = evaluate_xgb(orig_booster, X_test, y_test)
    logger.info(f"ORIGINAL XGBoost Test: P={orig_metrics['precision']}, R={orig_metrics['recall']}, F1={orig_metrics['f1_score']}, FPR={orig_metrics['false_positive_rate']}")
    
    # 2. Continued training using xgb_model parameter
    logger.info("Executing XGBoost continued training with additional boosting rounds...")
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dval = xgb.DMatrix(X_val, label=y_val)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "max_depth": 4,
        "learning_rate": 0.04,  # Conservative continued learning rate
        "subsample": 0.85,
        "colsample_bytree": 0.85
    }
    
    # Continue boosting for 25 additional trees
    updated_booster = xgb.train(
        params=params,
        dtrain=dtrain,
        num_boost_round=25,
        evals=[(dtrain, "train"), (dval, "val")],
        xgb_model=orig_booster,
        verbose_eval=False
    )
    
    # 3. Save UPDATED model separately
    os.makedirs(os.path.join(WEIGHTS_DIR, "updated"), exist_ok=True)
    updated_booster.save_model(UPDATED_JSON)
    joblib.dump(updated_booster, UPDATED_JOBLIB)
    logger.info(f"Saved UPDATED XGBoost model to: {UPDATED_JSON}")
    
    # 4. Evaluate UPDATED model
    updated_metrics = evaluate_xgb(updated_booster, X_test, y_test)
    logger.info(f"UPDATED XGBoost Test:   P={updated_metrics['precision']}, R={updated_metrics['recall']}, F1={updated_metrics['f1_score']}, FPR={updated_metrics['false_positive_rate']}")
    
    # 5. TreeSHAP feature attribution check
    explainer = shap.TreeExplainer(updated_booster)
    shap_vals = explainer.shap_values(X_test[:50])
    mean_abs_shap = np.mean(np.abs(shap_vals), axis=0)
    top_indices = np.argsort(mean_abs_shap)[::-1][:6]
    top_impacts = {feature_cols[i]: round(float(mean_abs_shap[i]), 4) for i in top_indices}
    logger.info(f"Updated Top TreeSHAP Impacts: {top_impacts}")
    
    # Comparison report
    comp = {
        "model_name": "XGBoost",
        "sample_count": len(y_test),
        "original_metrics": orig_metrics,
        "updated_metrics": updated_metrics,
        "top_shap_features": top_impacts,
        "f1_delta": round(updated_metrics["f1_score"] - orig_metrics["f1_score"], 4),
        "recall_delta": round(updated_metrics["recall"] - orig_metrics["recall"], 4)
    }
    with open(os.path.join(WEIGHTS_DIR, "updated", "xgboost_comparison.json"), "w", encoding="utf-8") as f:
        json.dump(comp, f, indent=2)

if __name__ == "__main__":
    main()
