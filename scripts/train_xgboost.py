"""
AgentShieldAI — Training Module for Model 3: XGBoost (Structured Event Threat Detector).
Trains a Gradient Boosted Decision Tree classifier on tabular agent-event telemetry.
Integrates TreeSHAP for exact feature attribution explanations.
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
import shap
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
os.makedirs(WEIGHTS_DIR, exist_ok=True)


def train_xgboost():
    print("=" * 80)
    print("AgentShieldAI: Training Model 3 — XGBoost (Structured Event Threat Detector)")
    print("=" * 80)

    train_csv = os.path.join(DATA_DIR, "xgboost_events_train.csv")
    val_csv = os.path.join(DATA_DIR, "xgboost_events_val.csv")
    test_csv = os.path.join(DATA_DIR, "xgboost_events_test.csv")
    schema_json = os.path.join(DATA_DIR, "xgboost_feature_schema.json")

    if not os.path.exists(train_csv):
        raise FileNotFoundError("Missing XGBoost datasets. Run prepare_datasets.py first!")

    # 1. Load Data
    df_train = pd.read_csv(train_csv)
    df_val = pd.read_csv(val_csv)
    df_test = pd.read_csv(test_csv)

    with open(schema_json, "r", encoding="utf-8") as f:
        schema = json.load(f)
    feature_cols = schema["feature_names"]

    print(f"[*] Features: {len(feature_cols)} columns")
    print(f"[*] Train shape: {df_train.shape}, Val shape: {df_val.shape}, Test shape: {df_test.shape}")

    X_train = df_train[feature_cols].values
    y_train = df_train["label"].values

    X_val = df_val[feature_cols].values
    y_val = df_val["label"].values

    X_test = df_test[feature_cols].values
    y_test = df_test["label"].values

    # Handle class imbalance with scale_pos_weight
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    scale_pos = (n_neg / n_pos) if n_pos > 0 else 1.0
    print(f"[*] Training class counts: Benign(0)={n_neg}, Attack(1)={n_pos}, scale_pos_weight={scale_pos:.3f}")

    # 2. Fit XGBoost Model
    start_train = time.time()
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=scale_pos,
        eval_metric="logloss",
        early_stopping_rounds=15,
        random_state=42
    )

    xgb_model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    train_duration = time.time() - start_train
    print(f"[*] XGBoost trained in {train_duration:.3f} seconds (Best iteration: {xgb_model.best_iteration})")

    # 3. Test Evaluation
    latencies = []
    y_pred = []
    y_prob = []

    for i in range(len(X_test)):
        t0 = time.perf_counter()
        prob = float(xgb_model.predict_proba(X_test[i:i+1])[0, 1])
        latencies.append((time.perf_counter() - t0) * 1000)
        y_prob.append(prob)
        y_pred.append(1 if prob >= 0.50 else 0)

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency = float(np.mean(latencies))

    print(f"\n[*] Empirical Evaluation Results (Test Split):")
    print(f"    - Total Test Samples: {len(y_test)}")
    print(f"    - True Positives (TP): {tp}")
    print(f"    - False Positives (FP): {fp}")
    print(f"    - True Negatives (TN): {tn}")
    print(f"    - False Negatives (FN): {fn}")
    print(f"    - Precision: {prec:.4f}")
    print(f"    - Recall: {rec:.4f}")
    print(f"    - F1-Score: {f1:.4f}")
    print(f"    - False Positive Rate: {fpr:.4f}")
    print(f"    - Avg Inference Latency: {avg_latency:.3f} ms")

    # 4. TreeSHAP Explainability Verification
    print(f"\n[*] Initializing TreeSHAP Explainer...")
    explainer = shap.TreeExplainer(xgb_model)
    shap_values = explainer.shap_values(X_test[:10])
    expected_value = float(explainer.expected_value) if isinstance(explainer.expected_value, (float, int, np.floating)) else float(explainer.expected_value[1] if len(explainer.expected_value) > 1 else explainer.expected_value[0])
    
    print(f"[*] SHAP Expected Value (base logit): {expected_value:.4f}")
    # Inspect top feature impacts across test set
    mean_abs_shap = np.mean(np.abs(shap_values), axis=0)
    top_indices = np.argsort(mean_abs_shap)[::-1][:6]
    print(f"[*] Top 6 Global Feature Contributions (Mean |SHAP|):")
    feature_impacts = {}
    for idx in top_indices:
        feat_name = feature_cols[idx]
        impact = float(mean_abs_shap[idx])
        feature_impacts[feat_name] = round(impact, 4)
        print(f"    - {feat_name}: {impact:.4f}")

    # 5. Save Model Checkpoints & Schema
    model_json_path = os.path.join(WEIGHTS_DIR, "xgboost_model.json")
    xgb_model.save_model(model_json_path)
    print(f"\n[*] XGBoost model saved to: {model_json_path}")

    model_joblib_path = os.path.join(WEIGHTS_DIR, "xgboost_model.joblib")
    joblib.dump(xgb_model, model_joblib_path)

    # Save feature metadata & SHAP config
    shap_config = {
        "model_name": "AgentShield-XGBoost-Structured-v1",
        "feature_names": feature_cols,
        "base_expected_value": expected_value,
        "top_feature_impacts": feature_impacts,
        "classes": [0, 1]
    }
    shap_config_path = os.path.join(WEIGHTS_DIR, "xgboost_shap_config.json")
    with open(shap_config_path, "w", encoding="utf-8") as f:
        json.dump(shap_config, f, indent=2)

    # Save evaluation metrics
    metrics = {
        "model_name": "XGBoost-Structured-Event-Detector",
        "n_train_samples": len(df_train),
        "n_test_samples": len(df_test),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(avg_latency, 3),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "top_feature_impacts": feature_impacts
    }

    metrics_path = os.path.join(WEIGHTS_DIR, "xgboost_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[*] Evaluation metrics saved to: {metrics_path}")

    return metrics


if __name__ == "__main__":
    train_xgboost()
