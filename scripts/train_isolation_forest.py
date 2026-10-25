"""
AgentShieldAI — Training Module for Model 4: Isolation Forest (Behavioral Anomaly Detector).
Trains on strictly legitimate benign operational agent telemetry.
Evaluates on held-out benign and anomalous/suspicious operational scenarios.
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
os.makedirs(WEIGHTS_DIR, exist_ok=True)

FEATURE_COLS = [
    "arg_character_length",
    "argument_keys_count",
    "path_depth_levels",
    "special_character_density",
    "inter_request_interval_s",
    "entropy_shannon"
]


def train_isolation_forest():
    print("=" * 80)
    print("AgentShieldAI: Training Model 4 — Isolation Forest (Behavioral Anomaly Detection)")
    print("=" * 80)

    train_csv = os.path.join(DATA_DIR, "isolation_forest_benign_train.csv")
    eval_csv = os.path.join(DATA_DIR, "isolation_forest_eval.csv")

    if not os.path.exists(train_csv) or not os.path.exists(eval_csv):
        raise FileNotFoundError("Missing isolation forest datasets. Run prepare_datasets.py first!")

    # 1. Load Data
    df_train = pd.read_csv(train_csv)
    df_eval = pd.read_csv(eval_csv)

    print(f"[*] Loaded training benign samples: {len(df_train)}")
    print(f"[*] Loaded held-out evaluation samples: {len(df_eval)} (Ground-truth benign: {(df_eval['ground_truth_label'] == 0).sum()}, anomalous: {(df_eval['ground_truth_label'] == 1).sum()})")

    X_train = df_train[FEATURE_COLS].values
    X_eval = df_eval[FEATURE_COLS].values
    y_true = df_eval["ground_truth_label"].values  # 0=normal, 1=anomalous

    # 2. Compute Baseline Statistics (for Explainability & Z-Score Deviation Profiling)
    baseline_stats = {}
    for col in FEATURE_COLS:
        mean_val = float(df_train[col].mean())
        std_val = float(df_train[col].std()) if df_train[col].std() > 0 else 1.0
        baseline_stats[col] = {
            "mean": round(mean_val, 4),
            "std": round(std_val, 4),
            "min": round(float(df_train[col].min()), 4),
            "max": round(float(df_train[col].max()), 4)
        }

    # 3. Fit Isolation Forest
    start_train = time.time()
    iso_model = IsolationForest(
        n_estimators=100,
        max_samples=min(256, len(df_train)),
        contamination=0.08,  # Expected slight noise in baseline
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(X_train)
    train_duration = time.time() - start_train
    print(f"[*] Isolation Forest fitted in {train_duration:.3f} seconds.")

    # 4. Evaluation
    start_eval = time.time()
    latencies = []
    y_pred = []
    anomaly_scores = []

    for i in range(len(X_eval)):
        t0 = time.perf_counter()
        sample = X_eval[i:i+1]
        raw_pred = iso_model.predict(sample)[0]  # -1 for anomaly, 1 for normal
        score = float(-iso_model.decision_function(sample)[0])  # Higher means more anomalous
        latencies.append((time.perf_counter() - t0) * 1000)
        
        # Map: -1 (anomaly) -> 1, 1 (normal) -> 0
        pred_label = 1 if raw_pred == -1 else 0
        y_pred.append(pred_label)
        anomaly_scores.append(score)

    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency = float(np.mean(latencies))

    print(f"\n[*] Empirical Evaluation Results (Held-Out Evaluation Set):")
    print(f"    - Total Test Samples: {len(y_true)}")
    print(f"    - True Positives (TP): {tp}")
    print(f"    - False Positives (FP): {fp}")
    print(f"    - True Negatives (TN): {tn}")
    print(f"    - False Negatives (FN): {fn}")
    print(f"    - Precision: {prec:.4f}")
    print(f"    - Recall: {rec:.4f}")
    print(f"    - F1-Score: {f1:.4f}")
    print(f"    - False Positive Rate: {fpr:.4f}")
    print(f"    - Avg Inference Latency: {avg_latency:.3f} ms")

    # 5. Explainability Verification: Check Deviation Attribution on Top Anomaly
    top_anom_idx = int(np.argmax(anomaly_scores))
    top_sample = df_eval.iloc[top_anom_idx]
    print(f"\n[*] XAI Verification — Feature Deviations on Top Anomaly (Score={anomaly_scores[top_anom_idx]:.4f}, Ground-Truth={top_sample['ground_truth_label']}):")
    deviations = {}
    for col in FEATURE_COLS:
        val = float(top_sample[col])
        z_score = (val - baseline_stats[col]["mean"]) / baseline_stats[col]["std"]
        deviations[col] = round(z_score, 2)
        print(f"    - {col}: Value={val:.2f}, Baseline Mean={baseline_stats[col]['mean']:.2f}, Z-score={z_score:+.2f}")

    # 6. Save Model, Schema & Metrics
    model_path = os.path.join(WEIGHTS_DIR, "isolation_forest.joblib")
    joblib.dump(iso_model, model_path)
    print(f"\n[*] Model saved to: {model_path}")

    weights_json_path = os.path.join(WEIGHTS_DIR, "isolation_forest_model.json")
    with open(weights_json_path, "w", encoding="utf-8") as f:
        json.dump(baseline_stats, f, indent=2)

    metrics = {
        "model_name": "IsolationForest-Behavioral-Anomaly-Detector",
        "n_train_samples": len(df_train),
        "n_eval_samples": len(df_eval),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(avg_latency, 3),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "baseline_features": baseline_stats
    }

    metrics_out_path = os.path.join(WEIGHTS_DIR, "isolation_forest_metrics.json")
    with open(metrics_out_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[*] Evaluation metrics saved to: {metrics_out_path}")

    return metrics


if __name__ == "__main__":
    train_isolation_forest()
