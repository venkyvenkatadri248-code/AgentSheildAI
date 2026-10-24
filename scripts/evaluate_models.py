"""
AgentShieldAI — Independent Model Evaluation CLI.
Reports empirical precision, recall, F1, false positive rate, and latency for:
- DistilBERT
- BiLSTM
- XGBoost
- Isolation Forest
- Multi-Model Fusion Engine
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from scripts.train_and_evaluate_models import run_training_and_evaluation

if __name__ == "__main__":
    metrics = run_training_and_evaluation()
    print("\nModel Evaluation Performance Summary Table:")
    print("-" * 75)
    print(f"{'Model':<20} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'FPR':<10} | {'Latency'}")
    print("-" * 75)
    for model_name, m in metrics.items():
        print(f"{model_name:<20} | {m['precision']:<10.3f} | {m['recall']:<10.3f} | {m['f1_score']:<10.3f} | {m['false_positive_rate']:<10.3f} | {m['avg_latency_ms']:.2f} ms")
    print("-" * 75)
