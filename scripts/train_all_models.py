"""
AgentShieldAI — Unified Pipeline Orchestrator.
Executes the end-to-end dataset inspection, preparation, training, and evaluation pipeline:
1. inspect_datasets.py (Schema, license, and provenance verification)
2. download_datasets.py (Automated download & manifest generation)
3. prepare_datasets.py (Cleaning, splitting, feature schemas, label mappings)
4. train_distilbert.py (Model 1: DistilBERT text classification & token attributions)
5. train_bilstm.py (Model 2: BiLSTM sequential action threat detector)
6. train_xgboost.py (Model 3: XGBoost tabular event detector & TreeSHAP)
7. train_isolation_forest.py (Model 4: Isolation Forest unsupervised behavioral baseline)
8. evaluate_models.py (Comprehensive empirical evaluation & fusion comparison)
"""

import os
import sys
import time
import argparse
import subprocess

PYTHON_EXE = sys.executable
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")


def run_stage(script_name: str, args: list = None, desc: str = ""):
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [PYTHON_EXE, script_path] + (args or [])
    
    print("\n" + "=" * 80)
    print(f"PIPELINE STAGE: {desc or script_name}")
    print(f"Command: {' '.join(cmd)}")
    print("=" * 80)

    start_t = time.time()
    res = subprocess.run(cmd, cwd=BASE_DIR)
    duration = time.time() - start_t

    if res.returncode != 0:
        print(f"\n[!] Stage '{script_name}' failed with return code {res.returncode} after {duration:.2f}s.")
        sys.exit(res.returncode)

    print(f"\n[+] Stage '{script_name}' completed successfully in {duration:.2f}s.")
    return duration


def main():
    parser = argparse.ArgumentParser(description="AgentShieldAI Full Pipeline Orchestrator")
    parser.add_argument("--skip-download", action="store_true", help="Skip dataset download if already downloaded")
    parser.add_argument("--distilbert-subsample", type=int, default=300, help="Subsample for fast local CPU training (set 0 for full 3,923)")
    parser.add_argument("--distilbert-epochs", type=int, default=1, help="DistilBERT fine-tuning epochs")
    parser.add_argument("--only-eval", action="store_true", help="Only run evaluation on existing trained models")
    args = parser.parse_args()

    total_start = time.time()
    print("*" * 80)
    print("AgentShieldAI: Full Dataset Preparation & Model Training Orchestration")
    print(f"Python: {PYTHON_EXE}")
    print(f"Directory: {BASE_DIR}")
    print("*" * 80)

    if args.only_eval:
        run_stage("evaluate_models.py", desc="Model Evaluation & Fusion Comparison")
        return

    # Stage 0: Inspection
    run_stage("inspect_datasets.py", desc="Dataset Inspection (Schemas & Licenses)")

    # Stage 1: Download
    if not args.skip_download:
        run_stage("download_datasets.py", desc="Dataset Download & Provenance Registry")
    else:
        print("\n[*] Skipping download step (--skip-download requested).")

    # Stage 2: Prepare Datasets
    run_stage("prepare_datasets.py", desc="Data Cleaning, Splitting & Feature Schemas")

    # Stage 3: Train Model 4 (Isolation Forest)
    run_stage("train_isolation_forest.py", desc="Train Model 4: Isolation Forest (Behavioral Anomaly)")

    # Stage 4: Train Model 3 (XGBoost)
    run_stage("train_xgboost.py", desc="Train Model 3: XGBoost (Structured Event Telemetry)")

    # Stage 5: Train Model 2 (BiLSTM)
    run_stage("train_bilstm.py", desc="Train Model 2: BiLSTM (Sequential Action Trajectories)")

    # Stage 6: Train Model 1 (DistilBERT)
    distilbert_args = ["--epochs", str(args.distilbert_epochs)]
    if args.distilbert_subsample > 0:
        distilbert_args.extend(["--subsample", str(args.distilbert_subsample)])
    run_stage("train_distilbert.py", args=distilbert_args, desc="Train Model 1: DistilBERT (Prompt Injections)")

    # Stage 7: Evaluate Models & Fusion Comparison
    run_stage("evaluate_models.py", desc="Empirical Evaluation & Multi-Model Fusion Comparison")

    total_duration = time.time() - total_start
    print("\n" + "*" * 80)
    print(f"ALL PIPELINE STAGES COMPLETED SUCCESSFULLY IN {total_duration:.2f} SECONDS!")
    print("*" * 80)


if __name__ == "__main__":
    main()
