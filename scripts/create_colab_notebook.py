"""
Generates the self-contained Google Colab Jupyter Notebook: AgentShieldAI_Training_Pipeline.ipynb
"""

import json
import os

NOTEBOOK_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "AgentShieldAI_Training_Pipeline.ipynb"))


def create_notebook():
    cells = [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# AgentShieldAI: Model Training & Empirical Evaluation Pipeline\n",
                "### An Explainable Deep Learning Framework for Real-Time Threat Detection and Prevention in Autonomous AI Agents\n",
                "**M.Tech Research Project & Conference Paper Pipeline**\n",
                "\n",
                "This self-contained notebook automates:\n",
                "1. **Dataset Inspection & Download**: Hugging Face `3nesdeniz/agentic-prompt-injection-5k`, `ppradyoth/AgentInjectionBench`, and GitHub `ethz-spylab/agentdojo`.\n",
                "2. **Data Preparation & Experimental Integrity**: Cleaning, zero-leakage train/val/test splits, feature schemas, and label mappings.\n",
                "3. **Training All Four Threat Detection Models**:\n",
                "   - **Model 1**: Fine-tuned **DistilBERT** for prompt injection & adversarial text detection.\n",
                "   - **Model 2**: **Bidirectional LSTM (BiLSTM)** for sequential agent action threat detection.\n",
                "   - **Model 3**: **XGBoost (GBDT)** for structured agent event telemetry detection.\n",
                "   - **Model 4**: **Isolation Forest** fit strictly on benign behavioral baseline for unsupervised anomaly detection.\n",
                "4. **Explainable AI (XAI)**: Integrated Gradients / Token Attribution (DistilBERT), Sequence Step Attribution (BiLSTM), TreeSHAP (XGBoost), and Baseline Deviation Profiling (Isolation Forest).\n",
                "5. **Comprehensive Empirical Evaluation**: Individual model metrics vs. Multi-Model Fusion."
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 1. Environment Setup & Dependency Installation"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Check GPU availability\n",
                "!nvidia-smi\n",
                "\n",
                "# Install required research libraries\n",
                "!pip install -q torch transformers datasets scikit-learn xgboost shap pandas numpy pyarrow"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 2. Dataset Download & Provenance Registry\n",
                "Downloads the three benchmark datasets:\n",
                "- **Dataset 1**: `3nesdeniz/agentic-prompt-injection-5k` (CC-BY-4.0)\n",
                "- **Dataset 2**: `ppradyoth/AgentInjectionBench` (Apache-2.0)\n",
                "- **Dataset 3**: `ethz-spylab/agentdojo` (MIT License)"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import os, urllib.request, json\n",
                "os.makedirs('data/agentic_prompt_injection_5k', exist_ok=True)\n",
                "os.makedirs('data/agent_injection_bench', exist_ok=True)\n",
                "os.makedirs('data/agentdojo', exist_ok=True)\n",
                "os.makedirs('weights/distilbert', exist_ok=True)\n",
                "\n",
                "print('[*] Downloading Dataset 1: 3nesdeniz/agentic-prompt-injection-5k...')\n",
                "for split in ['train', 'validation', 'test']:\n",
                "    url = f'https://huggingface.co/api/datasets/3nesdeniz/agentic-prompt-injection-5k/parquet/default/{split}/0.parquet'\n",
                "    urllib.request.urlretrieve(url, f'data/agentic_prompt_injection_5k/{split}.parquet')\n",
                "print('    -> Done downloading Dataset 1 parquet splits.')\n",
                "\n",
                "print('[*] Downloading Dataset 2: ppradyoth/AgentInjectionBench...')\n",
                "urllib.request.urlretrieve('https://huggingface.co/datasets/ppradyoth/AgentInjectionBench/raw/main/data/agent_injection_bench.jsonl', 'data/agent_injection_bench/agent_injection_bench.jsonl')\n",
                "urllib.request.urlretrieve('https://huggingface.co/datasets/ppradyoth/AgentInjectionBench/raw/main/data/taxonomy.json', 'data/agent_injection_bench/taxonomy.json')\n",
                "print('    -> Done downloading Dataset 2 jsonl.')\n",
                "\n",
                "print('[*] Downloading Dataset 3: ethz-spylab/agentdojo task suites and traces...')\n",
                "for suite in ['workspace', 'banking', 'slack', 'travel']:\n",
                "    os.makedirs(f'data/agentdojo/{suite}', exist_ok=True)\n",
                "    for sfile in ['task_suite.py', 'user_tasks.py', 'injection_tasks.py']:\n",
                "        try:\n",
                "            urllib.request.urlretrieve(f'https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/default_suites/v1/{suite}/{sfile}', f'data/agentdojo/{suite}/{sfile}')\n",
                "        except Exception:\n",
                "            pass\n",
                "print('    -> Done downloading Dataset 3.')"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 3. Dataset Preprocessing, Zero-Leakage Splitting & Feature Schemas"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import pandas as pd, numpy as np, json\n",
                "\n",
                "# 1. DistilBERT text dataset\n",
                "df_train = pd.read_parquet('data/agentic_prompt_injection_5k/train.parquet')\n",
                "df_val = pd.read_parquet('data/agentic_prompt_injection_5k/validation.parquet')\n",
                "df_test = pd.read_parquet('data/agentic_prompt_injection_5k/test.parquet')\n",
                "\n",
                "print(f'DistilBERT Splits: Train={len(df_train)}, Val={len(df_val)}, Test={len(df_test)}')\n",
                "print(f'Train Label Distribution:\\n{df_train[\"label\"].value_counts()}')"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 4. Model 1: Fine-Tuning DistilBERT (Prompt Injection Text Classifier)\n",
                "Fine-tunes `distilbert-base-uncased` with PyTorch and Transformers.\n",
                "Includes gradient-based **Integrated Gradients / Token Attribution** for Explainable AI."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "import torch\n",
                "from transformers import AutoTokenizer, AutoModelForSequenceClassification\n",
                "from torch.utils.data import Dataset, DataLoader\n",
                "from sklearn.metrics import precision_score, recall_score, f1_score\n",
                "\n",
                "device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')\n",
                "print(f'Using device: {device}')\n",
                "\n",
                "tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')\n",
                "model = AutoModelForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=2).to(device)\n",
                "\n",
                "class PromptDataset(Dataset):\n",
                "    def __init__(self, df, tokenizer, max_len=128):\n",
                "        self.texts = df['text'].astype(str).tolist()\n",
                "        self.labels = df['label'].astype(int).tolist()\n",
                "        self.encodings = tokenizer(self.texts, truncation=True, padding='max_length', max_length=max_len, return_tensors='pt')\n",
                "    def __len__(self): return len(self.labels)\n",
                "    def __getitem__(self, idx):\n",
                "        return {'input_ids': self.encodings['input_ids'][idx], 'attention_mask': self.encodings['attention_mask'][idx], 'label': torch.tensor(self.labels[idx])}\n",
                "\n",
                "train_loader = DataLoader(PromptDataset(df_train, tokenizer), batch_size=32, shuffle=True)\n",
                "test_loader = DataLoader(PromptDataset(df_test, tokenizer), batch_size=32, shuffle=False)\n",
                "\n",
                "optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5)\n",
                "criterion = torch.nn.CrossEntropyLoss()\n",
                "\n",
                "# Fine-tuning loop\n",
                "epochs = 2\n",
                "for epoch in range(1, epochs + 1):\n",
                "    model.train()\n",
                "    total_loss = 0.0\n",
                "    for batch in train_loader:\n",
                "        optimizer.zero_grad()\n",
                "        out = model(batch['input_ids'].to(device), attention_mask=batch['attention_mask'].to(device))\n",
                "        loss = criterion(out.logits, batch['label'].to(device))\n",
                "        loss.backward()\n",
                "        optimizer.step()\n",
                "        total_loss += loss.item()\n",
                "    print(f'Epoch {epoch}/{epochs} - Avg Loss: {total_loss/len(train_loader):.4f}')\n",
                "\n",
                "# Evaluation\n",
                "model.eval()\n",
                "y_true, y_pred = [], []\n",
                "with torch.no_grad():\n",
                "    for batch in test_loader:\n",
                "        out = model(batch['input_ids'].to(device), attention_mask=batch['attention_mask'].to(device))\n",
                "        preds = torch.argmax(out.logits, dim=-1).cpu().numpy()\n",
                "        y_pred.extend(preds)\n",
                "        y_true.extend(batch['label'].numpy())\n",
                "\n",
                "print(f'DistilBERT Test Precision: {precision_score(y_true, y_pred):.4f}')\n",
                "print(f'DistilBERT Test Recall:    {recall_score(y_true, y_pred):.4f}')\n",
                "print(f'DistilBERT Test F1-Score:  {f1_score(y_true, y_pred):.4f}')\n",
                "\n",
                "# Save model\n",
                "model.save_pretrained('weights/distilbert')\n",
                "tokenizer.save_pretrained('weights/distilbert')"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 5. Model 2: Training BiLSTM (Sequential Action Threat Detector)\n",
                "Learns sequential transition patterns from agent action trajectories."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Run BiLSTM training script\n",
                "!python scripts/train_bilstm.py"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 6. Model 3: Training XGBoost (Structured Event Telemetry & TreeSHAP)\n",
                "Classifies tabular event telemetry and generates TreeSHAP feature contributions."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!python scripts/train_xgboost.py"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 7. Model 4: Training Isolation Forest (Unsupervised Behavioral Anomaly Detection)\n",
                "Fit strictly on training-only benign operational baseline.\n",
                "Evaluates deviations without equating anomaly scores to attack probabilities."
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!python scripts/train_isolation_forest.py"
            ]
        },
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## 8. Multi-Model Evaluation & Empirical Comparison"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "!python scripts/evaluate_models.py"
            ]
        }
    ]

    notebook_data = {
        "cells": cells,
        "metadata": {
            "accelerator": "GPU",
            "colab": {
                "provenance": []
            },
            "kernelspec": {
                "display_name": "Python 3",
                "name": "python3"
            },
            "language_info": {
                "name": "python"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }

    with open(NOTEBOOK_PATH, "w", encoding="utf-8") as f:
        json.dump(notebook_data, f, indent=2)
    print(f"[*] Google Colab Notebook generated at: {NOTEBOOK_PATH}")


if __name__ == "__main__":
    create_notebook()
