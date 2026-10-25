"""
AgentShieldAI — Training Module for Model 2: BiLSTM (Sequential Action Threat Detector).
Trains a Bidirectional LSTM on ordered agent action sequences from AgentDojo and AgentInjectionBench.
Computes sequence step-attribution for explainability.
"""

import os
import sys
import json
import time
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
os.makedirs(WEIGHTS_DIR, exist_ok=True)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# -------------------------------------------------------------------------
# PyTorch BiLSTM Architecture
# -------------------------------------------------------------------------
class BiLSTMThreatClassifier(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int = 64, hidden_dim: int = 64, num_layers: int = 2, num_classes: int = 2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            bidirectional=True,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, num_classes)
        )

    def forward(self, x, lengths=None):
        # x: (batch_size, seq_len)
        embedded = self.embedding(x)  # (batch, seq, embed)
        lstm_out, (hn, cn) = self.lstm(embedded)
        
        # Max-pooling across time steps to capture peak threat markers
        pooled, _ = torch.max(lstm_out, dim=1)
        logits = self.fc(pooled)
        return logits

    def get_step_attributions(self, x_seq: torch.Tensor) -> np.ndarray:
        """
        Computes gradient-based sequence step attribution (saliency / Integrated Gradients approximation).
        Identifies which action step in the trajectory triggered the detection.
        """
        self.eval()
        embedded = self.embedding(x_seq).clone().detach().requires_grad_(True)
        lstm_out, _ = self.lstm(embedded)
        pooled, _ = torch.max(lstm_out, dim=1)
        logits = self.fc(pooled)
        threat_score = logits[0, 1] - logits[0, 0]
        threat_score.backward()
        
        # Gradient magnitude per step
        grad = embedded.grad[0].norm(dim=-1).cpu().numpy()
        total = grad.sum()
        if total > 0:
            return grad / total
        return np.ones_like(grad) / len(grad)


class ActionSequenceDataset(Dataset):
    def __init__(self, sequences, vocab, max_len: int = 16):
        self.samples = []
        for s in sequences:
            tool_ids = [vocab.get(step["tool"], vocab["<UNK>"]) for step in s.get("steps", [])]
            if len(tool_ids) > max_len:
                tool_ids = tool_ids[:max_len]
            padded = tool_ids + [vocab["<PAD>"]] * (max_len - len(tool_ids))
            self.samples.append({
                "input_ids": torch.tensor(padded, dtype=torch.long),
                "length": max(1, len(tool_ids)),
                "label": torch.tensor(s["label"], dtype=torch.long)
            })

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]


def train_bilstm():
    print("=" * 80)
    print("AgentShieldAI: Training Model 2 — BiLSTM (Sequential Action Threat Detector)")
    print(f"Device: {DEVICE}")
    print("=" * 80)

    dataset_json = os.path.join(DATA_DIR, "bilstm_sequence_dataset.json")
    if not os.path.exists(dataset_json):
        raise FileNotFoundError("Missing bilstm_sequence_dataset.json. Run prepare_datasets.py first!")

    with open(dataset_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    train_seqs = data["train"]
    val_seqs = data["val"]
    test_seqs = data["test"]
    vocab = data["vocab"]
    max_len = data.get("max_seq_len", 16)

    print(f"[*] Vocab size: {len(vocab)}, Max sequence length: {max_len}")
    print(f"[*] Samples: Train={len(train_seqs)}, Val={len(val_seqs)}, Test={len(test_seqs)}")

    train_ds = ActionSequenceDataset(train_seqs, vocab, max_len)
    val_ds = ActionSequenceDataset(val_seqs, vocab, max_len)
    test_ds = ActionSequenceDataset(test_seqs, vocab, max_len)

    train_loader = DataLoader(train_ds, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=16, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=1, shuffle=False)

    # Class weighting to handle imbalance
    labels = [s["label"] for s in train_seqs]
    n_neg = sum(1 for l in labels if l == 0)
    n_pos = sum(1 for l in labels if l == 1)
    weight_tensor = torch.tensor([n_pos / max(1, n_neg), 1.0], dtype=torch.float32).to(DEVICE)
    print(f"[*] Class weights: Benign={weight_tensor[0]:.2f}, Attack=1.00")

    model = BiLSTMThreatClassifier(vocab_size=len(vocab), embed_dim=64, hidden_dim=64, num_layers=2).to(DEVICE)
    criterion = nn.CrossEntropyLoss(weight=weight_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.002, weight_decay=1e-4)

    # Training Loop
    epochs = 15
    best_val_f1 = 0.0
    best_state = None
    start_train = time.time()

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            x = batch["input_ids"].to(DEVICE)
            y = batch["label"].to(DEVICE)

            optimizer.zero_grad()
            logits = model(x)
            loss = criterion(logits, y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        # Validation
        model.eval()
        val_preds, val_targets = [], []
        with torch.no_grad():
            for batch in val_loader:
                x = batch["input_ids"].to(DEVICE)
                logits = model(x)
                preds = torch.argmax(logits, dim=-1).cpu().numpy()
                val_preds.extend(preds)
                val_targets.extend(batch["label"].numpy())

        val_f1 = f1_score(val_targets, val_preds, zero_division=0)
        avg_loss = total_loss / len(train_loader)
        
        if val_f1 >= best_val_f1:
            best_val_f1 = val_f1
            best_state = model.state_dict().copy()

        if epoch % 5 == 0 or epoch == epochs:
            print(f"    Epoch {epoch:02d}/{epochs:02d} - Loss: {avg_loss:.4f} - Val F1: {val_f1:.4f}")

    train_duration = time.time() - start_train
    print(f"[*] Training finished in {train_duration:.2f}s. Restoring best model (Best Val F1={best_val_f1:.4f}).")
    if best_state is not None:
        model.load_state_dict(best_state)

    # Evaluation on Test Split
    model.eval()
    y_true, y_pred, y_probs = [], [], []
    latencies = []

    for batch in test_loader:
        x = batch["input_ids"].to(DEVICE)
        target = batch["label"].item()
        
        t0 = time.perf_counter()
        with torch.no_grad():
            logits = model(x)
            prob = torch.softmax(logits, dim=-1)[0, 1].item()
            pred = int(prob >= 0.50)
        latencies.append((time.perf_counter() - t0) * 1000)

        y_true.append(target)
        y_pred.append(pred)
        y_probs.append(prob)

    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency = float(np.mean(latencies))

    print(f"\n[*] Empirical Evaluation Results (Held-Out Test Set):")
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

    # Sequence Attribution XAI Verification
    # Pick a suspicious test sample and compute step attributions
    susp_idx = [i for i, yt in enumerate(y_true) if yt == 1][0]
    sample_seq = test_seqs[susp_idx]
    x_sample = test_ds[susp_idx]["input_ids"].unsqueeze(0).to(DEVICE)
    step_attributions = model.get_step_attributions(x_sample)
    
    print(f"\n[*] XAI Verification — Sequence Step Attributions on Sample '{sample_seq['id']}':")
    for s_idx, step in enumerate(sample_seq["steps"][:len(step_attributions)]):
        attrib = step_attributions[s_idx]
        print(f"    Step {s_idx+1}: Tool='{step['tool']}', Status='{step['status']}', Attribution={attrib:.4f}")

    # Save Checkpoint
    checkpoint_path = os.path.join(WEIGHTS_DIR, "bilstm_model.pt")
    torch.save({
        "model_state_dict": model.state_dict(),
        "vocab": vocab,
        "vocab_size": len(vocab),
        "embed_dim": 64,
        "hidden_dim": 64,
        "max_len": max_len,
        "classes": ["benign", "suspicious"]
    }, checkpoint_path)
    print(f"\n[*] Checkpoint saved to: {checkpoint_path}")

    # Save Evaluation Metrics
    metrics = {
        "model_name": "BiLSTM-Sequence-Threat-Detector",
        "n_train_samples": len(train_seqs),
        "n_test_samples": len(test_seqs),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(avg_latency, 3),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}
    }
    metrics_path = os.path.join(WEIGHTS_DIR, "bilstm_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[*] Evaluation metrics saved to: {metrics_path}")

    return metrics


if __name__ == "__main__":
    train_bilstm()
