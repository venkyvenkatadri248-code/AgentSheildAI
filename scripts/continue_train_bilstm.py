"""
AgentShieldAI — Step 3: Continued Training for Model 2: BiLSTM (Sequence Threat Detector).
Loads existing checkpoint, preserves architecture and vocabulary, fine-tunes with conservative
learning rate, and saves updated checkpoint separately in weights/updated/bilstm_model.pt.
Evaluates original vs. updated on independent test set.
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, Any, List

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("continue_train_bilstm")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")
ORIG_CHECKPOINT = os.path.join(WEIGHTS_DIR, "original_backup", "bilstm_model.pt")
UPDATED_CHECKPOINT = os.path.join(WEIGHTS_DIR, "updated", "bilstm_model.pt")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

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

    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        pooled, _ = torch.max(lstm_out, dim=1)
        return self.fc(pooled)

class ActionSequenceDataset(Dataset):
    def __init__(self, sequences, vocab, max_len: int = 16):
        self.samples = []
        for item in sequences:
            steps = item.get("steps", [])
            token_ids = []
            for s in steps:
                tool_name = s.get("tool", "")
                token_ids.append(vocab.get(tool_name, 1))
            
            if not token_ids:
                token_ids = [0]
                
            if len(token_ids) > max_len:
                token_ids = token_ids[-max_len:]
            else:
                token_ids = token_ids + [0] * (max_len - len(token_ids))
                
            label = int(item.get("label", 0))
            self.samples.append((torch.tensor(token_ids, dtype=torch.long), torch.tensor(label, dtype=torch.long)))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]

def evaluate_bilstm(model, test_loader) -> Dict[str, Any]:
    model.eval()
    all_preds = []
    all_labels = []
    latencies = []
    
    with torch.no_grad():
        for x, y in test_loader:
            x, y = x.to(DEVICE), y.to(DEVICE)
            t0 = time.perf_counter()
            logits = model(x)
            latencies.append((time.perf_counter() - t0) * 1000 / len(y))
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(y.cpu().numpy())
            
    p = float(precision_score(all_labels, all_preds, zero_division=0))
    r = float(recall_score(all_labels, all_preds, zero_division=0))
    f1 = float(f1_score(all_labels, all_preds, zero_division=0))
    cm = confusion_matrix(all_labels, all_preds).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    avg_lat = float(sum(latencies) / len(latencies)) if latencies else 0.0
    
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(avg_lat, 3),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "sample_count": len(all_labels)
    }

def main():
    vocab_file = os.path.join(DATA_DIR, "bilstm_vocab.json")
    seq_file = os.path.join(DATA_DIR, "bilstm_sequence_dataset.json")
    
    with open(vocab_file, "r", encoding="utf-8") as f: vocab = json.load(f)
    with open(seq_file, "r", encoding="utf-8") as f: seq_data = json.load(f)
    
    train_seqs = seq_data["train"]
    val_seqs = seq_data["val"]
    test_seqs = seq_data["test"]
    
    vocab_size = max(vocab.values()) + 1
    
    test_ds = ActionSequenceDataset(test_seqs, vocab)
    test_loader = DataLoader(test_ds, batch_size=32, shuffle=False)
    
    # 1. Load ORIGINAL model and evaluate
    logger.info(f"Loading ORIGINAL BiLSTM checkpoint from: {ORIG_CHECKPOINT}")
    orig_model = BiLSTMThreatClassifier(vocab_size=vocab_size).to(DEVICE)
    ckpt = torch.load(ORIG_CHECKPOINT, map_location=DEVICE)
    orig_model.load_state_dict(ckpt["model_state_dict"] if "model_state_dict" in ckpt else ckpt)
    
    orig_metrics = evaluate_bilstm(orig_model, test_loader)
    logger.info(f"ORIGINAL BiLSTM Test: P={orig_metrics['precision']}, R={orig_metrics['recall']}, F1={orig_metrics['f1_score']}, FPR={orig_metrics['false_positive_rate']}")
    
    # 2. Continue fine-tuning
    updated_model = orig_model
    train_ds = ActionSequenceDataset(train_seqs, vocab)
    val_ds = ActionSequenceDataset(val_seqs, vocab)
    train_loader = DataLoader(train_ds, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=16, shuffle=False)
    
    optimizer = torch.optim.AdamW(updated_model.parameters(), lr=5e-5, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss()
    
    logger.info("Starting BiLSTM continued training (3 epochs, lr=5e-5)...")
    for epoch in range(1, 4):
        updated_model.train()
        train_loss = 0.0
        for x, y in train_loader:
            x, y = x.to(DEVICE), y.to(DEVICE)
            optimizer.zero_grad()
            logits = updated_model(x)
            loss = criterion(logits, y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item()
            
        updated_model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for x, y in val_loader:
                x, y = x.to(DEVICE), y.to(DEVICE)
                logits = updated_model(x)
                val_loss += criterion(logits, y).item()
                
        logger.info(f"BiLSTM Epoch {epoch}/3 -> Train Loss: {train_loss/len(train_loader):.4f} | Val Loss: {val_loss/len(val_loader):.4f}")
        
    # 3. Save UPDATED checkpoint
    os.makedirs(os.path.join(WEIGHTS_DIR, "updated"), exist_ok=True)
    torch.save(updated_model.state_dict(), UPDATED_CHECKPOINT)
    logger.info(f"Saved UPDATED BiLSTM checkpoint to: {UPDATED_CHECKPOINT}")
    
    # 4. Evaluate UPDATED model on exact same test set
    updated_metrics = evaluate_bilstm(updated_model, test_loader)
    logger.info(f"UPDATED BiLSTM Test:   P={updated_metrics['precision']}, R={updated_metrics['recall']}, F1={updated_metrics['f1_score']}, FPR={updated_metrics['false_positive_rate']}")
    
    # Comparison report
    comp = {
        "model_name": "BiLSTM",
        "sample_count": len(test_seqs),
        "original_metrics": orig_metrics,
        "updated_metrics": updated_metrics,
        "f1_delta": round(updated_metrics["f1_score"] - orig_metrics["f1_score"], 4),
        "recall_delta": round(updated_metrics["recall"] - orig_metrics["recall"], 4)
    }
    with open(os.path.join(WEIGHTS_DIR, "updated", "bilstm_comparison.json"), "w", encoding="utf-8") as f:
        json.dump(comp, f, indent=2)

if __name__ == "__main__":
    main()
