"""
AgentShieldAI — Step 3: Continued Fine-Tuning for DistilBERT on InjecAgent.
Loads existing checkpoint, preserves architecture and tokenizer, fine-tunes with conservative
learning rate, and saves updated checkpoint separately in weights/updated/distilbert/.
Evaluates original vs. updated on independent test sets.
"""

import os
import sys
import json
import time
import argparse
import logging
from typing import Dict, Any, List, Tuple

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("continue_train_distilbert")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEIGHTS_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "models", "weights")
ORIG_MODEL_DIR = os.path.join(WEIGHTS_DIR, "original_backup", "distilbert")
if not os.path.exists(ORIG_MODEL_DIR):
    ORIG_MODEL_DIR = os.path.join(WEIGHTS_DIR, "distilbert")

UPDATED_MODEL_DIR = os.path.join(WEIGHTS_DIR, "updated", "distilbert")
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")
INJEC_DIR = os.path.join(DATA_DIR, "injecagent")

class PromptDataset(Dataset):
    def __init__(self, data: List[Dict[str, Any]], tokenizer, max_length: int = 128):
        self.texts = [d["text"] for d in data]
        self.labels = [int(d["label"]) for d in data]
        self.encodings = tokenizer(
            self.texts,
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors="pt"
        )

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {key: val[idx] for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item

def evaluate_model(model, tokenizer, test_data: List[Dict[str, Any]], device: torch.device) -> Dict[str, Any]:
    model.eval()
    test_ds = PromptDataset(test_data, tokenizer)
    loader = DataLoader(test_ds, batch_size=32, shuffle=False)
    
    all_preds = []
    all_labels = []
    latencies = []
    
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            
            t0 = time.perf_counter()
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            latencies.append((time.perf_counter() - t0) * 1000 / len(labels))
            
            logits = outputs.logits
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(labels.cpu().numpy())
            
    p = float(precision_score(all_labels, all_preds, zero_division=0))
    r = float(recall_score(all_labels, all_preds, zero_division=0))
    f1 = float(f1_score(all_labels, all_preds, zero_division=0))
    cm = confusion_matrix(all_labels, all_preds).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    avg_latency = float(sum(latencies) / len(latencies)) if latencies else 0.0
    
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "avg_latency_ms": round(avg_latency, 3),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "sample_count": len(all_labels)
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--lr", type=float, default=1e-5)
    parser.add_argument("--batch_size", type=int, default=16)
    parser.add_argument("--subsample", type=int, default=600, help="Subsample train set for fast local CPU training")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")
    
    # 1. Load InjecAgent dataset splits
    train_file = os.path.join(INJEC_DIR, "injecagent_train.json")
    val_file = os.path.join(INJEC_DIR, "injecagent_val.json")
    test_file = os.path.join(INJEC_DIR, "injecagent_test.json")
    orig_test_file = os.path.join(DATA_DIR, "distilbert_test.json")
    
    with open(train_file, "r", encoding="utf-8") as f: train_data = json.load(f)
    with open(val_file, "r", encoding="utf-8") as f: val_data = json.load(f)
    with open(test_file, "r", encoding="utf-8") as f: test_data = json.load(f)
    with open(orig_test_file, "r", encoding="utf-8") as f: orig_test_data = json.load(f)
    
    if args.subsample and len(train_data) > args.subsample:
        import random
        random.seed(42)
        train_data = random.sample(train_data, args.subsample)
        logger.info(f"Subsampled continuation training set to {len(train_data)} balanced samples")

    # 2. Load ORIGINAL DistilBERT checkpoint and evaluate baseline
    logger.info(f"Loading ORIGINAL DistilBERT checkpoint from: {ORIG_MODEL_DIR}")
    tokenizer = AutoTokenizer.from_pretrained(ORIG_MODEL_DIR)
    orig_model = AutoModelForSequenceClassification.from_pretrained(ORIG_MODEL_DIR).to(device)
    
    logger.info("Evaluating ORIGINAL model on InjecAgent test set...")
    orig_injec_metrics = evaluate_model(orig_model, tokenizer, test_data, device)
    logger.info(f"ORIGINAL on InjecAgent Test: P={orig_injec_metrics['precision']}, R={orig_injec_metrics['recall']}, F1={orig_injec_metrics['f1_score']}, FPR={orig_injec_metrics['false_positive_rate']}")
    
    logger.info("Evaluating ORIGINAL model on Original test set (catastrophic forgetting baseline)...")
    orig_orig_metrics = evaluate_model(orig_model, tokenizer, orig_test_data, device)
    logger.info(f"ORIGINAL on Original Test:   P={orig_orig_metrics['precision']}, R={orig_orig_metrics['recall']}, F1={orig_orig_metrics['f1_score']}, FPR={orig_orig_metrics['false_positive_rate']}")

    # 3. CONTINUE FINE-TUNING with conservative learning rate
    logger.info("=" * 60)
    logger.info(f"Starting Continued Training: {args.epochs} epochs, lr={args.lr}, batch_size={args.batch_size}")
    logger.info("=" * 60)
    
    # Train using the model instance initialized from original weights
    updated_model = orig_model
    updated_model.train()
    
    train_ds = PromptDataset(train_data, tokenizer)
    val_ds = PromptDataset(val_data, tokenizer)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False)
    
    optimizer = torch.optim.AdamW(updated_model.parameters(), lr=args.lr, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss()
    
    best_val_loss = float("inf")
    
    for epoch in range(1, args.epochs + 1):
        total_train_loss = 0.0
        updated_model.train()
        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            
            outputs = updated_model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(updated_model.parameters(), max_norm=1.0)
            optimizer.step()
            total_train_loss += loss.item()
            
        avg_train_loss = total_train_loss / len(train_loader)
        
        # Validation
        updated_model.eval()
        total_val_loss = 0.0
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["labels"].to(device)
                outputs = updated_model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                total_val_loss += outputs.loss.item()
                
        avg_val_loss = total_val_loss / len(val_loader)
        logger.info(f"Epoch {epoch}/{args.epochs} -> Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f}")

    # 4. Save UPDATED model separately
    os.makedirs(UPDATED_MODEL_DIR, exist_ok=True)
    logger.info(f"Saving UPDATED model checkpoint to: {UPDATED_MODEL_DIR}")
    updated_model.save_pretrained(UPDATED_MODEL_DIR)
    tokenizer.save_pretrained(UPDATED_MODEL_DIR)

    # 5. Evaluate UPDATED model on all test sets
    logger.info("Evaluating UPDATED model on InjecAgent test set...")
    updated_injec_metrics = evaluate_model(updated_model, tokenizer, test_data, device)
    logger.info(f"UPDATED on InjecAgent Test:  P={updated_injec_metrics['precision']}, R={updated_injec_metrics['recall']}, F1={updated_injec_metrics['f1_score']}, FPR={updated_injec_metrics['false_positive_rate']}")

    logger.info("Evaluating UPDATED model on Original test set...")
    updated_orig_metrics = evaluate_model(updated_model, tokenizer, orig_test_data, device)
    logger.info(f"UPDATED on Original Test:    P={updated_orig_metrics['precision']}, R={updated_orig_metrics['recall']}, F1={updated_orig_metrics['f1_score']}, FPR={updated_orig_metrics['false_positive_rate']}")

    # 6. Generate Comparison Output
    comparison = {
        "model_name": "DistilBERT",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "original_checkpoint_path": ORIG_MODEL_DIR,
        "updated_checkpoint_path": UPDATED_MODEL_DIR,
        "injecagent_independent_test": {
            "sample_count": len(test_data),
            "original_metrics": orig_injec_metrics,
            "updated_metrics": updated_injec_metrics,
            "f1_delta": round(updated_injec_metrics["f1_score"] - orig_injec_metrics["f1_score"], 4),
            "recall_delta": round(updated_injec_metrics["recall"] - orig_injec_metrics["recall"], 4)
        },
        "original_benchmark_test": {
            "sample_count": len(orig_test_data),
            "original_metrics": orig_orig_metrics,
            "updated_metrics": updated_orig_metrics,
            "f1_delta": round(updated_orig_metrics["f1_score"] - orig_orig_metrics["f1_score"], 4),
            "catastrophic_forgetting_detected": bool(updated_orig_metrics["f1_score"] < orig_orig_metrics["f1_score"] - 0.05)
        }
    }
    
    out_comparison = os.path.join(WEIGHTS_DIR, "updated", "distilbert_comparison.json")
    with open(out_comparison, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)
    logger.info(f"Saved DistilBERT comparison report to: {out_comparison}")

    print("\n" + "=" * 70)
    print("   DISTILBERT: ORIGINAL vs. UPDATED MODEL COMPARISON")
    print("=" * 70)
    print(f"InjecAgent Test Set (N={len(test_data)}):")
    print(f" - Precision: Original {orig_injec_metrics['precision']} -> Updated {updated_injec_metrics['precision']}")
    print(f" - Recall:    Original {orig_injec_metrics['recall']} -> Updated {updated_injec_metrics['recall']}")
    print(f" - F1-Score:  Original {orig_injec_metrics['f1_score']} -> Updated {updated_injec_metrics['f1_score']}")
    print(f" - FPR:       Original {orig_injec_metrics['false_positive_rate']} -> Updated {updated_injec_metrics['false_positive_rate']}")
    print("-" * 70)
    print(f"Original 5K Test Set (N={len(orig_test_data)}):")
    print(f" - F1-Score:  Original {orig_orig_metrics['f1_score']} -> Updated {updated_orig_metrics['f1_score']}")
    print("=" * 70)

if __name__ == "__main__":
    main()
