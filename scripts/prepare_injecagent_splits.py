"""
AgentShieldAI — Prepare Balanced InjecAgent Continuation Dataset.
Combines:
- InjecAgent prompt injections (direct and indirect)
- Benign operational agent prompts (balanced replay to prevent catastrophic forgetting)
Creates clean, zero-leakage Train (70%), Val (15%), and Test (15%) splits.
"""

import os
import json
import random
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prepare_injecagent")

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "app", "security", "data"))
INJEC_DIR = os.path.join(DATA_DIR, "injecagent")

def main():
    random.seed(42)
    
    dh_file = os.path.join(INJEC_DIR, "test_cases_dh_base.json")
    ds_file = os.path.join(INJEC_DIR, "test_cases_ds_base.json")
    orig_train_file = os.path.join(DATA_DIR, "distilbert_train.json")
    
    threats = []
    seen_threats = set()
    
    # 1. Extract InjecAgent attack cases
    for filepath in [dh_file, ds_file]:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    tr = item.get("Tool Response", "").strip()
                    if len(tr) >= 15 and tr not in seen_threats:
                        seen_threats.add(tr)
                        threats.append({
                            "text": tr,
                            "label": 1,
                            "category": "indirect_prompt_injection",
                            "source": "injecagent"
                        })
                    ai = item.get("Attacker Instruction", "").strip()
                    if len(ai) >= 15 and ai not in seen_threats:
                        seen_threats.add(ai)
                        threats.append({
                            "text": ai,
                            "label": 1,
                            "category": "direct_attack_instruction",
                            "source": "injecagent"
                        })

    # 2. Extract balanced benign samples from original training set (replay buffer)
    benigns = []
    seen_benigns = set()
    if os.path.exists(orig_train_file):
        with open(orig_train_file, "r", encoding="utf-8") as f:
            orig_data = json.load(f)
            for item in orig_data:
                if item.get("label") == 0:
                    t = item.get("text", "").strip()
                    if t and t not in seen_benigns:
                        seen_benigns.add(t)
                        benigns.append({
                            "text": t,
                            "label": 0,
                            "category": "benign_operational_prompt",
                            "source": "agent_operational_replay"
                        })

    random.shuffle(threats)
    random.shuffle(benigns)

    # Balance 1:1 ratio
    target_count = min(len(threats), len(benigns))
    selected_threats = threats[:target_count]
    selected_benigns = benigns[:target_count]

    n_train = int(target_count * 0.70)
    n_val = int(target_count * 0.15)

    train_set = selected_threats[:n_train] + selected_benigns[:n_train]
    val_set = selected_threats[n_train:n_train + n_val] + selected_benigns[n_train:n_train + n_val]
    test_set = selected_threats[n_train + n_val:] + selected_benigns[n_train + n_val:]

    random.shuffle(train_set)
    random.shuffle(val_set)
    random.shuffle(test_set)

    os.makedirs(INJEC_DIR, exist_ok=True)
    train_path = os.path.join(INJEC_DIR, "injecagent_train.json")
    val_path = os.path.join(INJEC_DIR, "injecagent_val.json")
    test_path = os.path.join(INJEC_DIR, "injecagent_test.json")

    with open(train_path, "w", encoding="utf-8") as f: json.dump(train_set, f, indent=2)
    with open(val_path, "w", encoding="utf-8") as f: json.dump(val_set, f, indent=2)
    with open(test_path, "w", encoding="utf-8") as f: json.dump(test_set, f, indent=2)

    logger.info("=" * 60)
    logger.info(f"Balanced InjecAgent Splits Generated (1:1 Ratio)")
    logger.info(f" - Total Samples: {len(train_set) + len(val_set) + len(test_set)}")
    logger.info(f" - Train Set:     {len(train_set)} (Threats: {n_train}, Benign: {n_train})")
    logger.info(f" - Val Set:       {len(val_set)} (Threats: {n_val}, Benign: {n_val})")
    logger.info(f" - Test Set:      {len(test_set)} (Threats: {len(test_set)//2}, Benign: {len(test_set)//2})")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
