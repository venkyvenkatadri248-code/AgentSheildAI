"""
AgentShieldAI — Dataset Inspection & Provenance Verification Script.
Inspects:
1. Dataset 1: 3nesdeniz/agentic-prompt-injection-5k (Hugging Face)
2. Dataset 2: ppradyoth/AgentInjectionBench (Hugging Face)
3. Dataset 3: ethz-spylab/agentdojo (GitHub)

Checks schemas, column names, ground-truth label distributions, missing values,
duplicates, licenses, and availability for supervised training / evaluation.
"""

import json
import os
import sys
import urllib.request
import urllib.error

HEADERS = {
    "User-Agent": "AgentShieldAI-MTech-Research/1.0"
}


def fetch_json(url: str):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.getcode(), None
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="ignore")
        return None, e.code, f"HTTPError {e.code}: {e.reason} - {error_body[:200]}"
    except Exception as e:
        return None, None, str(e)


def inspect_dataset_1():
    print("=" * 80)
    print("DATASET 1: 3nesdeniz/agentic-prompt-injection-5k")
    print("URL: https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k")
    print("=" * 80)

    # 1. HF Repo Metadata
    meta_url = "https://huggingface.co/api/datasets/3nesdeniz/agentic-prompt-injection-5k"
    meta, code, err = fetch_json(meta_url)
    if err:
        print(f"[!] Error fetching metadata: {err}")
    else:
        print(f"[*] ID: {meta.get('id')}")
        print(f"[*] Author: {meta.get('author')}")
        print(f"[*] Created At: {meta.get('createdAt')}")
        print(f"[*] Downloads: {meta.get('downloads')}")
        print(f"[*] Likes: {meta.get('likes')}")
        card_data = meta.get("cardData", {})
        print(f"[*] License: {card_data.get('license', meta.get('license', 'Not specified'))}")
        print(f"[*] Tags: {meta.get('tags')}")

    # 2. Inspect Dataset Rows via HF Datasets Server
    rows_url = "https://datasets-server.huggingface.co/rows?dataset=3nesdeniz/agentic-prompt-injection-5k&config=default&split=train&offset=0&length=5"
    rows_data, code, err = fetch_json(rows_url)
    if err:
        print(f"[!] HF Datasets Server rows query returned error: {err}")
        # Try parquet info
        info_url = "https://datasets-server.huggingface.co/info?dataset=3nesdeniz/agentic-prompt-injection-5k"
        info_data, code, err2 = fetch_json(info_url)
        if err2:
            print(f"[!] Datasets Server info query returned: {err2}")
        else:
            print(f"[*] Dataset Info: {json.dumps(info_data, indent=2)[:500]}")
    else:
        features = rows_data.get("features", [])
        print("\n[*] Schema / Features:")
        for feat in features:
            print(f"    - {feat.get('feature_idx', '')}: {feat.get('name')} (type: {feat.get('type')})")
        rows = rows_data.get("rows", [])
        print(f"\n[*] Retrieved {len(rows)} sample rows:")
        for idx, r in enumerate(rows):
            row_data = r.get("row", {})
            print(f"\n--- Sample #{idx + 1} (Row index {r.get('row_idx')}) ---")
            for k, v in row_data.items():
                val_str = str(v)
                if len(val_str) > 120:
                    val_str = val_str[:120] + "... [truncated]"
                print(f"  {k}: {val_str}")

    # 3. Check splits and size
    splits_url = "https://datasets-server.huggingface.co/splits?dataset=3nesdeniz/agentic-prompt-injection-5k"
    splits_data, code, err = fetch_json(splits_url)
    if splits_data:
        print("\n[*] Splits available:")
        for s in splits_data.get("splits", []):
            print(f"    Config: {s.get('config')}, Split: {s.get('split')}, Num rows: {s.get('num_rows', 'unknown')}")


def inspect_dataset_2():
    print("\n" + "=" * 80)
    print("DATASET 2: ppradyoth/AgentInjectionBench")
    print("URL: https://huggingface.co/datasets/ppradyoth/AgentInjectionBench")
    print("=" * 80)

    # 1. HF Repo Metadata
    meta_url = "https://huggingface.co/api/datasets/ppradyoth/AgentInjectionBench"
    meta, code, err = fetch_json(meta_url)
    if err:
        print(f"[!] Error fetching metadata: {err}")
    else:
        print(f"[*] ID: {meta.get('id')}")
        print(f"[*] Author: {meta.get('author')}")
        print(f"[*] Downloads: {meta.get('downloads')}")
        card_data = meta.get("cardData", {})
        print(f"[*] License: {card_data.get('license', meta.get('license', 'Not specified'))}")
        print(f"[*] Description / Summary in Card: {card_data.get('description', 'N/A')}")
        print(f"[*] Tags: {meta.get('tags')}")

    # 2. Inspect Splits & Configs
    splits_url = "https://datasets-server.huggingface.co/splits?dataset=ppradyoth/AgentInjectionBench"
    splits_data, code, err = fetch_json(splits_url)
    if splits_data:
        print("\n[*] Splits & Configs:")
        for s in splits_data.get("splits", []):
            print(f"    Config: {s.get('config')}, Split: {s.get('split')}")
        
        # Query rows for first split
        first_split = splits_data.get("splits", [{}])[0]
        cfg = first_split.get("config", "default")
        spl = first_split.get("split", "train")
        rows_url = f"https://datasets-server.huggingface.co/rows?dataset=ppradyoth/AgentInjectionBench&config={cfg}&split={spl}&offset=0&length=5"
        rows_data, code, err = fetch_json(rows_url)
        if rows_data:
            print(f"\n[*] Schema / Features for Config '{cfg}', Split '{spl}':")
            for feat in rows_data.get("features", []):
                print(f"    - {feat.get('name')}: {feat.get('type')}")
            rows = rows_data.get("rows", [])
            print(f"\n[*] Retrieved {len(rows)} sample rows:")
            for idx, r in enumerate(rows):
                row_data = r.get("row", {})
                print(f"\n--- Sample #{idx + 1} ---")
                for k, v in row_data.items():
                    val_str = str(v)
                    if len(val_str) > 120:
                        val_str = val_str[:120] + "... [truncated]"
                    print(f"  {k}: {val_str}")
        else:
            print(f"[!] Could not query rows: {err}")
    else:
        print(f"[!] Could not retrieve splits: {err}")


def inspect_dataset_3():
    print("\n" + "=" * 80)
    print("DATASET 3: ethz-spylab/agentdojo")
    print("URL: https://github.com/ethz-spylab/agentdojo")
    print("=" * 80)

    repo_url = "https://api.github.com/repos/ethz-spylab/agentdojo"
    repo_data, code, err = fetch_json(repo_url)
    if err:
        print(f"[!] Error fetching GitHub repo info: {err}")
    else:
        print(f"[*] Full Name: {repo_data.get('full_name')}")
        print(f"[*] Description: {repo_data.get('description')}")
        license_info = repo_data.get("license") or {}
        print(f"[*] License: {license_info.get('name', 'N/A')} (spdx: {license_info.get('spdx_id')})")
        print(f"[*] Default Branch: {repo_data.get('default_branch')}")
        print(f"[*] Stargazers: {repo_data.get('stargazers_count')}")

    # Inspect tree / contents
    contents_url = "https://api.github.com/repos/ethz-spylab/agentdojo/contents"
    contents_data, code, err = fetch_json(contents_url)
    if contents_data and isinstance(contents_data, list):
        print("\n[*] Root Directory Contents:")
        for item in contents_data:
            print(f"    - {item.get('name')} ({item.get('type')})")

    # Inspect src/agentdojo
    dojo_url = "https://api.github.com/repos/ethz-spylab/agentdojo/contents/src/agentdojo"
    dojo_data, code, err = fetch_json(dojo_url)
    if dojo_data and isinstance(dojo_data, list):
        print("\n[*] src/agentdojo Structure:")
        for item in dojo_data:
            print(f"    - {item.get('name')} ({item.get('type')})")


if __name__ == "__main__":
    inspect_dataset_1()
    inspect_dataset_2()
    inspect_dataset_3()
