"""
AgentShieldAI — InjecAgent Dataset Downloader & Verifier.
Downloads the official InjecAgent dataset files from uiuc-kang-lab/InjecAgent on GitHub:
- attacker_cases_dh.jsonl (Direct Harm attacker instructions)
- attacker_cases_ds.jsonl (Data Stealing attacker instructions)
- user_cases.jsonl (Benign user instructions)
- test_cases_dh_base.json (Full multi-turn evaluation cases)
- test_cases_ds_base.json (Full data stealing evaluation cases)
"""

import os
import json
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("download_injecagent")

BASE_URL = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data"
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "app", "security", "data", "injecagent"))

FILES_TO_DOWNLOAD = [
    "attacker_cases_dh.jsonl",
    "attacker_cases_ds.jsonl",
    "user_cases.jsonl",
    "test_cases_dh_base.json",
    "test_cases_ds_base.json"
]

def download_file(filename: str) -> str:
    os.makedirs(TARGET_DIR, exist_ok=True)
    target_path = os.path.join(TARGET_DIR, filename)
    url = f"{BASE_URL}/{filename}"
    logger.info(f"Downloading {filename} from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AgentShieldAI-Downloader/1.0"})
        with urllib.request.urlopen(req) as resp, open(target_path, "wb") as f:
            f.write(resp.read())
        size_bytes = os.path.getsize(target_path)
        logger.info(f"Saved {filename} ({size_bytes} bytes) to {target_path}")
        return target_path
    except Exception as e:
        logger.error(f"Failed to download {filename}: {e}")
        return ""

def main():
    logger.info("=" * 60)
    logger.info("AgentShieldAI: Downloading InjecAgent Dataset")
    logger.info("=" * 60)
    
    downloaded = {}
    for fn in FILES_TO_DOWNLOAD:
        path = download_file(fn)
        if path and os.path.exists(path):
            downloaded[fn] = os.path.getsize(path)
            
    # Inspect downloaded files
    logger.info("\n--- InjecAgent Files Summary ---")
    for fn, sz in downloaded.items():
        logger.info(f" - {fn}: {sz} bytes")
        
    return downloaded

if __name__ == "__main__":
    main()
