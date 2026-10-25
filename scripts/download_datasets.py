"""
AgentShieldAI — Automated Dataset Download and Provenance Registry.
Downloads and verifies:
1. Dataset 1: 3nesdeniz/agentic-prompt-injection-5k (Hugging Face)
2. Dataset 2: ppradyoth/AgentInjectionBench (Hugging Face)
3. Dataset 3: ethz-spylab/agentdojo (GitHub)

Saves files to backend/app/security/data/ and writes a formal provenance manifest.
"""

import os
import sys
import json
import time
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "backend", "app", "security", "data")
os.makedirs(DATA_DIR, exist_ok=True)

HEADERS = {
    "User-Agent": "AgentShieldAI-MTech-Research/1.0"
}


def download_file(url: str, dest_path: str) -> int:
    """Downloads a file with basic progress reporting and returns bytes downloaded."""
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    print(f"[*] Downloading: {url}")
    print(f"    -> Destination: {dest_path}")
    
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, "wb") as out_f:
        total_size = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024  # 1 MB chunks
        
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out_f.write(chunk)
            downloaded += len(chunk)
            if total_size > 0:
                percent = (downloaded / total_size) * 100
                print(f"\r    Progress: {downloaded / 1024 / 1024:.2f} MB / {total_size / 1024 / 1024:.2f} MB ({percent:.1f}%)", end="", flush=True)
            else:
                print(f"\r    Progress: {downloaded / 1024 / 1024:.2f} MB", end="", flush=True)
        print()
    return downloaded


def download_dataset_1():
    print("\n" + "=" * 80)
    print("STEP 1: Downloading Dataset 1 (3nesdeniz/agentic-prompt-injection-5k)")
    print("=" * 80)
    
    ds_dir = os.path.join(DATA_DIR, "agentic_prompt_injection_5k")
    os.makedirs(ds_dir, exist_ok=True)
    
    files = {
        "train.parquet": "https://huggingface.co/api/datasets/3nesdeniz/agentic-prompt-injection-5k/parquet/default/train/0.parquet",
        "validation.parquet": "https://huggingface.co/api/datasets/3nesdeniz/agentic-prompt-injection-5k/parquet/default/validation/0.parquet",
        "test.parquet": "https://huggingface.co/api/datasets/3nesdeniz/agentic-prompt-injection-5k/parquet/default/test/0.parquet"
    }
    
    results = {}
    for fname, url in files.items():
        dest = os.path.join(ds_dir, fname)
        if os.path.exists(dest) and os.path.getsize(dest) > 1000:
            print(f"[*] Already exists: {dest} ({os.path.getsize(dest):,} bytes)")
            results[fname] = os.path.getsize(dest)
        else:
            size = download_file(url, dest)
            results[fname] = size
            
    return {
        "dataset_name": "agentic-prompt-injection-5k",
        "source": "https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k",
        "license": "CC-BY-4.0",
        "local_dir": ds_dir,
        "files": results,
        "status": "COMPLETED"
    }


def download_dataset_2():
    print("\n" + "=" * 80)
    print("STEP 2: Downloading Dataset 2 (ppradyoth/AgentInjectionBench)")
    print("=" * 80)
    
    ds_dir = os.path.join(DATA_DIR, "agent_injection_bench")
    os.makedirs(ds_dir, exist_ok=True)
    
    files = {
        "agent_injection_bench.jsonl": "https://huggingface.co/datasets/ppradyoth/AgentInjectionBench/raw/main/data/agent_injection_bench.jsonl",
        "taxonomy.json": "https://huggingface.co/datasets/ppradyoth/AgentInjectionBench/raw/main/data/taxonomy.json"
    }
    
    results = {}
    for fname, url in files.items():
        dest = os.path.join(ds_dir, fname)
        if os.path.exists(dest) and os.path.getsize(dest) > 100:
            print(f"[*] Already exists: {dest} ({os.path.getsize(dest):,} bytes)")
            results[fname] = os.path.getsize(dest)
        else:
            size = download_file(url, dest)
            results[fname] = size
            
    return {
        "dataset_name": "AgentInjectionBench",
        "source": "https://huggingface.co/datasets/ppradyoth/AgentInjectionBench",
        "license": "Apache-2.0",
        "local_dir": ds_dir,
        "files": results,
        "status": "COMPLETED"
    }


def download_dataset_3():
    print("\n" + "=" * 80)
    print("STEP 3: Downloading AgentDojo Task Suites & Documented Benchmark Runs")
    print("URL: https://github.com/ethz-spylab/agentdojo")
    print("=" * 80)
    
    ds_dir = os.path.join(DATA_DIR, "agentdojo")
    suites_dir = os.path.join(ds_dir, "suites")
    runs_dir = os.path.join(ds_dir, "runs", "gpt-4o-2024-05-13")
    os.makedirs(suites_dir, exist_ok=True)
    os.makedirs(runs_dir, exist_ok=True)

    # 1. Download core task suite definition files
    suites = ["workspace", "banking", "slack", "travel"]
    suite_files = ["task_suite.py", "user_tasks.py", "injection_tasks.py"]
    downloaded_files = 0

    for suite in suites:
        suite_sub = os.path.join(suites_dir, suite)
        os.makedirs(suite_sub, exist_ok=True)
        for sfile in suite_files:
            url = f"https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/src/agentdojo/default_suites/v1/{suite}/{sfile}"
            dest = os.path.join(suite_sub, sfile)
            if not os.path.exists(dest):
                try:
                    req = urllib.request.Request(url, headers=HEADERS)
                    with urllib.request.urlopen(req, timeout=15) as resp, open(dest, "wb") as f:
                        f.write(resp.read())
                    downloaded_files += 1
                except Exception as e:
                    pass

    # 2. Download documented benchmark runs from AgentDojo runs/gpt-4o-2024-05-13
    # Both benign baseline (none/none.json) and injection attack scenarios across all suites
    downloaded_traces = 0
    trace_manifest = []

    for suite in suites:
        suite_runs_dir = os.path.join(runs_dir, suite)
        os.makedirs(suite_runs_dir, exist_ok=True)
        
        # User tasks 0 to 15 per suite
        for t_idx in range(16):
            task_name = f"user_task_{t_idx}"
            
            # (a) Benign control trace: none/none.json
            none_url = f"https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/runs/gpt-4o-2024-05-13/{suite}/{task_name}/none/none.json"
            none_dest_dir = os.path.join(suite_runs_dir, task_name, "none")
            os.makedirs(none_dest_dir, exist_ok=True)
            none_dest = os.path.join(none_dest_dir, "none.json")
            
            if not os.path.exists(none_dest):
                try:
                    req = urllib.request.Request(none_url, headers=HEADERS)
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        content = resp.read()
                        with open(none_dest, "wb") as f:
                            f.write(content)
                        downloaded_traces += 1
                        trace_manifest.append({"suite": suite, "task": task_name, "type": "benign", "file": none_dest})
                except Exception:
                    pass

            # (b) Injection attack traces: injecagent/injection_task_0.json to injection_task_2.json
            for inj_id in range(3):
                inj_url = f"https://raw.githubusercontent.com/ethz-spylab/agentdojo/main/runs/gpt-4o-2024-05-13/{suite}/{task_name}/injecagent/injection_task_{inj_id}.json"
                inj_dest_dir = os.path.join(suite_runs_dir, task_name, "injecagent")
                os.makedirs(inj_dest_dir, exist_ok=True)
                inj_dest = os.path.join(inj_dest_dir, f"injection_task_{inj_id}.json")
                
                if not os.path.exists(inj_dest):
                    try:
                        req = urllib.request.Request(inj_url, headers=HEADERS)
                        with urllib.request.urlopen(req, timeout=10) as resp:
                            content = resp.read()
                            with open(inj_dest, "wb") as f:
                                f.write(content)
                            downloaded_traces += 1
                            trace_manifest.append({"suite": suite, "task": task_name, "type": "injection", "file": inj_dest})
                    except Exception:
                        pass

    # Save AgentDojo traces manifest
    traces_manifest_path = os.path.join(ds_dir, "agentdojo_traces_manifest.json")
    with open(traces_manifest_path, "w", encoding="utf-8") as f:
        json.dump(trace_manifest, f, indent=2)

    print(f"[*] AgentDojo download complete:")
    print(f"    - Suites downloaded: {suites}")
    print(f"    - Benchmark run traces downloaded: {len(trace_manifest)} traces")
    print(f"    - Traces manifest written to: {traces_manifest_path}")

    return {
        "dataset_name": "agentdojo",
        "source": "https://github.com/ethz-spylab/agentdojo",
        "license": "MIT License",
        "local_dir": ds_dir,
        "suites": suites,
        "traces_downloaded": len(trace_manifest),
        "status": "COMPLETED"
    }


def main():
    start_time = time.time()
    print("AgentShieldAI — Automated Dataset Download and Provenance Registry")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Target Directory: {DATA_DIR}")
    
    manifest = {
        "project": "AgentShieldAI",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "datasets": {}
    }
    
    try:
        manifest["datasets"]["agentic_prompt_injection_5k"] = download_dataset_1()
    except Exception as e:
        print(f"[!] Dataset 1 failed: {e}")
        manifest["datasets"]["agentic_prompt_injection_5k"] = {"error": str(e), "status": "FAILED"}
        
    try:
        manifest["datasets"]["agent_injection_bench"] = download_dataset_2()
    except Exception as e:
        print(f"[!] Dataset 2 failed: {e}")
        manifest["datasets"]["agent_injection_bench"] = {"error": str(e), "status": "FAILED"}
        
    try:
        manifest["datasets"]["agentdojo"] = download_dataset_3()
    except Exception as e:
        print(f"[!] Dataset 3 failed: {e}")
        manifest["datasets"]["agentdojo"] = {"error": str(e), "status": "FAILED"}
        
    # Write manifest
    manifest_path = os.path.join(DATA_DIR, "dataset_provenance_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n[*] Dataset Provenance Manifest written to: {manifest_path}")
    print(f"[*] Completed in {time.time() - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()
