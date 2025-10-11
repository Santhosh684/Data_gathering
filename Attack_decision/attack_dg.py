"""
generate_attack_dataset.py

Reads `master-data.json` (list of recon file items) and synthesizes
a dataset of payload-state rows suitable for training an Attack Decision AI.
Outputs:
  - attack_dataset.json  (list of records, JSON)
  - attack_dataset.csv   (tabular view for quick inspection)

Usage:
  python generate_attack_dataset.py
"""

import json
import random
import math
import csv
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------- CONFIG ----------------------
MASTER_FILE = "master-data.json"       # input (your generator output)
OUT_JSON    = "attack_dataset.json"    # output dataset JSON
OUT_CSV     = "attack_dataset.csv"     # output dataset CSV
NUM_ROWS    = 1000                     # how many synthetic payload states to generate
MIN_ITEMS   = 1                        # min recon items per payload state
MAX_ITEMS   = 8                        # max recon items per payload state
HIGH_IMPORTANCE_THRESHOLD = 0.7        # threshold to consider "high importance"
EVASION_PROB = 0.20                    # probability that evasion_flag = 1 (sandbox detected)
NOISE_FLIP_PROB = 0.03                 # small probability to randomly change the label (simulates noise)
RANDOM_SEED = 42

# Safe simulation labels (harmless)
SIM_LABELS = ["SIM_READ_FILE", "SIM_LIST_PROCESSES", "SIM_SCAN_PORT", "SIM_NO_OP"]

# ---------------------- HELPERS ----------------------
random.seed(RANDOM_SEED)

def load_master(master_path):
    p = Path(master_path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {master_path}")
    with p.open('r', encoding='utf-8') as fh:
        rows = json.load(fh)
    return rows

def synth_process_pool(n=50):
    """Generate synthetic process items (harmless metadata)."""
    procs = []
    common = ["svchost.exe", "explorer.exe", "backup_tool.exe", "db_service.exe", "antivirus_stub.exe",
              "monitor_tool.exe", "webserver.exe", "sync_agent.exe"]
    for i in range(n):
        name = random.choice(common)
        procs.append({
            "type": "process",
            "id": f"proc_{i:04d}",
            "name": f"{name.replace('.exe','')}_{i:03d}.exe",
            "importance": round(random.uniform(0.0, 1.0), 3),
            "scan_confidence": round(random.uniform(0.5, 0.99), 3)
        })
    return procs

def synth_port_pool(n=50):
    """Generate synthetic port items (harmless metadata)."""
    common_ports = [22, 80, 443, 3389, 3306, 445, 21]
    ports = []
    for i in range(n):
        port = random.choice(common_ports + [random.randint(1024, 65535)])
        ports.append({
            "type": "port",
            "id": f"port_{i:04d}",
            "port": port,
            "importance": round(random.uniform(0.0, 1.0), 3),
            "scan_confidence": round(random.uniform(0.5, 0.99), 3)
        })
    return ports

def file_item_to_recon_item(file_item):
    """Map file entries from master-data.json into a standardized recon item."""
    # ensure defaults if fields are missing
    importance = 0.5
    scan_conf = round(random.uniform(0.6, 0.99), 3)
    if "recon_signal" in file_item:
        importance = file_item["recon_signal"].get("importance", importance)
        scan_conf = file_item["recon_signal"].get("scan_confidence", scan_conf)
    else:
        # derive importance from sensitivity if available
        sens = file_item.get("sensitivity", "").lower()
        if sens == "high":
            importance = round(random.uniform(0.7, 1.0), 3)
        elif sens == "medium":
            importance = round(random.uniform(0.4, 0.7), 3)
        else:
            importance = round(random.uniform(0.0, 0.5), 3)

    return {
        "type": "file",
        "id": file_item.get("id") or f"file_{random.randint(0,999999):06d}",
        "name": file_item.get("filename") or file_item.get("file_path") or "unknown",
        "importance": float(importance),
        "scan_confidence": float(scan_conf),
        "filesize_kb": int(file_item.get("filesize_kb", 0))
    }

def aggregate_features(recon_items):
    """Compute aggregated, fixed-length features from a list of recon items."""
    importances = [r["importance"] for r in recon_items]
    max_importance = max(importances) if importances else 0.0
    avg_importance = sum(importances)/len(importances) if importances else 0.0
    count_high = sum(1 for v in importances if v >= HIGH_IMPORTANCE_THRESHOLD)
    # top item type (most common), if tie choose deterministic by sorted order
    types = [r["type"] for r in recon_items] or ["none"]
    type_counts = Counter(types)
    top_item_type = sorted(type_counts.items(), key=lambda x: (-x[1], x[0]))[0][0]
    # top item id (highest importance)
    top_item = max(recon_items, key=lambda r: (r["importance"], r.get("scan_confidence",0)))
    top_item_id = top_item.get("id")
    top_item_name = top_item.get("name")
    top_item_size = top_item.get("filesize_kb", 0)
    # simple resource proxies (sum/avg sizes)
    total_filesize = sum(r.get("filesize_kb",0) for r in recon_items if r["type"]=="file")
    avg_scan_conf = sum(r.get("scan_confidence",0) for r in recon_items) / len(recon_items) if recon_items else 0.0

    return {
        "max_importance_score": round(float(max_importance), 3),
        "avg_importance_score": round(float(avg_importance), 3),
        "count_high_importance_items": int(count_high),
        "top_item_type": top_item_type,
        "top_item_id": top_item_id,
        "top_item_name": top_item_name,
        "top_item_filesize_kb": int(top_item_size),
        "total_filesize_kb": int(total_filesize),
        "avg_scan_confidence": round(float(avg_scan_conf), 3)
    }

def rule_based_label(features, evasion_flag, last_action):
    """Deterministic (but simple) safe rules to pick a simulation label."""
    # Prefer high-importance file reads if present and not in sandbox
    if features["count_high_importance_items"] >= 1 and evasion_flag == 0:
        return "SIM_READ_FILE"
    # Prefer port scans if top item is a port and importance high, and not sandboxed
    if features["top_item_type"] == "port" and features["max_importance_score"] >= 0.6 and evasion_flag == 0:
        return "SIM_SCAN_PORT"
    # Prefer listing processes if a process type is prominent
    if features["top_item_type"] == "process" and features["max_importance_score"] >= 0.5:
        return "SIM_LIST_PROCESSES"
    # Default safe action
    return "SIM_NO_OP"

# ---------------------- MAIN GENERATION ----------------------
def generate_attack_dataset(master_rows, out_json=OUT_JSON, out_csv=OUT_CSV, num_rows=NUM_ROWS):
    # build pools
    file_pool = [file_item_to_recon_item(r) for r in master_rows]
    proc_pool = synth_process_pool(80)
    port_pool = synth_port_pool(80)

    # small helper to sample a recon session (mixing types)
    all_pool = file_pool + proc_pool + port_pool

    dataset = []
    for i in range(num_rows):
        # pick how many recon items this payload state will report
        k = random.randint(MIN_ITEMS, MAX_ITEMS)
        # sample (without replacement if pool big enough)
        session_items = random.sample(all_pool, k) if len(all_pool) >= k else [random.choice(all_pool) for _ in range(k)]

        # compute aggregates
        features = aggregate_features(session_items)

        # evasion signal (0 or 1)
        evasion_flag = 1 if random.random() < EVASION_PROB else 0

        # last_action chosen from safe set (encoded as string)
        last_action = random.choice(SIM_LABELS)

        # derive label via rule-based mapping
        label = rule_based_label(features, evasion_flag, last_action)

        # add small noise: flip label with small probability to simulate variance
        if random.random() < NOISE_FLIP_PROB:
            label = random.choice(SIM_LABELS)

        # build final row
        row = {
            "id": f"session_{i:05d}",
            "recon_count": k,
            "evasion_flag": evasion_flag,
            "last_action": last_action,
            "features": features,
            "label": label,
            # keep a small sample of the top items for traceability (IDs and types)
            "top_item_id": features["top_item_id"],
            "top_item_type": features["top_item_type"],
            "top_item_name": features["top_item_name"]
        }
        dataset.append(row)

    # write JSON
    with open(out_json, 'w', encoding='utf-8') as fh:
        json.dump(dataset, fh, indent=2, ensure_ascii=False)
    print(f"✅ Wrote {len(dataset)} rows to {out_json}")

    # write CSV (flatten key fields for quick model import)
    csv_fields = [
        "id",
        "recon_count",
        "evasion_flag",
        "last_action",
        "max_importance_score",
        "avg_importance_score",
        "count_high_importance_items",
        "top_item_type",
        "top_item_filesize_kb",
        "total_filesize_kb",
        "avg_scan_confidence",
        "label"
    ]
    with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=csv_fields)
        writer.writeheader()
        for r in dataset:
            f = r["features"]
            writer.writerow({
                "id": r["id"],
                "recon_count": r["recon_count"],
                "evasion_flag": r["evasion_flag"],
                "last_action": r["last_action"],
                "max_importance_score": f["max_importance_score"],
                "avg_importance_score": f["avg_importance_score"],
                "count_high_importance_items": f["count_high_importance_items"],
                "top_item_type": f["top_item_type"],
                "top_item_filesize_kb": f["top_item_filesize_kb"],
                "total_filesize_kb": f["total_filesize_kb"],
                "avg_scan_confidence": f["avg_scan_confidence"],
                "label": r["label"]
            })
    print(f"✅ Wrote tabular CSV to {out_csv}")

    return dataset

# ---------------------- RUN AS SCRIPT ----------------------
if __name__ == "__main__":
    master = load_master(MASTER_FILE)
    dataset = generate_attack_dataset(master, num_rows=NUM_ROWS)
