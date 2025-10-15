#!/usr/bin/env python3
"""
Cylix Mock Prototype - CentOS
Safe, non-destructive mock of scanning + hardening workflow for CentOS.
Simulates Timeshift-style snapshots for rollback.
All files live in workspace (~/.cylix_mock_centos) to avoid touching real system configs.
"""

import argparse
import json
import os
import platform
import random
import shutil
import socket
import time
from datetime import datetime

WORKDIR = os.path.expanduser("~/.cylix_mock_centos")
SNAPSHOTDIR = os.path.join(WORKDIR, "snapshots")  # Timeshift-like snapshots
REPORTDIR = os.path.join(WORKDIR, "reports")
SEED = 123
random.seed(SEED)

# Mock vulnerabilities database
MOCK_VULNS = [
    {"id": "CYLX-CENTOS-2025-01", "component": "ssh", "severity": "High", "desc": "Weak SSH ciphers enabled"},
    {"id": "CYLX-CENTOS-2024-02", "component": "firewalld", "severity": "Medium", "desc": "Default firewalld rules allow all"},
    {"id": "CYLX-CENTOS-2023-03", "component": "httpd", "severity": "Low", "desc": "Server tokens reveal version info"},
]

def ensure_dirs():
    for d in (WORKDIR, SNAPSHOTDIR, REPORTDIR):
        os.makedirs(d, exist_ok=True)

def now_ts():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def human_time(s):
    return f"{s:.1f}s"

def simulate_delay(min_s=0.2, max_s=0.8):
    t = random.uniform(min_s, max_s)
    time.sleep(t)
    return t

def baseline_scan():
    ensure_dirs()
    start = time.time()
    print("[*] Running baseline scan (mock) for CentOS...")
    simulate_delay()
    info = {
        "host": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "platform": platform.platform(),
        "python_version": platform.python_version()
    }

    # Mock installed components and versions
    components = {
        "ssh": random.choice(["OpenSSH_8.0p1", "OpenSSH_8.9p1"]),
        "firewalld": random.choice(["active", "inactive"]),
        "httpd": random.choice(["2.4.37", "2.4.54"])
    }

    # Common CentOS ports (SSH 22, HTTP 80, HTTPS 443)
    open_ports = []
    for p in [22, 80, 443]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect(("127.0.0.1", p))
            open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()

    # Simulated services
    services = [
        {"name": "ssh", "status": "running" if components["ssh"].startswith("OpenSSH") else "stopped"},
        {"name": "firewalld", "status": components["firewalld"]},
        {"name": "httpd", "status": "running" if random.random() > 0.4 else "stopped"}
    ]

    baseline = {
        "timestamp": now_ts(),
        "summary": info,
        "components": components,
        "open_ports": open_ports,
        "services": services
    }

    path = os.path.join(WORKDIR, f"baseline_{baseline['timestamp']}.json")
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)

    elapsed = time.time() - start
    print(f"[+] Baseline saved to {path} ({human_time(elapsed)})")
    return baseline, elapsed

def detect_vulns(baseline):
    start = time.time()
    print("[*] Detecting mock vulnerabilities...")
    simulate_delay()
    detected = []

    comps = baseline["components"]
    # Simple rules
    if "ssh" in comps and random.random() > 0.3:
        detected.append(MOCK_VULNS[0])
    if "firewalld" in comps and comps["firewalld"] != "active":
        detected.append(MOCK_VULNS[1])
    if "httpd" in comps and random.random() > 0.5:
        detected.append(MOCK_VULNS[2])

    print(f"[+] Detected {len(detected)} issues (mock).")
    elapsed = time.time() - start
    return detected, elapsed

def create_snapshot():
    start = time.time()
    ensure_dirs()
    stamp = now_ts()
    snap_dir = os.path.join(SNAPSHOTDIR, f"timeshift_snapshot_{stamp}")
    os.makedirs(snap_dir, exist_ok=True)
    # Create mock config files
    with open(os.path.join(snap_dir, "ssh_config"), "w") as f:
        f.write("PermitRootLogin no\nCiphers aes256-gcm@openssh.com\n")
    with open(os.path.join(snap_dir, "firewalld_rules.conf"), "w") as f:
        f.write("default zone: public\nallow ports: 22,80,443\n")
    elapsed = time.time() - start
    print(f"[+] Timeshift-like snapshot created at {snap_dir} ({human_time(elapsed)})")
    return snap_dir, elapsed

def perform_hardening(detected):
    start = time.time()
    print("[*] Performing mock hardening steps for CentOS...")
    actions = []
    for d in detected:
        if d["component"] == "ssh":
            actions.append("Enforce strong SSH ciphers (simulated)")
        elif d["component"] == "firewalld":
            actions.append("Enable firewalld with default block policy (simulated)")
        elif d["component"] == "httpd":
            actions.append("Hide server tokens in HTTP headers (simulated)")

    actions += ["Ensure automatic updates enabled (simulated)", "Disable unnecessary services (simulated)"]

    change_file = os.path.join(WORKDIR, f"centos_changes_{now_ts()}.json")
    with open(change_file, "w") as f:
        json.dump({"timestamp": now_ts(), "actions": actions, "rollback_possible": True}, f, indent=2)

    elapsed = time.time() - start
    baseline_score = random.randint(40, 65)
    post_score = min(100, baseline_score + random.randint(25, 50))
    stability = round(random.uniform(0.92, 0.995), 3)
    compliance_improvement = round((post_score - baseline_score) / baseline_score * 100, 1)

    summary = {
        "baseline_score": baseline_score,
        "post_hardening_score": post_score,
        "hardening_time_sec": round(elapsed, 2),
        "system_stability_index": stability,
        "compliance_improvement_pct": compliance_improvement,
        "changes_file": change_file
    }

    print(f"[+] Hardening actions recorded to {change_file}")
    return summary, elapsed

def rollback_last_snapshot():
    print("[*] Attempting mock rollback using last Timeshift snapshot...")
    snapshots = sorted([d for d in os.listdir(SNAPSHOTDIR) if d.startswith("timeshift_snapshot_")]) if os.path.exists(SNAPSHOTDIR) else []
    changes = sorted([f for f in os.listdir(WORKDIR) if f.startswith("centos_changes_")]) if os.path.exists(WORKDIR) else []
    if not snapshots or not changes:
        print("[!] No snapshots or change records found.")
        return False, None
    last_snap = snapshots[-1]
    last_change = changes[-1]
    success = random.random() > 0.05
    simulate_delay(0.5, 1.2)
    if success:
        print(f"[+] Rollback simulated: SUCCESS (restored {last_snap})")
    else:
        print("[!] Rollback simulated: FAILED")
    return success, {"snapshot": last_snap, "change_record": last_change}

def write_report(baseline, detected, hard_summary, scan_time, detect_time):
    stamp = now_ts()
    report = {
        "system_id": f"CYLX-CENTOS-MOCK-{stamp}",
        "baseline": baseline,
        "detected_vulns": detected,
        "hardening_summary": hard_summary,
        "timings": {"scan_sec": round(scan_time, 2), "detect_sec": round(detect_time, 2)}
    }
    rpt_path = os.path.join(REPORTDIR, f"report_{stamp}.json")
    with open(rpt_path, "w") as f:
        json.dump(report, f, indent=2)
    # CSV summary
    csv_path = os.path.join(REPORTDIR, f"summary_{stamp}.csv")
    with open(csv_path, "w") as f:
        f.write("system_id,baseline_score,post_score,stability,compliance_improvement\n")
        b = hard_summary
        f.write(f"{report['system_id']},{b['baseline_score']},{b['post_hardening_score']},{b['system_stability_index']},{b['compliance_improvement_pct']}\n")
    print(f"[+] Report: {rpt_path}")
    print(f"[+] CSV summary: {csv_path}")
    return rpt_path, csv_path

def action_full():
    baseline, scan_time = baseline_scan()
    detected, detect_time = detect_vulns(baseline)
