#!/usr/bin/env python3
"""
Cylix Mock Prototype - macOS
Safe, non-destructive mock of scanning + hardening workflow for macOS.
All files live in workspace (~/.cylix_mock_macos) to avoid touching real system configs.
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

WORKDIR = os.path.expanduser("~/.cylix_mock_macos")
BACKUPDIR = os.path.join(WORKDIR, "backups")
REPORTDIR = os.path.join(WORKDIR, "reports")
SEED = 77
random.seed(SEED)

# Mock vulnerabilities database
MOCK_VULNS = [
    {"id": "CYLX-MAC-2025-01", "component": "ssh", "severity": "High", "desc": "Weak SSH ciphers enabled"},
    {"id": "CYLX-MAC-2024-02", "component": "apache", "severity": "Medium", "desc": "Default HTTP headers reveal server info"},
    {"id": "CYLX-MAC-2023-03", "component": "firewall", "severity": "Low", "desc": "pf firewall default rules allow all incoming"},
]

def ensure_dirs():
    for d in (WORKDIR, BACKUPDIR, REPORTDIR):
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
    print("[*] Running baseline scan (mock) for macOS...")
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
        "ssh": random.choice(["OpenSSH_8.1p1", "OpenSSH_8.9p1"]),
        "apache": random.choice(["2.4.46", "2.4.54"]),
        "pf": random.choice(["enabled", "disabled"])
    }

    # Common macOS ports (SSH 22, HTTP 80, HTTPS 443)
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
        {"name": "apache", "status": "running" if random.random() > 0.4 else "stopped"},
        {"name": "pf firewall", "status": components["pf"]}
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
        detected.append({"id": "CYLX-MAC-2025-01", "component": "ssh", "severity": "High", "desc": "Weak SSH ciphers enabled (mock)"})
    if "apache" in comps and random.random() > 0.5:
        detected.append({"id": "CYLX-MAC-2024-02", "component": "apache", "severity": "Medium", "desc": "Default HTTP headers (mock)"})
    if comps.get("pf") == "disabled":
        detected.append({"id": "CYLX-MAC-2023-03", "component": "firewall", "severity": "Low", "desc": "PF firewall disabled (mock)"})

    print(f"[+] Detected {len(detected)} issues (mock).")
    elapsed = time.time() - start
    return detected, elapsed

def backup_configs():
    start = time.time()
    ensure_dirs()
    stamp = now_ts()
    tmp_dir = os.path.join(BACKUPDIR, f"snapshot_{stamp}")
    os.makedirs(tmp_dir, exist_ok=True)
    # Create mock config files
    with open(os.path.join(tmp_dir, "ssh_config"), "w") as f:
        f.write("PermitRootLogin no\nCiphers aes256-gcm@openssh.com\n")
    with open(os.path.join(tmp_dir, "pf_rules.conf"), "w") as f:
        f.write("block in all\npass out all\n")
    elapsed = time.time() - start
    print(f"[+] Backup created at {tmp_dir} ({human_time(elapsed)})")
    return tmp_dir, elapsed

def perform_hardening(detected):
    start = time.time()
    print("[*] Performing mock hardening steps...")
    actions = []
    for d in detected:
        if d["component"] == "ssh":
            actions.append("Enforce strong SSH ciphers (simulated)")
        elif d["component"] == "apache":
            actions.append("Hide server headers (simulated)")
        elif d["component"] == "firewall":
            actions.append("Enable PF firewall with default block policy (simulated)")

    # Generic macOS hardening actions
    actions += ["Ensure automatic security updates enabled (simulated)", "Disable unnecessary services (simulated)"]

    change_file = os.path.join(WORKDIR, f"mac_changes_{now_ts()}.json")
    with open(change_file, "w") as f:
        json.dump({"timestamp": now_ts(), "actions": actions, "rollback_possible": True}, f, indent=2)

    elapsed = time.time() - start
    baseline_score = random.randint(35, 60)
    post_score = min(100, baseline_score + random.randint(30, 50))
    stability = round(random.uniform(0.91, 0.995), 3)
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

def rollback_last():
    print("[*] Attempting mock rollback (macOS)...")
    snapshots = sorted([d for d in os.listdir(BACKUPDIR) if d.startswith("snapshot_")]) if os.path.exists(BACKUPDIR) else []
    changes = sorted([f for f in os.listdir(WORKDIR) if f.startswith("mac_changes_")]) if os.path.exists(WORKDIR) else []
    if not snapshots or not changes:
        print("[!] No snapshots or change records found.")
        return False, None
    last_snap = snapshots[-1]
    last_change = changes[-1]
    success = random.random() > 0.05
    simulate_delay(0.5, 1.1)
    if success:
        print(f"[+] Rollback simulated: SUCCESS (restored {last_snap})")
    else:
        print("[!] Rollback simulated: FAILED")
    return success, {"snapshot": last_snap, "change_record": last_change}

def write_report(baseline, detected, hard_summary, scan_time, detect_time):
    stamp = now_ts()
    report = {
        "system_id": f"CYLX-MAC-MOCK-{stamp}",
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
    snap, bk_time = backup_configs()
    hard_summary, hard_t = perform_hardening(detected)
    write_report(baseline, detected, hard_summary, scan_time, detect_time)
    print("\n=== MOCK RUN SUMMARY ===")
    print(f"Detected issues: {len(detected)}")
    print(f"Backup: {snap}")
    print(f"Post-hardening score: {hard_summary['post_hardening_score']}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Cylix Mock Prototype - macOS (safe)")
    parser.add_argument("action", choices=["scan", "detect", "backup", "harden", "rollback", "report", "full"])
    args = parser.parse_args()

    if args.action == "scan":
        baseline_scan()
    elif args.action == "detect":
        files = sorted([f for f in os.listdir(WORKDIR) if f.startswith("baseline_")]) if os.path.exists(WORKDIR) else []
        if not files:
            baseline, _ = baseline_scan()
        else:
            with open(os.path.join(WORKDIR, files[-1])) as f:
                baseline = json.load(f)
        detect_vulns(baseline)
    elif args.action == "backup":
        backup_configs()
    elif args.action == "harden":
        files = sorted([f for f in os.listdir(WORKDIR) if f.startswith("baseline_")]) if os.path.exists(WORKDIR) else []
        if not files:
            baseline, _ = baseline_scan()
        else:
            with open(os.path.join(WORKDIR, files[-1])) as f:
                baseline = json.load(f)
        detected, _ = detect_vulns(baseline)
        backup_configs()
        perform_hardening(detected)
    elif args.action == "rollback":
        rollback_last()
    elif args.action == "report":
        files = sorted([f for f in os.listdir(WORKDIR) if f.startswith("baseline_")]) if os.path.exists(WORKDIR) else []
        if not files:
            print("[!] No baseline found.")
            return
        with open(os.path.join(WORKDIR, files[-1])) as f:
            baseline = json.load(f)
        detected, detect_time = detect_vulns(baseline)
        hard_sum = {
            "baseline_score": 50,
            "post_hardening_score": 90,
            "hardening_time_sec": 140,
            "system_stability_index": 0.98,
            "compliance_improvement_pct": 80.0,
            "changes_file": "N/A"
        }
        write_report(baseline, detected, hard_sum, 2.5, detect_time)
    elif args.action == "full":
        action_full()

if __name__ == "__main__":
    main()
