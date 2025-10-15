#!/usr/bin/env python3
"""
Cylix Mock Prototype - Linux
Safe, non-destructive mock of scanning + hardening workflow.
All files live in the workspace directory (~/.cylix_cylix_mock by default).
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

WORKDIR = os.path.expanduser("~/.cylix_mock_linux")
BACKUPDIR = os.path.join(WORKDIR, "backups")
REPORTDIR = os.path.join(WORKDIR, "reports")
SEED = 42
random.seed(SEED)

# Mock vulnerability DB (very small, believable)
MOCK_VULNS = [
    {"id": "CYLX-2025-001", "component": "openssh", "affected_max_version": "8.6p1",
     "severity": "High", "desc": "Weak client KEX algorithms allowed"},
    {"id": "CYLX-2024-007", "component": "openssl", "affected_max_version": "1.1.1k",
     "severity": "Medium", "desc": "Deprecated TLS versions enabled"},
    {"id": "CYLX-2023-015", "component": "iptables", "affected_max_version": "1.8.2",
     "severity": "Low", "desc": "Loose default INPUT policy"},
]

def ensure_dirs():
    for d in (WORKDIR, BACKUPDIR, REPORTDIR):
        os.makedirs(d, exist_ok=True)

def now_ts():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def human_time(s):
    return f"{s:.1f}s"

def simulate_command_delay(min_s=0.2, max_s=0.7):
    t = random.uniform(min_s, max_s)
    time.sleep(t)
    return t

def baseline_scan():
    ensure_dirs()
    start = time.time()
    print("[*] Starting baseline scan (mock)...")
    delays = 0.0

    info = {
        "host": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
    }
    delays += simulate_command_delay()

    # Mock package versions (in real tool you'd query package manager)
    packages = {
        "openssh": random.choice(["8.4p1", "8.6p1", "8.3p1"]),
        "openssl": random.choice(["1.1.1j", "1.1.1k", "3.0.2"]),
        "iptables": random.choice(["1.8.2", "1.8.3"]),
    }
    delays += simulate_command_delay()

    # Mock open ports: check a few localhost ports for believability
    common_ports = [22, 80, 443, 3306, 5432]
    open_ports = []
    for p in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect(("127.0.0.1", p))
            open_ports.append(p)
        except Exception:
            # not open
            pass
        finally:
            s.close()
    delays += simulate_command_delay()

    # Simulated service list
    services = [
        {"name": "sshd", "status": "running" if random.random() > 0.2 else "stopped"},
        {"name": "nginx", "status": "running" if random.random() > 0.6 else "stopped"},
        {"name": "mysql", "status": "running" if random.random() > 0.8 else "stopped"},
    ]
    delays += simulate_command_delay()

    baseline = {
        "timestamp": now_ts(),
        "summary": info,
        "packages": packages,
        "open_ports": open_ports,
        "services": services,
    }

    path = os.path.join(WORKDIR, f"baseline_{baseline['timestamp']}.json")
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"[+] Baseline saved to {path}")
    elapsed = time.time() - start
    print(f"[*] Baseline scan completed in {human_time(elapsed)}")
    return baseline, elapsed

def detect_vulns(baseline):
    start = time.time()
    print("[*] Running mock vulnerability detection...")
    simulate_command_delay()
    detected = []
    for v in MOCK_VULNS:
        comp = v["component"]
        if comp in baseline["packages"]:
            # naive version comparison: if installed version <= affected_max_version -> vulnerable
            installed = baseline["packages"][comp]
            # for believable randomness, assume 50% chance if versions close
            if installed == v["affected_max_version"] or random.random() < 0.45:
                detected.append(v)
    # Also create a believable count for false positives
    false_positive = random.choice([0, 0, 1])
    for i in range(false_positive):
        detected.append({"id": f"FP-{random.randint(100,999)}", "component": "misc", "severity": "Low", "desc": "Possible misconfig"})
    elapsed = time.time() - start
    print(f"[+] Detected {len(detected)} potential issues (mock) in {human_time(elapsed)}")
    return detected, elapsed

def backup_configs():
    start = time.time()
    ensure_dirs()
    stamp = now_ts()
    bk_path = os.path.join(BACKUPDIR, f"config_backup_{stamp}.tar")
    # For mock: create some text config files inside workspace and tar them
    mock_files = {
        "sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\nKexAlgorithms +diffie-hellman-group14-sha1\n",
        "sysctl.conf": "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n",
    }
    tmpfolder = os.path.join(WORKDIR, f"tmpcfg_{stamp}")
    os.makedirs(tmpfolder, exist_ok=True)
    for name, content in mock_files.items():
        with open(os.path.join(tmpfolder, name), "w") as f:
            f.write(content)
    # create a tar file (mock: just copy files into backup dir with timestamp)
    shutil.make_archive(bk_path.replace(".tar", ""), 'tar', tmpfolder)
    shutil.rmtree(tmpfolder)
    elapsed = time.time() - start
    print(f"[+] Backup created: {bk_path} ({human_time(elapsed)})")
    return bk_path, elapsed

def perform_hardening(detected):
    start = time.time()
    print("[*] Performing mock hardening steps...")
    steps = []
    # For each detected high/medium vuln, propose a step
    for v in detected:
        if v.get("severity") in ("High", "Medium"):
            steps.append(f"Apply recommended config change for {v['component']} ({v['id']})")
    # Generic hardening actions
    steps += [
        "Disable root SSH login (simulated)",
        "Require stronger KEX algorithms (simulated)",
        "Harden sysctl network settings (simulated)",
        "Set default INPUT policy to DROP in iptables (simulated)"
    ]
    # Write a mock "changes" file to workspace (simulate applying)
    change_file = os.path.join(WORKDIR, f"changes_{now_ts()}.json")
    change_record = {"timestamp": now_ts(), "actions": steps, "rollback_possible": True}
    with open(change_file, "w") as f:
        json.dump(change_record, f, indent=2)
    # Simulate time taken
    t = simulate_command_delay(0.8, 1.6)
    elapsed = time.time() - start
    print(f"[+] Hardening actions recorded to {change_file}")
    print(f"[*] Hardening simulated in {human_time(elapsed)}")
    # Return a mock post-hardening score and stability index
    baseline_score = random.randint(30, 60)
    post_score = min(100, baseline_score + random.randint(30, 55))
    stability = round(random.uniform(0.90, 0.995), 3)
    compliance_improvement = round((post_score - baseline_score) / baseline_score * 100, 1)
    summary = {
        "baseline_score": baseline_score,
        "post_hardening_score": post_score,
        "hardening_time_sec": round(elapsed, 2),
        "system_stability_index": stability,
        "compliance_improvement_pct": compliance_improvement,
        "changes_file": change_file
    }
    return summary, elapsed

def rollback_last():
    # locate latest backup and latest changes file
    print("[*] Attempting mock rollback...")
    backups = sorted([f for f in os.listdir(BACKUPDIR) if f.startswith("config_backup_")]) if os.path.exists(BACKUPDIR) else []
    changes = sorted([f for f in os.listdir(WORKDIR) if f.startswith("changes_")]) if os.path.exists(WORKDIR) else []
    if not backups or not changes:
        print("[!] No backups or changes found to rollback (mock).")
        return False, None
    last_backup = backups[-1]
    last_change = changes[-1]
    # Simulate rollback success probability
    success = random.random() > 0.05  # 95% success in mock
    simulate_command_delay(0.5, 1.0)
    print(f"[+] Found backup {last_backup} and change record {last_change}")
    if success:
        print("[+] Rollback simulated: SUCCESS")
    else:
        print("[!] Rollback simulated: FAILED (mock)")
    return success, {"backup": last_backup, "change": last_change}

def write_report(baseline, detected, hardening_summary, scan_time, detect_time):
    stamp = now_ts()
    report = {
        "system_id": f"CYLX-MOCK-{stamp}",
        "baseline": baseline,
        "detected_vulns": detected,
        "hardening_summary": hardening_summary,
        "timings": {"scan_sec": round(scan_time, 2), "detect_sec": round(detect_time, 2)}
    }
    rpt_path = os.path.join(REPORTDIR, f"report_{stamp}.json")
    with open(rpt_path, "w") as f:
        json.dump(report, f, indent=2)
    # Also create a compact CSV summary
    csv_path = os.path.join(REPORTDIR, f"summary_{stamp}.csv")
    with open(csv_path, "w") as f:
        f.write("system_id,baseline_score,post_score,stability,compliance_improvement\n")
        b = hardening_summary
        f.write(f"{report['system_id']},{b['baseline_score']},{b['post_hardening_score']},{b['system_stability_index']},{b['compliance_improvement_pct']}\n")
    print(f"[+] Report written: {rpt_path}")
    print(f"[+] CSV summary: {csv_path}")
    return rpt_path, csv_path

def action_full():
    baseline, scan_time = baseline_scan()
    detected, detect_time = detect_vulns(baseline)
    backup_path, bk_time = backup_configs()
    hardening_summary, hard_t = perform_hardening(detected)
    rpt, csv = write_report(baseline, detected, hardening_summary, scan_time, detect_time)
    print("\n=== MOCK RUN SUMMARY ===")
    print(f"Baseline saved. Issues found: {len(detected)}")
    print(f"Backup: {backup_path}")
    print(f"Hardening post-score: {hardening_summary['post_hardening_score']}")
    print(f"Report: {rpt}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Cylix Mock Prototype - Linux (safe, non-destructive)")
    parser.add_argument("action", choices=["scan", "detect", "backup", "harden", "rollback", "report", "full"], help="Action to perform")
    args = parser.parse_args()

    if args.action == "scan":
        baseline_scan()
    elif args.action == "detect":
        # need a baseline file: pick latest
        files = sorted([f for f in os.listdir(WORKDIR) if f.startswith("baseline_")]) if os.path.exists(WORKDIR) else []
        if not files:
            print("[!] No baseline found; running a new baseline scan.")
            baseline, _ = baseline_scan()
        else:
            with open(os.path.join(WORKDIR, files[-1])) as f:
                baseline = json.load(f)
        detect_vulns(baseline)
    elif args.action == "backup":
        backup_configs()
    elif args.action == "harden":
        # detect then harden
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
        # pick latest baseline and hardening change
        files = sorted([f for f in os.listdir(WORKDIR) if f.startswith("baseline_")]) if os.path.exists(WORKDIR) else []
        if not files:
            print("[!] No baseline found; nothing to report.")
            return
        with open(os.path.join(WORKDIR, files[-1])) as f:
            baseline = json.load(f)
        detected, detect_time = detect_vulns(baseline)
        # simulate a previous hardening summary if none exists
        hard_sum = {
            "baseline_score": 45,
            "post_hardening_score": 88,
            "hardening_time_sec": 120,
            "system_stability_index": 0.97,
            "compliance_improvement_pct": 95.6,
            "changes_file": "N/A"
        }
        write_report(baseline, detected, hard_sum, 2.1, detect_time)
    elif args.action == "full":
        action_full()

if __name__ == "__main__":
    main()
