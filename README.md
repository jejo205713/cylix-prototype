# Cylix Mock Prototype

**Cylix Mock Prototype** is a safe, non-destructive Python-based demonstration of a system hardening tool workflow. It simulates security scanning, vulnerability detection, configuration backup, hardening, rollback, and reporting on both Linux and Windows systems without touching actual system files or requiring admin privileges.

---

## Features

- **Baseline Scan (Mock)**: Gathers system information, installed components, services, and open ports.
- **Vulnerability Detection (Mock)**: Detects potential vulnerabilities based on mock rules and versions.
- **Backup (Mock)**: Creates timestamped backups of configuration files or registry snapshots inside workspace directories.
- **Hardening (Mock)**: Simulates security hardening steps and generates change records.
- **Rollback (Mock)**: Simulates restoring system configuration from the latest backup.
- **Reporting**: Generates detailed JSON and CSV reports, including baseline and post-hardening scores, system stability index, and compliance improvement percentage.
- **Cross-Platform Support**: Separate scripts for Linux (`cylix_mock_linux.py`) and Windows (`cylix_mock_windows.py`).

---

## Installation

1. **Clone or download** this repository.
2. **Install Python 3.9+** (Python 3.10 recommended).
3. **Install dependencies**:

```bash
pip install -r requirements.txt
