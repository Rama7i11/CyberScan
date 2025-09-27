# CyberScan 1.1

A starter Linux malware + web scan orchestrator.

## Usage

### Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
⚠️ **Important**: Only scan systems or websites that you **own** or have **explicit permission** to test.

---

## ✨ Features
- **System scans** with:
  - [ClamAV](https://www.clamav.net/) (`clamscan`)
  - [rkhunter](http://rkhunter.sourceforge.net/) (if installed)
  - [YARA rules](https://yara.readthedocs.io/) from the `rules/` folder
- **Web scans** with [OWASP ZAP](https://www.zaproxy.org/) (requires ZAP running in daemon mode)
- **Plugin support** — drop `.py` files in `plugins/` and they’ll be executed automatically
- Generates **JSON reports** in the `reports/` folder

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/Rama7i11/CyberScan.git
cd CyberScan
