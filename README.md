# CyberScan 1.1

A starter Linux malware + web scan orchestrator.

## Usage

### Setup
```bash
✅ Requirements

Common (all platforms)

Python 3.8+

pip

Repo cloned locally

Python packages (install with requirements.txt)

yara-python
python-owasp-zap-v2.4


System tools (optional but recommended for fuller results)

ClamAV (clamscan)

rkhunter

OWASP ZAP (running in daemon/headless mode on 127.0.0.1:8080)

CyberScan still runs without these, but the related sections in the report will say “not installed” or “not used.”
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

🚀 Quick Start (Linux/Kali)
# 1) Get the code
git clone https://github.com/Rama7i11/CyberScan.git
cd CyberScan

# 2) Python env + deps
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 3) (Optional) Install system scanners
sudo apt update
sudo apt install -y clamav rkhunter
sudo freshclam   # updates ClamAV signatures

# 4) System scan example (scans /tmp)
echo "MALICIOUS_TEST_TOKEN" > /tmp/malicious.txt   # test string for sample YARA rule
python3 cyberscan.py system --paths /tmp
# -> Report saved under reports/system_scan_*.json
Web scan on Linux/Kali (with ZAP)

Option A: Run ZAP via Docker

# requires Docker installed & running
sudo docker run --rm -d -p 8080:8080 --name zap \
  owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true


Option B: Run ZAP natively

sudo apt install -y zaproxy
zaproxy -daemon -host 127.0.0.1 -port 8080 & disown
📄 Reading Reports

Reports are JSON files saved in reports/.
On Linux/Kali:

sudo apt install -y jq
REPORT=$(ls -t reports | head -n 1)
jq '.' "reports/$REPORT"


Quick views:

# YARA matches (system scans)
jq '.yara.matches' "reports/$REPORT"

# ClamAV output snippet
jq '.clamscan.stdout_snippet' "reports/$REPORT"

# ZAP alerts (web scans)
jq '.zap.alerts[] | {risk: .risk, alert: .alert, url: .url}' "reports/$REPORT"
