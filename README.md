🛡️ CyberScan 1.1 — Simple & Effective Malware & Web Security Scanner

CyberScan is a lightweight, cross-platform tool that helps security enthusiasts and system administrators scan their local systems and web applications for potential malware, misconfigurations, and weak security headers.

It supports two modes:

🧠 System Scan: Checks local directories using ClamAV, rkhunter, and YARA (or built-in heuristics if not installed).

🌐 Web Scan: Audits websites via OWASP ZAP (if available) or performs quick, standalone HTTP checks in Lite Mode (no setup required).

⚖️ Legal Notice

CyberScan must only be used on systems and websites you own or have explicit permission to test.
For safe demonstrations, use the intentionally vulnerable OWASP Juice Shop web app.

🚀 Installation (Linux / Kali)
# 1️⃣ Clone the repository
cd ~
git clone https://github.com/Rama7i11/CyberScan.git
cd CyberScan

# 2️⃣ Create and activate a virtual environment
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate

# 3️⃣ Install dependencies
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt


✅ Optional (for advanced scanning features):

sudo apt install -y clamav rkhunter docker.io
sudo freshclam
sudo rkhunter --update
sudo systemctl enable --now docker

🧹 Uninstallation (Clean Removal)
# Stop any running containers
sudo docker stop juice-shop zap 2>/dev/null || true

# Remove project completely
cd ~
rm -rf ~/CyberScan

# (Optional) Remove system tools
sudo apt remove --purge -y clamav rkhunter docker.io
sudo apt autoremove -y


If you only want to reset the environment:

cd ~/CyberScan
deactivate 2>/dev/null || true
rm -rf .venv

🧠 How to Use CyberScan
🖥️ System Scan (Local Machine)

Scans local directories for malware and suspicious files.

cd ~/CyberScan
source .venv/bin/activate

# Basic system scan (recommended)
sudo python3 cyberscan.py system --paths /home /etc


🧩 Where to put your paths:

You can include any folders separated by spaces:
/home, /etc, /var/www, /opt, etc.

Avoid /proc, /sys, and /dev (CyberScan skips them automatically).

Example:

sudo python3 cyberscan.py system --paths /home /usr/local /var/www


Reports are saved under:

CyberScan/reports/system_scan_YYYYMMDD_HHMMSS.json

🌐 Web Scan (Websites & Apps)

Scans web applications for security header issues, mixed content, and more.

⚡ Lite Mode (no OWASP ZAP required)
python3 cyberscan.py web https://example.com --lite


Lite Mode performs:

Security header validation (HSTS, CSP, X-Frame-Options)

Cookie flag checks (Secure, HttpOnly)

Mixed content detection

Shallow same-site link crawl

🔥 Full Mode (requires OWASP ZAP)
# Start OWASP ZAP locally (Docker example)
sudo docker run --rm -d -p 8080:8080 --name zap \
  owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# Run CyberScan using ZAP
python3 cyberscan.py web https://example.com

🧪 Safe demo target (OWASP Juice Shop)
# Launch Juice Shop (safe demo)
sudo docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Run a scan against it
python3 cyberscan.py web http://127.0.0.1:3000 --lite


Reports are saved under:

CyberScan/reports/web_scan_YYYYMMDD_HHMMSS.json

📊 Viewing Reports

All reports are stored as .json files inside the reports/ folder.

🔍 List and open the latest report
ls -lt reports
REPORT=$(ls -t reports | head -n 1)
jq '.' "reports/$REPORT" | less -R

🧭 Quick report views
# Show YARA matches (system)
jq '.yara.matches' "reports/$REPORT"

# Show ClamAV output snippet
jq '.clamscan.stdout_snippet' "reports/$REPORT"

# Show Lite web scan results
jq '.lite' "reports/$REPORT"

# Show ZAP alerts (web)
jq '.zap.alerts[] | {risk: .risk, alert: .alert, url: .url}' "reports/$REPORT"


💡 On Windows, open the report JSON in Notepad or VS Code.

🧱 Demo in 3 Commands (for Presentations)
git clone https://github.com/Rama7i11/CyberScan.git && cd CyberScan
python3 -m venv .venv && source .venv/bin/activate && python -m pip install -r requirements.txt
python3 cyberscan.py web http://127.0.0.1:3000 --lite

⚙️ Features Summary
Feature	Description
🧠 System Scanning	Uses ClamAV, rkhunter, YARA, or built-in heuristics
🌐 Web Scanning	Uses OWASP ZAP (if available) or internal Lite Mode
🔍 Report Generation	JSON output with clean structure
🧩 Plugin Support	Drop .py scripts into plugins/ folder
🧾 YARA Rules	Add .yar or .yara files into rules/ folder
🧱 Safe Defaults	Skips /proc, /sys, /dev, caps file size at 8 MB
🚀 Cross-Platform	Works on Linux, macOS, and Windows
🧰 Dependencies

Core Python requirements (requirements.txt):

yara-python
python-owasp-zap-v2.4
requests
beautifulsoup4
tldextract


Optional system tools (auto-detected):

clamav
rkhunter
docker

🧾 License

CyberScan 1.1 is released under the MIT License — free for educational and ethical use.

👤 Author

Developed by: Rama7i11 (Mohammed Abushamma)

Cybersecurity student & developer passionate about practical security tools.
