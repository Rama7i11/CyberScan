# CyberScan 1.1

CyberScan 1.1 is a lightweight orchestration tool for **system malware scans** and **web application scans**.  
It integrates **ClamAV**, **rkhunter**, **YARA rules**, and **OWASP ZAP** into one easy-to-use CLI.

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
