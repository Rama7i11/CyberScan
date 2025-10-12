#!/usr/bin/env python3
"""
CyberScan 1.1 - Simple & Practical Edition

Usage:
  # system scan (uses ClamAV/rkhunter/yara if present; otherwise runs Python "lite" heuristics)
  python3 cyberscan.py system --paths /home /etc

  # web scan with ZAP (if available) or lite HTTP checks:
  python3 cyberscan.py web http://127.0.0.1:3000
  python3 cyberscan.py web http://example.com --lite

Notes:
 - Lite mode requires only Python packages listed in requirements.txt.
 - Always have explicit permission to scan remote hosts.
"""
import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

# optional imports
try:
    import yara
except Exception:
    yara = None

try:
    from zapv2 import ZAPv2
except Exception:
    ZAPv2 = None

try:
    import requests
    from bs4 import BeautifulSoup
    import tldextract
except Exception:
    requests = None
    BeautifulSoup = None
    tldextract = None

REPO_ROOT = Path(__file__).parent
REPORT_DIR = REPO_ROOT / "reports"
RULES_DIR = REPO_ROOT / "rules"
PLUGINS_DIR = REPO_ROOT / "plugins"

# safe default excludes to avoid pseudo filesystems and huge files
SAFE_EXCLUDES = {"/proc", "/dev", "/sys", "/run", "/var/run", "/mnt", "/media"}
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MB

def run_cmd(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"

# -------------------------
# System: external wrappers
# -------------------------
def scan_rkhunter():
    if shutil.which("rkhunter") is None:
        return {"installed": False, "note": "rkhunter not installed"}
    rc, out, err = run_cmd("sudo rkhunter --check --sk", timeout=900)
    return {"installed": True, "returncode": rc, "stdout_snippet": out[:400], "stderr_snippet": err[:400]}

def scan_clamscan(paths):
    if shutil.which("clamscan") is None:
        return {"installed": False, "note": "clamscan not installed"}
    paths_str = " ".join(map(str, paths))
    rc, out, err = run_cmd(f"clamscan -r --no-summary {paths_str}", timeout=3600)
    return {"installed": True, "returncode": rc, "stdout_snippet": out[-800:], "stderr_snippet": err[:400]}

def run_yara_scan(paths):
    if yara is None:
        return {"enabled": False, "note": "yara python module not installed"}
    rules_files = sorted(list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara")))
    if not rules_files:
        return {"enabled": False, "note": "no yara rules found in rules/"}
    try:
        mapping = {r.name: str(r) for r in rules_files}
        ruleset = yara.compile(filepaths=mapping)
    except Exception as e:
        return {"enabled": False, "error": str(e)}
    matches = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            try:
                m = ruleset.match(str(p))
                if m:
                    matches.append({"path": str(p), "matches": [str(x) for x in m]})
            except Exception as e:
                matches.append({"path": str(p), "error": str(e)})
        else:
            for root, _, files in os.walk(p):
                for f in files:
                    full = Path(root) / f
                    try:
                        m = ruleset.match(str(full))
                        if m:
                            matches.append({"path": str(full), "matches": [str(x) for x in m]})
                    except Exception:
                        pass
    return {"enabled": True, "rules_count": len(rules_files), "matches": matches}

# -------------------------
# System: lite heuristics (pure Python)
# -------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in cnt.values())

def system_scan_lite(paths):
    indicators = [
        (re.compile(rb"EICAR-?STANDARD-?ANTIVIRUS-?TEST-?FILE", re.I), "EICAR test string"),
        (re.compile(rb"http[s]?://[^\s\"'>]+", re.I), "embedded URL"),
        (re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "embedded IPv4"),
    ]
    suspicious_ext = {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".sh", ".php", ".jar"}
    findings = []
    for base in map(Path, paths):
        if not base.exists():
            continue
        # skip known pseudo-filesystems
        if any(str(base).startswith(x) for x in SAFE_EXCLUDES):
            continue
        for root, _, files in os.walk(base, followlinks=False):
            # skip pseudo paths inside walk
            if any(root.startswith(x) for x in SAFE_EXCLUDES):
                continue
            for f in files:
                p = Path(root) / f
                try:
                    size = p.stat().st_size
                    if size > MAX_FILE_SIZE:
                        continue
                    blob = p.read_bytes()
                except Exception:
                    continue
                tags = []
                if p.suffix.lower() in suspicious_ext:
                    tags.append("suspicious_extension")
                ent = shannon_entropy(blob[:4096])
                if ent > 7.5:
                    tags.append(f"high_entropy:{ent:.2f}")
                for rx, label in indicators:
                    if rx.search(blob):
                        tags.append(label)
                if tags:
                    findings.append({
                        "path": str(p),
                        "size": size,
                        "sha256": hashlib.sha256(blob).hexdigest(),
                        "tags": tags
                    })
    return {"lite": True, "findings": findings, "count": len(findings)}

# -------------------------
# Plugins
# -------------------------
def load_plugins():
    res = []
    if not PLUGINS_DIR.exists():
        return res
    sys.path.insert(0, str(PLUGINS_DIR))
    for p in PLUGINS_DIR.glob("*.py"):
        name = p.stem
        try:
            mod = __import__(name)
            if hasattr(mod, "run") and callable(mod.run):
                try:
                    r = mod.run()
                    res.append({"plugin": name, "result": r})
                except Exception as e:
                    res.append({"plugin": name, "error": str(e)})
            else:
                res.append({"plugin": name, "note": "no run()"})
        except Exception as e:
            res.append({"plugin": name, "error": str(e)})
    return res

# -------------------------
# Web: ZAP or lite HTTP checks
# -------------------------
def run_zap_scan(target, zap_api_key=None, zap_base="http://127.0.0.1:8080"):
    if ZAPv2 is None:
        return {"enabled": False, "note": "python-owasp-zap-v2.4 not installed"}
    # ensure the Python client uses localhost rather than 'zap' hostname
    proxies = {"http": zap_base, "https": zap_base}
    zap = ZAPv2(apikey=zap_api_key, proxies=proxies) if zap_api_key else ZAPv2(proxies=proxies)
    try:
        zap.urlopen(target)
        time.sleep(2)
        spider_id = zap.spider.scan(target)
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(1)
        scan_id = zap.ascan.scan(target)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(2)
        alerts = zap.core.alerts(baseurl=target)
        return {"enabled": True, "alerts_count": len(alerts), "alerts": alerts}
    except Exception as e:
        return {"enabled": True, "error": str(e)}

def web_scan_lite(target):
    if requests is None:
        return {"lite": True, "error": "requests/bs4 not installed"}
    out = {"lite": True, "target": target, "status": None, "headers": {}, "alerts": [], "pages": []}
    sess = requests.Session()
    sess.headers["User-Agent"] = "CyberScanLite/1.1"
    try:
        r = sess.get(target, timeout=15, allow_redirects=True, verify=True)
    except Exception as e:
        out["error"] = str(e)
        return out
    out["status"] = r.status_code
    out["headers"] = dict(r.headers)
    def alert(msg, sev="Medium"):
        out["alerts"].append({"severity": sev, "alert": msg})
    hdr = out["headers"]
    if "Strict-Transport-Security" not in hdr:
        alert("Missing HSTS", "High")
    if "Content-Security-Policy" not in hdr:
        alert("Missing Content-Security-Policy", "High")
    if hdr.get("X-Frame-Options", "").lower() not in ("deny", "sameorigin"):
        alert("Missing or weak X-Frame-Options", "Medium")
    if hdr.get("X-Content-Type-Options", "").lower() != "nosniff":
        alert("Missing X-Content-Type-Options", "Low")
    # cookies check
    set_cookie = hdr.get("Set-Cookie", "")
    if set_cookie and "httponly" not in set_cookie.lower():
        alert("Some cookies may be missing HttpOnly", "Low")
    # mixed content check
    scheme = requests.utils.urlparse(r.url).scheme
    if scheme == "https" and re.search(r'http://', r.text, re.I):
        alert("Possible mixed (http) content", "Medium")
    # shallow same-site crawl (cap few)
    if tldextract:
        ex = tldextract.extract(r.url)
        base_domain = f"{ex.domain}.{ex.suffix}"
        soup = BeautifulSoup(r.text, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            href = requests.compat.urljoin(r.url, a["href"])
            ex2 = tldextract.extract(href)
            if f"{ex2.domain}.{ex2.suffix}" == base_domain:
                links.add(href)
        links = list(links)[:10]
        for u in links[:5]:
            try:
                rr = sess.get(u, timeout=10)
                out["pages"].append({"url": u, "status": rr.status_code})
            except Exception:
                out["pages"].append({"url": u, "status": "error"})
    return out

# -------------------------
# Reporting
# -------------------------
def save_report(name, data):
    REPORT_DIR.mkdir(exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = REPORT_DIR / f"{name}_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2))
    print(f"[+] Report saved to {out_path}")
    return str(out_path)

def confirm_permission(target):
    print("IMPORTANT: you must have authorization to scan the target.")
    print(f"Target: {target}")
    ans = input("Type 'YES' (capitalized) to confirm you have permission to scan this target: ").strip()
    return ans == "YES"

# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="CyberScan 1.1 - Simple & Practical")
    sub = parser.add_subparsers(dest="cmd")
    system = sub.add_parser("system", help="run local system checks")
    system.add_argument("--paths", nargs="+", default=[str(Path.home() / "Downloads")], help="paths to scan with YARA/ClamAV")
    system.add_argument("--use-lite", action="store_true", help="force lite python scan (no external tools)")
    web = sub.add_parser("web", help="run a web scan via ZAP or lite checks")
    web.add_argument("target", help="target URL (must be authorized)")
    web.add_argument("--zap-api-key", help="ZAP API key (optional)")
    web.add_argument("--zap-base", default="http://127.0.0.1:8080", help="ZAP base URL (default: http://127.0.0.1:8080)")
    web.add_argument("--lite", action="store_true", help="force lite HTTP checks (no ZAP)")
    args = parser.parse_args()

    if args.cmd == "system":
        print("[*] Running system scans...")
        # safe sanitize paths and remove unsafe roots
        paths = []
        for p in args.paths:
            if any(str(p).startswith(x) for x in SAFE_EXCLUDES):
                print(f"Skipping excluded path: {p}")
                continue
            paths.append(p)
        rkh = scan_rkhunter() if not args.use_lite else {"installed": False, "note": "lite mode"}
        clam = scan_clamscan(paths) if not args.use_lite else {"installed": False, "note": "lite mode"}
        yara_r = run_yara_scan(paths)
        lite = system_scan_lite(paths) if (args.use_lite or (not shutil.which("clamscan") and yara_r.get("enabled") is False)) else {"lite": False}
        plugins = load_plugins()
        report = {
            "type": "system",
            "paths": paths,
            "rkhunter": rkh,
            "clamscan": clam,
            "yara": yara_r,
            "lite": lite,
            "plugins": plugins,
            "generated_at": datetime.utcnow().isoformat()
        }
        save_report("system_scan", report)

    elif args.cmd == "web":
        target = args.target
        if not confirm_permission(target):
            print("Permission not confirmed. Aborting.")
            sys.exit(1)
        # prefer ZAP if available and not forced-lite
        zap_res = None
        lite_res = None
        if args.lite or ZAPv2 is None:
            lite_res = web_scan_lite(target)
            zap_res = {"enabled": False, "note": "ZAP not used (lite mode or client not installed)"}
        else:
            zap_res = run_zap_scan(target, zap_api_key=args.zap_api_key, zap_base=args.zap_base)
        plugins = load_plugins()
        report = {
            "type": "web",
            "target": target,
            "zap": zap_res,
            "lite": lite_res,
            "plugins": plugins,
            "generated_at": datetime.utcnow().isoformat()
        }
        save_report("web_scan", report)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

