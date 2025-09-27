#!/usr/bin/env python3
"""
CyberScan 1.1 - Enhanced starter tool
Modes: system (local scanning wrappers) | web (OWASP ZAP orchestration)

Usage:
  python3 cyberscan.py system --paths /tmp
  python3 cyberscan.py web http://localhost:3000 --zap-api-key MYKEY

NOTE: This is a starter orchestration script. It wraps existing tools (rkhunter, clamscan),
runs YARA rules in ./rules, can call OWASP ZAP API for web scans (requires ZAP daemon running).
Always have explicit permission to scan remote targets.
"""
import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import yara
except Exception:
    yara = None

try:
    from zapv2 import ZAPv2
except Exception:
    ZAPv2 = None

REPO_ROOT = Path(__file__).parent
REPORT_DIR = REPO_ROOT / "reports"
RULES_DIR = REPO_ROOT / "rules"
PLUGINS_DIR = REPO_ROOT / "plugins"


def run_cmd(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"


# -------------------------
# System scanners
# -------------------------
def scan_rkhunter():
    if shutil.which("rkhunter") is None:
        return {"installed": False, "note": "rkhunter not installed"}
    rc, out, err = run_cmd("sudo rkhunter --check --sk", timeout=600)
    return {"installed": True, "returncode": rc, "stdout_snippet": out[:400], "stderr_snippet": err[:400]}


def scan_clamscan(target_paths):
    if shutil.which("clamscan") is None:
        return {"installed": False, "note": "clamscan not installed"}
    paths = " ".join(map(str, target_paths))
    rc, out, err = run_cmd(f"clamscan -r --no-summary {paths}", timeout=1800)
    return {"installed": True, "returncode": rc, "stdout_snippet": out[-400:], "stderr_snippet": err[:400]}


def run_yara_scan(paths):
    if yara is None:
        return {"enabled": False, "note": "yara python module not installed"}
    rules_files = sorted(list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara")))
    if not rules_files:
        return {"enabled": False, "note": "no yara rules found in rules/"}
    try:
        rules = yara.compile(filepaths={r.name: str(r) for r in rules_files})
    except Exception as e:
        return {"enabled": False, "error": str(e)}
    matches = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            try:
                m = rules.match(str(p))
                if m:
                    matches.append({"path": str(p), "matches": [str(x) for x in m]})
            except Exception as e:
                matches.append({"path": str(p), "error": str(e)})
        else:
            for root, _, files in os.walk(p):
                for f in files:
                    full = Path(root) / f
                    try:
                        m = rules.match(str(full))
                        if m:
                            matches.append({"path": str(full), "matches": [str(x) for x in m]})
                    except Exception:
                        pass
    return {"enabled": True, "rules_count": len(rules_files), "matches": matches}


# -------------------------
# Plugins loader
# -------------------------
def load_plugins():
    results = []
    if not PLUGINS_DIR.exists():
        return results
    sys.path.insert(0, str(PLUGINS_DIR))
    for p in PLUGINS_DIR.glob("*.py"):
        name = p.stem
        try:
            mod = importlib.import_module(name)
            if hasattr(mod, "run") and callable(mod.run):
                try:
                    r = mod.run()
                    results.append({"plugin": name, "result": r})
                except Exception as e:
                    results.append({"plugin": name, "error": str(e)})
            else:
                results.append({"plugin": name, "note": "no callable run()"})
        except Exception as e:
            results.append({"plugin": name, "error": str(e)})
    return results


# -------------------------
# OWASP ZAP orchestration
# -------------------------
def run_zap_scan(target, zap_api_key=None, zap_base="http://127.0.0.1:8080"):
    if ZAPv2 is None:
        return {"enabled": False, "note": "python-owasp-zap-v2.4 not installed"}
    zap = ZAPv2(apikey=zap_api_key) if zap_api_key else ZAPv2()
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
    parser = argparse.ArgumentParser(description="CyberScan 1.1 - system + web starter")
    sub = parser.add_subparsers(dest="cmd")
    system = sub.add_parser("system", help="run local system checks")
    system.add_argument("--paths", nargs='+', default=["/tmp"], help="paths to scan with YARA/ClamAV")
    web = sub.add_parser("web", help="run a web scan via OWASP ZAP (requires ZAP running)")
    web.add_argument("target", help="target URL (must be authorized)")
    web.add_argument("--zap-api-key", help="ZAP API key (optional)")
    args = parser.parse_args()

    if args.cmd == "system":
        print("[*] Running system scans...")
        rkh = scan_rkhunter()
        clam = scan_clamscan(args.paths)
        yara_r = run_yara_scan(args.paths)
        plugins = load_plugins()
        report = {"type": "system", "rkhunter": rkh, "clamscan": clam, "yara": yara_r, "plugins": plugins, "generated_at": datetime.utcnow().isoformat()}
        save_report("system_scan", report)
    elif args.cmd == "web":
        target = args.target
        if not confirm_permission(target):
            print("Permission not confirmed. Aborting.")
            sys.exit(1)
        print(f"[*] Running web scan for {target} (ZAP must be running at http://127.0.0.1:8080)")
        zap_res = run_zap_scan(target, zap_api_key=args.zap_api_key)
        plugins = load_plugins()
        report = {"type": "web", "target": target, "zap": zap_res, "plugins": plugins, "generated_at": datetime.utcnow().isoformat()}
        save_report("web_scan", report)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
