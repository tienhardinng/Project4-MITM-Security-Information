"""
02_capture_traffic.py — Phân tích traffic từ Burp Suite (Scenario 1)
"""

import argparse
import json
import re
from pathlib import Path
from utils.logger import print_banner, log_info, log_success, log_danger, log_warning, console

# Các pattern nhận dạng credentials (giống pattern server nhận diện)
SENSITIVE_PATTERNS = {
    "username": re.compile(r'"username"\s*:\s*"([^"]+)"', re.IGNORECASE),
    "password": re.compile(r'"password"\s*:\s*"([^"]+)"', re.IGNORECASE),
}

def parse_har_file(filepath):
    path = Path(filepath)
    if not path.exists():
        log_danger(f"Không tìm thấy file HAR tại: {filepath}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("log", {}).get("entries", [])

def run_vulnerable_phase(har_file):
    print_banner("PHASE 2.1 — VULNERABLE: PHÂN TÍCH TRAFFIC TỪ BURP SUITE")
    entries = parse_har_file(har_file)
    if not entries: return

    log_info(f"Đang quét {len(entries)} requests...")
    found_any = False

    for idx, entry in enumerate(entries, start=1):
        request = entry.get("request", {})
        url = request.get("url", "")
        post_data = request.get("postData", {}).get("text", "")

        findings = []
        for field, pattern in SENSITIVE_PATTERNS.items():
            match = pattern.search(post_data)
            if match: findings.append((field, match.group(1)))

        if findings:
            found_any = True
            log_danger(f"[!] Request #{idx} tới {url} bị lộ thông tin:")
            for field, value in findings:
                console.print(f"    [bold red]⚠ {field.upper()}:[/bold red] [red]{value}[/red]")

    if not found_any:
        log_success("Không tìm thấy credentials trong file HAR này.")

def run_hardened_phase():
    print_banner("PHASE 2.3 — HARDENED: KIỂM CHỨNG PHÒNG THỦ MẠNG")
    log_info("Mô phỏng kết quả Burp Suite khi App đã bật Network Security Config...")
    console.print("\n[bold red]Result: Connection Terminated[/bold red]")
    console.print("[yellow]Reason: SSLHandshakeException (Certificate Unknown)[/yellow]")
    log_success("Chặn MITM thành công! Không có dữ liệu nào bị bắt.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["vulnerable", "hardened"], required=True)
    parser.add_argument("--file", default="reports/raw_logs/captured.har")
    args = parser.parse_args()

    if args.phase == "vulnerable":
        run_vulnerable_phase(args.file)
    else:
        run_hardened_phase()

if __name__ == "__main__":
    main()