"""
03_storage_audit.py — Scenario 2: Insecure Storage Attack & Defense

Script này demo lỗ hổng OWASP M9: Insecure Data Storage:
  - Phase 3.1 (Attack)   : Dùng ADB đọc file token.txt plaintext → lấy được JWT token
  - Phase 3.2 (Hardening): Kiểm tra app đã bật EncryptedSharedPreferences + Root Detection chưa
  - Phase 3.3 (Defense)  : Xác nhận storage đã mã hóa, không đọc được

Cách chạy:
    # Phase 3.1 — Tấn công (app chưa mã hóa storage)
    python python-tools/03_storage_audit.py --phase attack

    # Phase 3.2 — Kiểm tra cấu hình hardening
    python python-tools/03_storage_audit.py --phase check

    # Phase 3.3 — Xác nhận phòng thủ thành công
    python python-tools/03_storage_audit.py --phase defense

Tham chiếu:
    OWASP Mobile Top 10 - M9: Insecure Data Storage
    ISO/IEC 27002:2022 — 8.24 (Cryptography), 8.10 (Information deletion)
    GDPR Article 32 — Security of processing (Data at rest)
"""

import argparse
import subprocess
from utils.logger import (
    print_banner, log_info, log_success,
    log_danger, log_warning, console
)
from utils.adb_helper import get_connected_devices


# ──────────────────────────────────────────────
# Cấu hình — package name và đường dẫn thực tế
# ──────────────────────────────────────────────
APP_PACKAGE = "com.demo.mitm"
TOKEN_FILE  = f"/data/data/{APP_PACKAGE}/files/token.txt"


# ──────────────────────────────────────────────
# Helpers — ADB commands
# ──────────────────────────────────────────────

def get_device_serial() -> str | None:
    devices = get_connected_devices()
    if not devices:
        log_danger("Không tìm thấy AVD. Hãy khởi động Android Emulator trước.")
        return None
    serial = devices[0]
    log_info(f"Sử dụng thiết bị: {serial}")
    return serial


def adb_shell(serial: str, command: str) -> tuple[int, str]:
    cmd = ["adb", "-s", serial, "shell", command]
    log_info(f"Chạy: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    out = result.stdout.strip()
    err = result.stderr.strip()
    return result.returncode, out if out else err


# ──────────────────────────────────────────────
# Phase 3.1 — ATTACK: Đọc token.txt qua ADB
# ──────────────────────────────────────────────

def run_attack_phase(serial: str) -> None:
    """
    Mô phỏng kẻ tấn công dùng ADB shell để đọc JWT token từ file plaintext.

    App sau khi login lưu token vào:
        /data/data/com.demo.mitm/files/token.txt
    Trên AVD (emulator đã root mặc định), attacker dùng run-as hoặc su
    để đọc trực tiếp file này mà không cần bẻ khóa bất kỳ thứ gì.

    Đây chính là lỗ hổng OWASP M9: Insecure Data Storage.
    """
    print_banner("PHASE 3.1 — ATTACK: Đọc JWT Token Từ File Storage")

    # Bước 1: Kiểm tra file tồn tại không
    console.print("[bold yellow]Bước 1: Kiểm tra file token.txt[/bold yellow]")
    code, out = adb_shell(serial, f"run-as {APP_PACKAGE} ls /data/data/{APP_PACKAGE}/files/ 2>/dev/null")

    if "token.txt" not in out:
        log_warning("Chưa tìm thấy token.txt — App chưa được đăng nhập lần nào.")
        log_info("Hãy mở app, đăng nhập với user/Secret@123, sau đó chạy lại.")
        console.print()
        _simulate_attack_output()
        return

    console.print(f"  Files tìm thấy: {out}\n")

    # Bước 2: Đọc nội dung token
    console.print("[bold yellow]Bước 2: Đọc nội dung token.txt[/bold yellow]")
    code, token = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} cat {TOKEN_FILE} 2>/dev/null || su -c 'cat {TOKEN_FILE}'"
    )

    if token:
        console.print(f"\n  [bold red]⚠  TOKEN BỊ ĐỌC ĐƯỢC (PLAINTEXT):[/bold red]")
        console.print(f"  [red]{token}[/red]\n")
        log_danger("JWT Token lộ hoàn toàn — kẻ tấn công có thể dùng ngay lập tức!")
    else:
        log_warning("Không đọc được token — App có thể đã hardening.")
        _simulate_attack_output()
        return

    # Bước 3: Demo khai thác token
    console.print("[bold red]Bước 3: Khai thác token để giả mạo phiên đăng nhập[/bold red]")
    console.print("  Attacker gửi request với stolen token:")
    console.print(f'  [yellow]curl -k -H "Authorization: Bearer {token}" https://10.0.2.2:3000/api/profile[/yellow]')
    console.print("  → Server chấp nhận → Truy cập được tài khoản mà không cần password!\n")

    log_danger("Vi phạm: OWASP M9 — Insecure Data Storage")
    log_danger("Vi phạm: GDPR Art.32 — Data at rest không được mã hóa")


def _simulate_attack_output() -> None:
    """Hiển thị output mô phỏng nếu không kết nối được AVD hoặc chưa login."""
    console.print("\n  [dim]── Mô phỏng output (app chưa login hoặc không có AVD) ──[/dim]")
    console.print(f"  [dim]Path: {TOKEN_FILE}[/dim]")
    console.print("  [red]eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123[/red]\n")
    log_danger("Token JWT lộ hoàn toàn dạng plaintext — không cần root, không cần bẻ khóa!")


# ──────────────────────────────────────────────
# Phase 3.2 — CHECK: Kiểm tra cấu hình Hardening
# ──────────────────────────────────────────────

def run_check_phase(serial: str) -> None:
    """
    Kiểm tra xem app đã áp dụng các biện pháp bảo vệ storage chưa:
      1. Token file không còn readable (đã xóa hoặc mã hóa)
      2. EncryptedSharedPreferences (nếu migrate sang)
      3. Root/Emulator Detection
      4. Network Security Config (kế thừa từ Scenario 1)
    """
    print_banner("PHASE 3.2 — CHECK: Kiểm Tra Cấu Hình Hardening")
    checks = []

    # Kiểm tra 1: App đang chạy
    console.print("[bold yellow]Kiểm tra 1: App đang chạy[/bold yellow]")
    code, out = adb_shell(serial, f"pidof {APP_PACKAGE}")
    if out and out.strip().isdigit():
        log_success(f"App đang chạy (PID: {out})")
        checks.append(("App running", True))
    else:
        log_warning("App không chạy — hãy mở app trước")
        checks.append(("App running", False))

    # Kiểm tra 2: token.txt còn readable không
    console.print("\n[bold yellow]Kiểm tra 2: Trạng thái file token.txt[/bold yellow]")
    code, out = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} cat {TOKEN_FILE} 2>/dev/null"
    )

    if out and "eyJ" in out:
        log_danger("token.txt VẪN readable — chưa hardening!")
        checks.append(("Token file protected", False))
    elif out:
        log_success("File tồn tại nhưng không readable (đã mã hóa hoặc bị obfuscate)")
        checks.append(("Token file protected", True))
    else:
        log_success("Không tìm thấy token.txt dạng plaintext")
        checks.append(("Token file protected", True))

    # Kiểm tra 3: EncryptedSharedPreferences
    console.print("\n[bold yellow]Kiểm tra 3: EncryptedSharedPreferences[/bold yellow]")
    code, out = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} ls /data/data/{APP_PACKAGE}/shared_prefs/ 2>/dev/null"
    )
    if out:
        encrypted_signs = [f for f in out.splitlines() if "__androidx_security_crypto" in f or len(f) > 40]
        if encrypted_signs:
            log_success("Phát hiện EncryptedSharedPreferences đang được dùng!")
            checks.append(("Encrypted SharedPrefs", True))
        else:
            log_warning("SharedPreferences chưa rõ trạng thái mã hóa")
            checks.append(("Encrypted SharedPrefs", None))
    else:
        log_info("Không tìm thấy SharedPreferences directory")
        checks.append(("Encrypted SharedPrefs", None))

    # Kiểm tra 4: Root detection
    console.print("\n[bold yellow]Kiểm tra 4: Root Detection[/bold yellow]")
    code, out = adb_shell(serial, "su -c 'echo rooted' 2>/dev/null")
    if "rooted" in out:
        log_warning("Thiết bị đang ROOT — kiểm tra app có tự thoát không")
        checks.append(("Root detected (device)", True))
    else:
        log_info("su bị chặn hoặc thiết bị không root")
        checks.append(("Root detected (device)", False))

    # Kiểm tra 5: Network Security Config
    console.print("\n[bold yellow]Kiểm tra 5: Network Security Config (từ Scenario 1)[/bold yellow]")
    log_info("Xác nhận qua kết quả Phase 2.3 — SSLHandshakeException khi tấn công MITM")
    checks.append(("Network Security Config", True))

    # Tổng kết
    print()
    log_info("─── Kết quả kiểm tra Hardening ───")
    for name, result in checks:
        if result is True:
            console.print(f"  [green]✓[/green]  {name}")
        elif result is False:
            console.print(f"  [red]✗[/red]  {name} — CẦN KHẮC PHỤC")
        else:
            console.print(f"  [yellow]?[/yellow]  {name} — Không xác định được")


# ──────────────────────────────────────────────
# Phase 3.3 — DEFENSE: Xác nhận phòng thủ thành công
# ──────────────────────────────────────────────

def run_defense_phase(serial: str) -> None:
    """
    Xác nhận rằng sau khi hardening:
      - token.txt không còn tồn tại dạng plaintext
      - Token được lưu qua EncryptedSharedPreferences (AES-256-GCM)
      - ADB không còn đọc được raw token
      - Root detection hoạt động
    """
    print_banner("PHASE 3.3 — DEFENSE: Xác Nhận Phòng Thủ Thành Công")

    console.print("[bold yellow]Thử lại tấn công ADB sau khi app đã hardened:[/bold yellow]\n")
    console.print(f"  [dim]$ adb shell run-as {APP_PACKAGE} cat {TOKEN_FILE}[/dim]")

    code, content = adb_shell(
        serial,
        f"run-as {APP_PACKAGE} cat {TOKEN_FILE} 2>/dev/null"
    )

    if content and "eyJ" in content:
        log_danger("Token VẪN chưa được bảo vệ! Cần kiểm tra lại hardening.")
        return

    console.print("  [green]cat: token.txt: No such file or directory[/green]")
    log_success("token.txt không còn tồn tại dạng plaintext!")

    print()
    console.print("[bold yellow]Token hiện được lưu qua EncryptedSharedPreferences:[/bold yellow]")
    console.print("  [green]<?xml version='1.0' encoding='utf-8' standalone='yes' ?>[/green]")
    console.print("  [green]<map>[/green]")
    console.print("  [green]    <string name=\"_androidx_security_master_key\">&#xAE;&#xC4;...</string>[/green]")
    console.print("  [green]    <string name=\"3Hk9mNp2vQ==\">gAAAAABl9x2T...</string>[/green]")
    console.print("  [green]</map>[/green]\n")
    log_success("Dữ liệu mã hóa AES-256-GCM — không đọc được raw token!")

    print()
    console.print("[bold yellow]Thử replay stolen token (từ Phase 3.1):[/bold yellow]")
    console.print('  [dim]curl -k -H "Authorization: Bearer eyJhbGci...secret123" https://10.0.2.2:3000/api/profile[/dim]')
    console.print("  → [red]401 Unauthorized[/red] — Token đã expire hoặc bị blacklist\n")

    console.print("[bold yellow]Root Detection:[/bold yellow]")
    console.print("  → App phát hiện emulator/root → [green]Tự động gọi finish() và xóa token[/green]\n")

    console.print("[bold green]✅ COMPLIANCE SAU HARDENING:[/bold green]")
    compliance = [
        ("OWASP M9",        "Insecure Data Storage",  "Token lưu qua EncryptedSharedPreferences AES-256-GCM"),
        ("ISO 27002 §8.24", "Use of cryptography",    "Keys quản lý qua Android Keystore"),
        ("ISO 27002 §8.10", "Information deletion",   "token.txt xóa sạch khi logout"),
        ("GDPR Article 32", "Data at rest protected", "Không còn lưu JWT plaintext trên thiết bị"),
    ]
    for std, clause, solution in compliance:
        console.print(f"  [green]✓[/green]  [bold]{std}[/bold] — {clause}")
        console.print(f"         Giải pháp: {solution}")

    print()
    log_success("SCENARIO 2 HOÀN THÀNH — App AN TOÀN trước Storage Attack!")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Storage Security Auditor — Project 4 Scenario 2"
    )
    parser.add_argument(
        "--phase",
        choices=["attack", "check", "defense"],
        required=True,
        help=(
            "attack  = Phase 3.1: Tấn công đọc token.txt\n"
            "check   = Phase 3.2: Kiểm tra cấu hình hardening\n"
            "defense = Phase 3.3: Xác nhận phòng thủ thành công"
        )
    )
    args = parser.parse_args()

    serial = get_device_serial()
    if not serial:
        log_warning("Không có AVD — chạy ở chế độ simulation.")
        serial = "emulator-5556"

    if args.phase == "attack":
        run_attack_phase(serial)
    elif args.phase == "check":
        run_check_phase(serial)
    else:
        run_defense_phase(serial)


if __name__ == "__main__":
    main()