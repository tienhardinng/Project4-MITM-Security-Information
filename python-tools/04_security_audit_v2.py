"""
04_security_audit.py — Tổng hợp Security Audit Report

Script này tổng hợp toàn bộ kết quả demo thành một báo cáo
có cấu trúc, ánh xạ sang các tiêu chuẩn quốc tế.

Cách chạy:
    python python-tools/04_security_audit.py
    → Sinh file: reports/final_report.html
"""

import datetime
from pathlib import Path
from utils.logger import print_banner, log_info, log_success


# ──────────────────────────────────────────────
# Dữ liệu cấu trúc — Findings & Compliance
# ──────────────────────────────────────────────

FINDINGS = [
    {
        "id":          "VULN-001",
        "title":       "M3: Insecure Communication — User-installed CA Accepted",
        "severity":    "CRITICAL",
        "description": (
            "App chấp nhận User-added CA certificates, cho phép kẻ tấn công "
            "thực hiện MITM qua chứng chỉ giả (Burp Suite CA). "
            "Toàn bộ HTTPS traffic bị đọc dưới dạng plaintext dù địa chỉ hiển thị HTTPS."
        ),
        "evidence":    "Burp Suite capture được POST /api/login với username và password rõ.",
        "fix":         "Áp dụng Network Security Config chỉ tin tưởng System CAs + Certificate Pinning.",
        "owasp":       "OWASP Mobile Top 10 - M3: Insecure Communication",
        "iso":         "ISO/IEC 27002:2022 — 8.24, 8.26",
        "gdpr":        "GDPR Article 32 — Security of processing (Data in transit)",
    },
    {
        "id":          "VULN-002",
        "title":       "M9: Insecure Data Storage — JWT Token Lưu Plaintext",
        "severity":    "HIGH",
        "description": (
            "Sau khi đăng nhập thành công, app lưu JWT token vào file plaintext tại "
            "/data/data/com.demo.mitm/files/token.txt. "
            "Trên AVD (emulator mặc định có quyền run-as), kẻ tấn công dùng ADB shell "
            "đọc trực tiếp token mà không cần root, không cần bẻ khóa, "
            "sau đó replay token để truy cập API với danh tính nạn nhân."
        ),
        "evidence": (
            "adb shell run-as com.demo.mitm cat /data/data/com.demo.mitm/files/token.txt "
            "→ JWT token lộ hoàn toàn dạng plaintext. "
            "Token có thể replay trực tiếp vào API mà không cần password."
        ),
        "fix":         "Xóa token.txt, lưu token qua EncryptedSharedPreferences (AES-256-GCM) + Android Keystore + Root Detection.",
        "owasp":       "OWASP Mobile Top 10 - M9: Insecure Data Storage",
        "iso":         "ISO/IEC 27002:2022 — 8.24, 8.10",
        "gdpr":        "GDPR Article 32 — Security of processing (Data at rest)",
    },
    {
        "id":          "VULN-003",
        "title":       "M3: Insecure Authentication — Thiếu Multi-Factor Authentication (MFA)",
        "severity":    "MEDIUM",
        "description": (
            "App chỉ xác thực bằng username/password đơn giản — không có yếu tố thứ 2. "
            "Quan trọng hơn: nếu thêm OTP/MFA mà chưa fix transport layer (VULN-001), "
            "attacker vẫn steal được OTP real-time qua MITM trong cùng session window. "
            "MFA chỉ có giá trị thực sự sau khi transport đã được bảo vệ."
        ),
        "evidence": (
            "Login thành công chỉ với username + password, không có OTP hay biometric. "
            "Nếu có OTP: Burp intercept POST /api/verify-otp → OTP lộ plaintext → "
            "attacker relay ngay lập tức trong 30 giây hiệu lực."
        ),
        "fix": (
            "Áp dụng theo đúng thứ tự: "
            "(1) Fix transport — Network Security Config + Cert Pinning, "
            "(2) Fix storage — EncryptedSharedPreferences, "
            "(3) Thêm MFA — TOTP (Google Authenticator) hoặc Biometric prompt."
        ),
        "owasp":       "OWASP Mobile Top 10 - M3: Insecure Communication, M4: Insufficient Authentication",
        "iso":         "ISO/IEC 27002:2022 — 8.05 (Secure authentication)",
        "gdpr":        "GDPR Article 32 — Appropriate technical measures",
    },
]

RISK_MATRIX = {
    "Threat":        "MITM attack (network) + ADB Token Extraction (local device).",
    "Vulnerability": "App không kiểm tra nguồn gốc chứng chỉ TLS; JWT token lưu plaintext trên thiết bị.",
    "Likelihood":    "HIGH — Cả hai attack đều thực hiện bằng free tools (Burp Suite, ADB).",
    "Impact":        "CRITICAL — Lộ credentials ở lớp network VÀ lộ token ở lớp storage, đủ để chiếm toàn bộ phiên.",
    "Risk Level":    "CRITICAL",
}

ATTACK_CHAIN = [
    ("Bước 1", "MITM Setup",        "Cài Burp CA vào AVD, cấu hình proxy 10.0.2.2:8080"),
    ("Bước 2", "Credential Theft",  "Intercept POST /api/login → lấy username + password plaintext"),
    ("Bước 2b", "MFA Bypass",       "Nếu có OTP: Burp intercept POST /api/verify-otp → steal OTP real-time trong 30 giây hiệu lực → MFA vô hiệu"),
    ("Bước 3", "Token Extraction",  "adb shell run-as com.demo.mitm cat .../token.txt → JWT token"),
    ("Bước 4", "Session Hijack",    "Replay token → truy cập API với danh tính nạn nhân, không cần password"),
]


def generate_html_report(output_path: str) -> None:
    """Sinh báo cáo HTML có thể in / nộp giảng viên."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Findings table rows
    rows = ""
    for f in FINDINGS:
        severity_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c"}.get(f["severity"], "#666")
        rows += f"""
        <tr>
          <td><code>{f['id']}</code></td>
          <td>{f['title']}</td>
          <td style="color:{severity_color};font-weight:bold">{f['severity']}</td>
          <td>{f['owasp']}</td>
          <td>{f['iso']}</td>
          <td>{f['gdpr']}</td>
          <td>{f['fix']}</td>
        </tr>"""

    # Attack chain rows
    chain_rows = ""
    for step, name, detail in ATTACK_CHAIN:
        chain_rows += f"""
        <tr>
          <td><strong>{step}</strong></td>
          <td>{name}</td>
          <td style="font-family:monospace;font-size:13px">{detail}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Security Audit Report — Project 4</title>
  <style>
    body     {{ font-family: 'Segoe UI', sans-serif; max-width: 980px;
                margin: 40px auto; color: #1e293b; line-height: 1.6; }}
    h1       {{ color: #0f172a; border-bottom: 3px solid #dc2626; padding-bottom: 8px; }}
    h2       {{ color: #1d4ed8; margin-top: 36px; }}
    h3       {{ color: #1d4ed8; }}
    table    {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }}
    th       {{ background: #1e293b; color: white; padding: 10px; text-align: left; }}
    td       {{ padding: 9px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    tr:hover {{ background: #f8fafc; }}
    .meta    {{ color:#64748b; font-size:14px; }}
    .box     {{ background:#f1f5f9; border-left:4px solid #1d4ed8;
                padding:12px 16px; margin:12px 0; border-radius:0 8px 8px 0; }}
    .box-red {{ background:#fff5f5; border-left:4px solid #dc2626;
                padding:12px 16px; margin:12px 0; border-radius:0 8px 8px 0; }}
    code     {{ background:#e2e8f0; padding:1px 5px; border-radius:3px;
                font-family:monospace; font-size:13px; }}
    .tag-critical {{ background:#dc2626; color:white; padding:2px 8px;
                     border-radius:4px; font-size:12px; font-weight:bold; }}
    .tag-high     {{ background:#ea580c; color:white; padding:2px 8px;
                     border-radius:4px; font-size:12px; font-weight:bold; }}
  </style>
</head>
<body>

  <h1>🔐 Security Audit Report</h1>
  <p class="meta">Project 4 — Android MITM &amp; Token Theft Lab &nbsp;|&nbsp; Generated: {now}</p>

  <!-- ══════════════════════════════════════ -->
  <h2>1. Executive Summary</h2>
  <div class="box">
    Demo này chứng minh <strong>2 lỗ hổng bảo mật nghiêm trọng</strong> trên ứng dụng Android,
    bao gồm cả lớp Network và lớp Storage — tương ứng với yêu cầu bảo vệ
    <em>Data in transit</em> và <em>Data at rest</em> theo GDPR Article 32.<br><br>

    <strong>Scenario 1 — MITM Attack (VULN-001):</strong>
    App chấp nhận User-installed CA → Burp Suite intercept POST /api/login →
    username &amp; password lộ dạng plaintext dù HTTPS.
    Fix: Network Security Config + Certificate Pinning.<br><br>

    <strong>Scenario 2 — Token Theft (VULN-002):</strong>
    App lưu JWT token vào <code>files/token.txt</code> dạng plaintext →
    ADB shell đọc trực tiếp không cần root →
    Attacker replay token để chiếm phiên đăng nhập.
    Fix: EncryptedSharedPreferences + Android Keystore + Root Detection.
  </div>

  <!-- ══════════════════════════════════════ -->
  <h2>2. Attack Chain — Kịch Bản Tấn Công Tổng Hợp</h2>
  <div class="box-red">
    Hai lỗ hổng kết hợp tạo thành một attack chain hoàn chỉnh:
    kẻ tấn công có thể chiếm toàn bộ tài khoản chỉ bằng free tools (Burp Suite + ADB).
  </div>
  <table>
    <tr>
      <th style="width:80px">Bước</th>
      <th style="width:160px">Kỹ thuật</th>
      <th>Chi tiết</th>
    </tr>
    {chain_rows}
  </table>

  <!-- ══════════════════════════════════════ -->
  <h2>3. Risk Assessment</h2>
  <table>
    <tr><th style="width:140px">Yếu tố</th><th>Mô tả</th></tr>
    {''.join(f"<tr><td><strong>{k}</strong></td><td>{v}</td></tr>" for k, v in RISK_MATRIX.items())}
  </table>

  <!-- ══════════════════════════════════════ -->
  <h2>4. Vulnerability Findings &amp; Compliance Mapping</h2>
  <table>
    <tr>
      <th style="width:90px">ID</th>
      <th>Lỗ hổng</th>
      <th style="width:80px">Severity</th>
      <th>OWASP</th>
      <th>ISO/IEC 27002</th>
      <th>GDPR</th>
      <th>Giải pháp</th>
    </tr>
    {rows}
  </table>

  <!-- ══════════════════════════════════════ -->
  <h2>5. Remediation</h2>

  <h3>5.1 Scenario 1 — Network Security Config + Certificate Pinning</h3>
  <div class="box">
    Áp dụng <code>res/xml/network_security_config.xml</code> với
    <code>cleartextTrafficPermitted="false"</code>, chỉ tin tưởng System CAs,
    và cấu hình Certificate Pinning SHA-256 trực tiếp trong XML (không phụ thuộc OkHttp).<br><br>
    Kết quả: App ném <code>SSLHandshakeException</code> khi phát hiện
    chứng chỉ không hợp lệ — Burp không nhận được request nào.
  </div>

  <h3>5.2 Scenario 2 — EncryptedSharedPreferences + Root Detection</h3>
  <div class="box">
    <strong>Bước 1:</strong> Xóa <code>token.txt</code> khỏi internal files storage.<br>
    <strong>Bước 2:</strong> Lưu token qua <code>EncryptedSharedPreferences</code>
    (AndroidX Security, AES-256-GCM). Keys được quản lý bởi Android Keystore —
    không đọc được kể cả qua ADB hay root.<br>
    <strong>Bước 3:</strong> Thêm Root Detection: App tự động gọi <code>finish()</code>
    và xóa token khi phát hiện thiết bị bị root hoặc chạy trên emulator không tin cậy.
  </div>

  <h3>5.3 Scenario 3 — MFA: Đúng Thứ Tự Triển Khai</h3>
  <div class="box">
    <strong>Phân tích quan trọng:</strong> MFA <em>không đủ</em> nếu transport layer chưa được bảo vệ.<br><br>
    Nếu thêm OTP mà chưa fix VULN-001: Burp intercept được cả
    <code>POST /api/login</code> lẫn <code>POST /api/verify-otp</code> —
    attacker relay OTP ngay lập tức trong cùng session window (30 giây).
    MFA hoàn toàn vô hiệu.<br><br>
    <strong>Thứ tự đúng:</strong><br>
    &nbsp;&nbsp;① Fix transport → Network Security Config + Certificate Pinning (VULN-001)<br>
    &nbsp;&nbsp;② Fix storage → EncryptedSharedPreferences (VULN-002)<br>
    &nbsp;&nbsp;③ Thêm MFA → TOTP (Google Authenticator) hoặc Android Biometric Prompt<br><br>
    Sau khi transport đã secure, MFA mới thực sự có giá trị:
    bảo vệ trước credential stuffing, phishing ngoài MITM context.
  </div>

  <!-- ══════════════════════════════════════ -->
  <table>
    <tr>
      <th>Tiêu chí</th>
      <th>Scenario 1 — MITM (VULN-001)</th>
      <th>Scenario 2 — Token Theft (VULN-002)</th>
    </tr>
    <tr><td>Attack vector</td>
        <td>Network (Wi-Fi proxy)</td>
        <td>Local device (ADB shell)</td></tr>
    <tr><td>Tool sử dụng</td>
        <td>Burp Suite Community</td>
        <td>ADB (Android SDK — có sẵn)</td></tr>
    <tr><td>Yêu cầu</td>
        <td>Cùng mạng Wi-Fi với nạn nhân</td>
        <td>Tiếp cận vật lý thiết bị (hoặc USB)</td></tr>
    <tr><td>Dữ liệu bị lộ</td>
        <td>Credentials in transit (username + password)</td>
        <td>JWT Token at rest → chiếm phiên</td></tr>
    <tr><td>OWASP</td>
        <td>M3: Insecure Communication</td>
        <td>M9: Insecure Data Storage</td></tr>
    <tr><td>Giải pháp</td>
        <td>Network Security Config + Cert Pinning</td>
        <td>EncryptedSharedPreferences + Keystore</td></tr>
    <tr><td>GDPR coverage</td>
        <td>Data in transit (Art.32)</td>
        <td>Data at rest (Art.32)</td></tr>
  </table>

  <!-- ══════════════════════════════════════ -->
  <h2>7. References</h2>
  <ul>
    <li>OWASP Mobile Security Testing Guide (MSTG) 2024</li>
    <li>OWASP Mobile Top 10 — M3: Insecure Communication, M4: Insufficient Authentication, M9: Insecure Data Storage</li>
    <li>ISO/IEC 27002:2022 Information Security Controls (8.24, 8.26, 8.10)</li>
    <li>GDPR Regulation (EU) 2016/679 — Article 32</li>
    <li>Android Developer Docs: Network Security Configuration</li>
    <li>Android Developer Docs: EncryptedSharedPreferences &amp; Android Keystore</li>
    <li>PortSwigger: Burp Suite Certificate Installation on Android</li>
  </ul>

</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    log_success(f"Báo cáo đã được lưu: {output_path}")


def main():
    print_banner("SECURITY AUDIT REPORT — Project 4")
    output = "reports/final_report.html"
    log_info(f"Đang sinh báo cáo → {output}")
    generate_html_report(output)
    log_success("Xong! Mở file HTML trong trình duyệt để xem báo cáo.")


if __name__ == "__main__":
    main()