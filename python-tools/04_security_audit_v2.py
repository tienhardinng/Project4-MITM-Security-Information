"""
04_security_audit_v2.py — Security Audit Report Generator
Project 4: Android MITM & Token Theft Lab

Covers:
  VULN-001 — M3: Insecure Communication (MITM via fake CA)
  VULN-002 — M9: Insecure Data Storage  (JWT token plaintext)
  VULN-003 — M3/M4: Missing MFA         (OTP bypass via MITM)

Usage:
    python python-tools/04_security_audit_v2.py
    → Output: reports/final_report.html
"""

import datetime
from pathlib import Path
from utils.logger import print_banner, log_info, log_success, log_warning


# ══════════════════════════════════════════════════════════════
# DATA — Findings, Risk, Attack Chain
# ══════════════════════════════════════════════════════════════

FINDINGS = [
    {
        "id"         : "VULN-001",
        "title"      : "Insecure Communication — User-installed CA Accepted",
        "severity"   : "CRITICAL",
        "cvss"       : "8.1",
        "description": (
            "App accepts User-installed CA certificates (src='user' in Network Security Config). "
            "An attacker who installs a fake CA (e.g. Burp Suite CA) into the device's User store "
            "can intercept all HTTPS traffic and read credentials in plaintext — "
            "despite the browser/app showing a valid HTTPS padlock."
        ),
        "evidence"   : (
            "Burp Suite HTTP History captured POST /api/login with "
            "{\"username\":\"admin\",\"password\":\"Secret@123\"} in plaintext "
            "over an HTTPS connection."
        ),
        "fix"        : (
            "1. Set network_security_config.xml to only trust System CAs (remove src='user'). "
            "2. Add Certificate Pinning (SHA-256 hash of server cert hardcoded in app). "
            "3. Set cleartextTrafficPermitted=false."
        ),
        "owasp"      : "OWASP Mobile Top 10 — M3: Insecure Communication",
        "iso"        : "ISO/IEC 27002:2022 — 8.24 (Cryptography), 8.26 (App Security)",
        "gdpr"       : "GDPR Article 32 — Data in transit protection",
        "status"     : "FIXED",
    },
    {
        "id"         : "VULN-002",
        "title"      : "Insecure Data Storage — JWT Token Stored as Plaintext",
        "severity"   : "HIGH",
        "cvss"       : "7.1",
        "description": (
            "After successful login, the app writes the JWT token to "
            "/data/data/com.demo.mitm/files/token.txt as plaintext. "
            "On Android emulators (which allow run-as without root), an attacker "
            "with USB access can read the token directly via ADB shell "
            "and replay it to authenticate as the victim — indefinitely, "
            "since the token has no expiry in the vulnerable server."
        ),
        "evidence"   : (
            "adb shell run-as com.demo.mitm cat /data/data/com.demo.mitm/files/token.txt "
            "→ returned JWT token. "
            "Token replayed to GET /api/profile → 200 OK with admin profile data."
        ),
        "fix"        : (
            "1. Remove token.txt — never store tokens as plaintext files. "
            "2. Use EncryptedSharedPreferences (AES-256-GCM via Android Keystore). "
            "3. Add token expiry on server (e.g. 15 minutes). "
            "4. Implement root/emulator detection."
        ),
        "owasp"      : "OWASP Mobile Top 10 — M9: Insecure Data Storage",
        "iso"        : "ISO/IEC 27002:2022 — 8.24 (Cryptography), 8.10 (Information deletion)",
        "gdpr"       : "GDPR Article 32 — Data at rest protection",
        "status"     : "FIXED",
    },
    {
        "id"         : "VULN-003",
        "title"      : "Missing MFA — OTP Bypassed via MITM Relay Attack",
        "severity"   : "MEDIUM",
        "cvss"       : "5.9",
        "description": (
            "The app authenticates with username/password only — no second factor. "
            "More critically: even if OTP/MFA is added, without fixing the transport layer (VULN-001), "
            "an attacker can steal the OTP in real-time via MITM and relay it within the 30-second "
            "validity window. MFA is only effective after transport is secured."
        ),
        "evidence"   : (
            "Server response to POST /api/login contained otp_generated field in plaintext. "
            "Attacker reads OTP from intercepted response and calls POST /api/verify-otp "
            "before the 30-second window expires → receives valid JWT token."
        ),
        "fix"        : (
            "Correct order: "
            "(1) Fix transport — Network Security Config + Certificate Pinning, "
            "(2) Fix storage — EncryptedSharedPreferences, "
            "(3) Add MFA — TOTP (RFC 6238) or Android BiometricPrompt."
        ),
        "owasp"      : "OWASP Mobile Top 10 — M3: Insecure Communication, M4: Insufficient Authentication",
        "iso"        : "ISO/IEC 27002:2022 — 8.05 (Secure authentication)",
        "gdpr"       : "GDPR Article 32 — Appropriate technical measures",
        "status"     : "PARTIAL",
    },
]

RISK_MATRIX = {
    "Threat"       : "MITM (network layer) + ADB Token Extraction (device layer)",
    "Vulnerability": "App trusts User CA; JWT token stored as plaintext file",
    "Likelihood"   : "HIGH — Both attacks use free tools (Burp Suite Community + ADB)",
    "Impact"       : "CRITICAL — Full account takeover: credentials + session token both exposed",
    "Risk Level"   : "CRITICAL",
}

ATTACK_CHAIN = [
    ("Step 1", "MITM Setup",
     "Install Burp CA into AVD User store. Set AVD proxy → 10.0.2.2:8080."),
    ("Step 2", "Credential Theft",
     "Intercept POST /api/login → {\"username\":\"admin\",\"password\":\"Secret@123\"} visible in plaintext."),
    ("Step 2b", "MFA Bypass (optional)",
     "Server response contains otp_generated. Attacker relays OTP to POST /api/verify-otp within 30s."),
    ("Step 3", "Token Extraction",
     "adb shell run-as com.demo.mitm cat /data/data/com.demo.mitm/files/token.txt → JWT token plaintext."),
    ("Step 4", "Session Hijack",
     "Replay stolen token to GET /api/profile → 200 OK. Full account access without password."),
]

BEFORE_AFTER = [
    ("Block User CA",            "✅ Vulnerable",  "✅ Hardened (System CA only)"),
    ("Block fake System CA",     "❌ No pinning",  "✅ Certificate Pinning (SHA-256)"),
    ("Block cleartext HTTP",     "❌ Allowed",     "✅ cleartextTrafficPermitted=false"),
    ("Token storage",            "❌ Plaintext file", "✅ EncryptedSharedPreferences"),
    ("Token expiry",             "❌ No expiry",   "✅ 15-minute expiry (server_hard.js)"),
    ("TLS version control",      "❌ Any TLS",     "✅ TLS 1.2+ only"),
    ("Security headers (HSTS)",  "❌ None",        "✅ HSTS + CSP + X-Frame-Options"),
    ("Runtime proxy detection",  "❌ None",        "✅ Suspicious header logging"),
]


# ══════════════════════════════════════════════════════════════
# HTML GENERATOR
# ══════════════════════════════════════════════════════════════

def generate_html_report(output_path: str) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Findings rows
    finding_rows = ""
    for f in FINDINGS:
        color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706"}.get(f["severity"], "#666")
        status_color = {"FIXED": "#16a34a", "PARTIAL": "#d97706", "OPEN": "#dc2626"}.get(f["status"], "#666")
        finding_rows += f"""
        <tr>
          <td><code>{f['id']}</code></td>
          <td><strong>{f['title']}</strong><br>
              <small style="color:#64748b">{f['description'][:120]}...</small></td>
          <td style="color:{color};font-weight:bold">{f['severity']}<br>
              <small>CVSS {f['cvss']}</small></td>
          <td style="font-size:13px">{f['owasp']}</td>
          <td style="font-size:13px">{f['iso']}</td>
          <td style="font-size:13px">{f['gdpr']}</td>
          <td style="color:{status_color};font-weight:bold">{f['status']}</td>
        </tr>"""

    # Attack chain rows
    chain_rows = ""
    for step, name, detail in ATTACK_CHAIN:
        chain_rows += f"""
        <tr>
          <td><strong>{step}</strong></td>
          <td><strong>{name}</strong></td>
          <td style="font-family:monospace;font-size:13px;color:#1e293b">{detail}</td>
        </tr>"""

    # Before/After rows
    ba_rows = ""
    for feature, before, after in BEFORE_AFTER:
        ba_rows += f"""
        <tr>
          <td>{feature}</td>
          <td style="color:#dc2626">{before}</td>
          <td style="color:#16a34a">{after}</td>
        </tr>"""

    # Risk rows
    risk_rows = "".join(
        f"<tr><td><strong>{k}</strong></td><td>{v}</td></tr>"
        for k, v in RISK_MATRIX.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit Report — Project 4</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      max-width: 1000px; margin: 40px auto; padding: 0 20px;
      color: #1e293b; line-height: 1.7; background: #f8fafc;
    }}
    .card {{
      background: white; border-radius: 12px; padding: 32px;
      margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }}
    h1 {{ font-size: 28px; color: #0f172a; margin-bottom: 4px; }}
    h2 {{ font-size: 20px; color: #1d4ed8; margin-bottom: 16px;
          padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
    h3 {{ font-size: 16px; color: #374151; margin: 16px 0 8px; }}
    .meta {{ color: #64748b; font-size: 14px; margin-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th {{ background: #1e293b; color: white; padding: 10px 12px; text-align: left; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: #f8fafc; }}
    code {{
      background: #e2e8f0; padding: 2px 6px; border-radius: 4px;
      font-family: 'Consolas', monospace; font-size: 13px;
    }}
    .box {{
      background: #eff6ff; border-left: 4px solid #1d4ed8;
      padding: 14px 18px; border-radius: 0 8px 8px 0; margin: 12px 0;
    }}
    .box-red {{
      background: #fff5f5; border-left: 4px solid #dc2626;
      padding: 14px 18px; border-radius: 0 8px 8px 0; margin: 12px 0;
    }}
    .box-green {{
      background: #f0fdf4; border-left: 4px solid #16a34a;
      padding: 14px 18px; border-radius: 0 8px 8px 0; margin: 12px 0;
    }}
    .badge {{
      display: inline-block; padding: 3px 10px; border-radius: 20px;
      font-size: 12px; font-weight: 600;
    }}
    .badge-critical {{ background: #fee2e2; color: #dc2626; }}
    .badge-high     {{ background: #ffedd5; color: #ea580c; }}
    .badge-medium   {{ background: #fef9c3; color: #d97706; }}
    .header-banner {{
      background: linear-gradient(135deg, #0f172a 0%, #1d4ed8 100%);
      color: white; padding: 32px; border-radius: 12px;
      margin-bottom: 24px;
    }}
    .header-banner h1 {{ color: white; }}
    .header-banner .meta {{ color: #93c5fd; }}
  </style>
</head>
<body>

  <!-- HEADER -->
  <div class="header-banner">
    <h1>🔐 Security Audit Report</h1>
    <p class="meta">Project 4 — Android MITM &amp; Token Theft Lab</p>
    <p class="meta">Generated: {now} &nbsp;|&nbsp; Project 4</p>
    <p class="meta">
      <span class="badge badge-critical">VULN-001 CRITICAL</span>&nbsp;
      <span class="badge badge-high">VULN-002 HIGH</span>&nbsp;
      <span class="badge badge-medium">VULN-003 MEDIUM</span>
    </p>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="card">
    <h2>1. Executive Summary</h2>
    <div class="box">
      This lab demonstrates <strong>2 critical security vulnerabilities</strong> on an Android app,
      covering both the <em>Network layer</em> (Data in transit) and <em>Storage layer</em>
      (Data at rest) — directly mapped to GDPR Article 32 requirements.<br><br>
      <strong>VULN-001 — MITM Attack:</strong>
      App trusts User-installed CA → Burp Suite intercepts HTTPS →
      credentials exposed as plaintext. Fixed with Network Security Config + Certificate Pinning.<br><br>
      <strong>VULN-002 — Token Theft:</strong>
      JWT token stored as plaintext file → ADB shell reads it without root →
      attacker replays token for persistent access. Fixed with EncryptedSharedPreferences + Keystore.
    </div>
  </div>

  <!-- ATTACK CHAIN -->
  <div class="card">
    <h2>2. Attack Chain</h2>
    <div class="box-red">
      Both vulnerabilities chain together to form a complete account takeover
      using only free tools (Burp Suite Community + ADB).
    </div>
    <table>
      <tr><th width="80">Step</th><th width="180">Technique</th><th>Detail</th></tr>
      {chain_rows}
    </table>
  </div>

  <!-- RISK ASSESSMENT -->
  <div class="card">
    <h2>3. Risk Assessment</h2>
    <table>
      <tr><th width="140">Factor</th><th>Description</th></tr>
      {risk_rows}
    </table>
  </div>

  <!-- FINDINGS -->
  <div class="card">
    <h2>4. Vulnerability Findings &amp; Compliance Mapping</h2>
    <table>
      <tr>
        <th width="90">ID</th>
        <th>Vulnerability</th>
        <th width="90">Severity</th>
        <th>OWASP</th>
        <th>ISO/IEC 27002</th>
        <th>GDPR</th>
        <th width="80">Status</th>
      </tr>
      {finding_rows}
    </table>
  </div>

  <!-- BEFORE / AFTER -->
  <div class="card">
    <h2>5. Before vs After Security Hardening</h2>
    <table>
      <tr>
        <th width="220">Security Feature</th>
        <th width="220">Vulnerable Version</th>
        <th>Hardened Version</th>
      </tr>
      {ba_rows}
    </table>
  </div>

  <!-- REMEDIATION -->
  <div class="card">
    <h2>6. Remediation Details</h2>

    <h3>6.1 Network Security Config + Certificate Pinning</h3>
    <div class="box">
      Remove <code>src="user"</code> from <code>network_security_config.xml</code>.
      Only trust System CAs. Add SHA-256 Certificate Pin.
      Result: App throws <code>SSLHandshakeException</code> — Burp receives 0 bytes.
    </div>

    <h3>6.2 EncryptedSharedPreferences + Token Expiry</h3>
    <div class="box">
      Replace <code>token.txt</code> with <code>EncryptedSharedPreferences</code>
      (AES-256-GCM, Android Keystore). Keys are hardware-bound — unreadable even via ADB or root.
      Server-side token expiry: 15 minutes (<code>server_hard.js</code>).
    </div>

    <h3>6.3 MFA — Correct Implementation Order</h3>
    <div class="box-red">
      <strong>Critical insight:</strong> MFA is ineffective if transport layer is not secured first.
      Without fixing VULN-001, MITM can steal OTP in real-time and relay it within 30 seconds.
    </div>
    <div class="box-green">
      <strong>Correct order:</strong><br>
      ① Fix transport — Network Security Config + Certificate Pinning (VULN-001)<br>
      ② Fix storage — EncryptedSharedPreferences (VULN-002)<br>
      ③ Add MFA — TOTP (RFC 6238 / Google Authenticator) or Android BiometricPrompt
    </div>
  </div>

  <!-- REFERENCES -->
  <div class="card">
    <h2>7. References</h2>
    <ul style="padding-left:20px;line-height:2">
      <li>OWASP Mobile Security Testing Guide (MSTG) 2024</li>
      <li>OWASP Mobile Top 10 — M3, M4, M9</li>
      <li>ISO/IEC 27002:2022 — Controls 8.05, 8.10, 8.24, 8.26</li>
      <li>GDPR (EU) 2016/679 — Article 32: Security of processing</li>
      <li>Android Docs: Network Security Configuration</li>
      <li>Android Docs: EncryptedSharedPreferences &amp; Android Keystore</li>
      <li>PortSwigger: Burp Suite CA Installation on Android</li>
    </ul>
  </div>

</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    log_success(f"Report saved: {output_path}")


def main():
    print_banner("SECURITY AUDIT REPORT — Project 4")
    log_info("Generating report...")

    output = "reports/final_report.html"
    generate_html_report(output)

    log_success("Done! Open reports/final_report.html in browser.")
    log_warning("Screenshot this terminal + the HTML report for SS-23 and SS-24!")


if __name__ == "__main__":
    main()