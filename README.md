# 🔐 Project 4 — Android MITM & Token Theft Lab

> **Academic Security Demo** | OWASP Mobile Top 10: M3 · M4 · M9

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org)
[![Android](https://img.shields.io/badge/Android-API%2029+-brightgreen.svg)](https://developer.android.com)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Community-orange.svg)](https://portswigger.net)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Repository Structure](#-repository-structure)
- [Prerequisites](#-prerequisites)
- [Setup Guide](#-setup-guide)
- [Demo Walkthrough](#-demo-walkthrough)
- [Attack Mechanics](#-attack-mechanics)
- [Defense Mechanisms](#-defense-mechanisms)
- [Victim Scenario](#-victim-scenario)
- [Compliance Mapping](#-compliance-mapping)
- [References](#-references)

---

## 📖 Overview

This lab demonstrates **three real-world Android security vulnerabilities** and their fixes:

| ID | Vulnerability | Severity | Status |
|----|--------------|----------|--------|
| VULN-001 | Insecure Communication — Fake CA accepted via MITM | 🔴 CRITICAL | FIXED |
| VULN-002 | Insecure Data Storage — JWT token stored as plaintext | 🟠 HIGH | FIXED |
| VULN-003 | Missing MFA — OTP bypassed via MITM relay attack | 🟡 MEDIUM | PARTIAL |

**Key insight:** The victim **voluntarily types their own credentials** — they are never forced or coerced. MITM is invisible. The padlock icon still shows green. The victim has no idea they are being watched.

---

## 🗂️ Repository Structure

This project spans **two repositories** and **three branches**:

```
GitHub
│
├── Repo: Project4-MITM-Security-Information
│   └── branch: main
│       ├── dummy-server/
│       │   ├── server.js           # Vulnerable HTTPS server (Trust All, no expiry)
│       │   ├── server_hard.js      # Hardened server (TLS 1.2+, HSTS, rate limit, token expiry)
│       │   ├── cert.pem            # Fixed self-signed cert (generated once, reused)
│       │   └── key.pem
│       ├── python-tools/
│       │   ├── utils/
│       │   │   ├── logger.py       # Rich terminal logging
│       │   │   └── adb_helper.py   # ADB command wrapper
│       │   ├── 01_check_env.py     # Environment verifier
│       │   ├── 02_capture_traffic.py  # Traffic analyzer (HAR + phase simulation)
│       │   ├── 03_storage_audit.py    # Token storage auditor (attack/defense phases)
│       │   └── 04_security_audit_v2.py  # HTML report generator
│       └── reports/
│           └── final_report.html   # Auto-generated security audit report
│
└── Repo: Project4-MITM-Lab  (Android App)
    ├── branch: android-vulnerable   ← HACK version
    │   ├── MainActivity.kt          # Trust ALL certs, saves token to plaintext file
    │   └── network_security_config.xml  # Accepts User CA (src="user")
    │
    └── branch: android-hardened     ← DEFENSE version
        ├── MainActivity.kt          # EncryptedSharedPreferences, no Trust All
        └── network_security_config.xml  # System CA only, no User CA
```

---

## 💻 Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | ≥ 3.10 | Analysis scripts & report generation |
| Node.js | ≥ 18 LTS | Dummy HTTPS server |
| Android Studio | Latest | Build & run Android app |
| Burp Suite Community | Latest | MITM proxy / traffic interception |
| ADB (Android SDK) | Latest | Token extraction demo |
| Git | Any | Branch switching between vulnerable/hardened |

**Android Virtual Device:**
```
Device  : Pixel 6
API     : 34 (Android 14)
```

---

## ⚙️ Setup Guide

### Step 1 — Clone repositories

```bash
# Python tools + Server
git clone https://github.com/tienhardinng/Project4-MITM-Security-Information.git
cd Project4-MITM-Security-Information
pip install -r python-tools/requirements.txt
cd dummy-server && npm install && cd ..

# Android App
git clone https://github.com/tienhardinng/Project4-MITM-Lab.git
```

### Step 2 — Create AVD
```
Android Studio → Tools → Device Manager → +
Device: Pixel 6 | API: 34 → Finish
```

### Step 3 — Install Burp CA into AVD (one-time)
```
1. Burp Suite → Proxy → Proxy Settings
   → Export CA Certificate → DER format → save cacert.der

2. adb -s emulator-5554 push cacert.der /sdcard/Download/cacert.der

3. AVD: Settings → Security → Encryption & Credentials
   → Install a certificate → CA certificate → cacert.der

4. Verify: Settings → Trusted Credentials → User tab → "PortSwigger" ✓
```

### Step 4 — Configure AVD Proxy
```
AVD: Settings → Network & Internet → Wi-Fi → AndroidWifi ✏️
→ Proxy: Manual | Host: 10.0.2.2 | Port: 8080 → Save
```

---

## 🎬 Demo Walkthrough

### Startup Sequence (every demo session)

```powershell
# Terminal 1 — Start vulnerable server
cd dummy-server
node server.js
# → [SERVER] HTTPS Listening on port 3000

# Terminal 2 — Keep for ADB + Python commands
cd Project4-MITM-Security-Information
$env:PYTHONPATH = "python-tools"

# Android Studio → ▶ Run (Shift+F10) to build & install app
```

---

### 🔴 PHASE 1 — ATTACK: MITM Credential Theft (VULN-001)

**App branch:** `android-vulnerable`
```powershell
cd Project4-MITM-Lab
git checkout android-vulnerable
# Android Studio → Shift+F10
```

**Demo steps:**
1. Burp Suite → Proxy → `Intercept is OFF`
2. Open app on AVD → Enter `admin / Secret@123` → tap **Login**
3. Burp → HTTP History → click `POST /api/login` → **Response** tab
4. Credentials visible in plaintext:
```json
{"username": "admin", "password": "Secret@123"}
```
5. Response also contains OTP (VULN-003):
```json
{"mfa": {"otp_generated": "847291", "expires_in": 30}}
```

**📸 Screenshot: Burp HTTP History showing password in plaintext**

---

### 🔴 PHASE 2 — ATTACK: Token Theft via ADB (VULN-002)

**While still on `android-vulnerable` branch:**

```powershell
# Read JWT token directly from app storage — no root required
adb -s emulator-5554 shell run-as com.demo.mitm cat /data/data/com.demo.mitm/files/token.txt
# → eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123

# Replay stolen token → access API without password
node -e "
const https = require('https');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const req = https.request({
  hostname: '127.0.0.1', port: 3000, path: '/api/profile', method: 'GET',
  headers: { Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123' }
}, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>console.log(d)); });
req.end();
"
# → {"status":"ok","username":"admin","role":"admin"}
```

**📸 Screenshot: ADB reads token + API returns 200 OK with stolen token**

---

### 🟢 PHASE 3 — DEFENSE: Network Security Config (VULN-001 Fix)

**Switch to hardened branch:**
```powershell
git checkout android-hardened
# Android Studio → Shift+F10
```

**Demo steps:**
1. Keep Burp CA still installed on AVD
2. Keep proxy still pointing to Burp
3. Login again on AVD → app shows:
```
CertPathValidatorException: Trust anchor for certification path not found
```
4. Burp HTTP History → **no new request** — 0 bytes intercepted

**📸 Screenshot: SSLHandshakeException on AVD + empty Burp history**

---

### 🟢 PHASE 4 — DEFENSE: Token Storage Fix (VULN-002 Fix)

**Switch to hardened server:**
```powershell
# Ctrl+C stop server.js
node server_hard.js
# → TLS 1.2+, HSTS, token expiry 15 min
```

```powershell
# Verify token.txt no longer exists
adb -s emulator-5554 shell run-as com.demo.mitm cat /data/data/com.demo.mitm/files/token.txt
# → cat: No such file or directory  ✓

# Old token rejected by server_hard.js
node -e "... same replay request ..."
# → 401 Unauthorized — token expired  ✓
```

**📸 Screenshot: No such file + 401 Unauthorized**

---

### 📊 PHASE 5 — Generate Report

```powershell
cd Project4-MITM-Security-Information
$env:PYTHONPATH = "python-tools"

# Environment check
python python-tools/01_check_env.py

# Storage audit
python python-tools/03_storage_audit.py --phase attack
python python-tools/03_storage_audit.py --phase defense

# Generate HTML report
python python-tools/04_security_audit_v2.py
start reports/final_report.html
```

---

## ⚔️ Attack Mechanics

### How MITM Works (VULN-001)

```
Victim's Phone              Hacker (Burp Suite)          Real Server
      │                            │                           │
      │── POST /api/login ────────▶│                           │
      │   {user, pass}             │──── relay ───────────────▶│
      │                            │◀─── response + OTP ───────│
      │◀── {token, otp_hint} ──────│                           │
      │                            │                           │
      │                    Hacker sees:                        │
      │                    - username + password               │
      │                    - JWT token                         │
      │                    - OTP (if MFA enabled)              │
```

**Why it works:** Android allows User-installed CAs by default. Burp acts as a "trusted" CA between the app and the real server. The app encrypts data to Burp's fake certificate — thinking it's talking to the real server.

### How Token Theft Works (VULN-002)

```
Physical access / USB cable
        ↓
adb shell run-as com.demo.mitm
        ↓
cat /data/data/com.demo.mitm/files/token.txt
        ↓
JWT token in plaintext
        ↓
curl -H "Authorization: Bearer <token>" /api/profile
        ↓
Full account access — no password needed
        ↓
Token works indefinitely (no expiry in vulnerable server)
```

### MFA Bypass Timeline (VULN-003)

```
T+0s   Victim taps Login → POST /api/login intercepted
T+0s   Server generates OTP → sent to victim's SMS
T+0s   Hacker reads OTP from Burp response (otp_hint field)
T+5s   Victim receives SMS, types OTP into app
T+5s   POST /api/verify-otp intercepted → hacker reads OTP again
T+6s   Hacker relays OTP to server before victim's request
T+6s   Server issues token to hacker
T+30s  OTP expires — but hacker already has the token
```

---

## 🛡️ Defense Mechanisms

### VULN-001 Fix — Network Security Config

```xml
<!-- VULNERABLE: accepts Burp CA -->
<certificates src="system" />
<certificates src="user" />   ← remove this line

<!-- HARDENED: System CAs only -->
<certificates src="system" />
```

Result: `SSLHandshakeException` — connection terminated before any data is sent.

### VULN-002 Fix — EncryptedSharedPreferences

```kotlin
// VULNERABLE: plaintext file
File(filesDir, "token.txt").writeText(token)

// HARDENED: AES-256-GCM via Android Keystore
val prefs = EncryptedSharedPreferences.create(
    "secure_prefs",
    MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
prefs.edit().putString("token", token).apply()
```

### Before vs After

| Security Feature | Vulnerable | Hardened |
|-----------------|-----------|----------|
| Block User CA | ❌ Accepts all | ✅ System CA only |
| Certificate Pinning | ❌ None | ✅ SHA-256 pin |
| Cleartext HTTP | ❌ Allowed | ✅ Blocked |
| Token storage | ❌ Plaintext file | ✅ EncryptedSharedPreferences |
| Token expiry | ❌ Never expires | ✅ 15 minutes |
| TLS version | ❌ Any | ✅ TLS 1.2+ only |
| HSTS header | ❌ None | ✅ max-age=31536000 |
| Proxy detection | ❌ None | ✅ Suspicious header logging |

---

## 👤 Victim Scenario

**The victim never knows they are being attacked.**

> Sarah is having coffee at a café. She connects to the free Wi-Fi "Coffee_Free_WiFi" — which is actually a rogue access point set up by an attacker nearby.
>
> She opens her banking app, which shows a green HTTPS padlock. She types her username and password, then taps Login. The app shows "Login successful."
>
> Meanwhile, on the attacker's laptop, Burp Suite has just logged:
> `{"username": "sarah@bank.com", "password": "MyP@ss2024"}`
>
> Later, the attacker plugs a USB cable into the charging port at the café table (a common "juice jacking" setup) and runs `adb shell run-as` to extract her JWT token — then accesses her account from anywhere in the world.

**Why MITM is dangerous:**
- Victim **voluntarily types** their own credentials
- App shows a **valid HTTPS padlock** — no warning
- Attack is **completely silent** — no alerts, no notifications
- Works on **any public Wi-Fi** where proxy can be configured

---

## 📊 Compliance Mapping

| Standard | Clause | Violation | Fix Applied |
|---------|--------|-----------|-------------|
| OWASP Mobile Top 10 | M3: Insecure Communication | App accepts User CA → MITM possible | Network Security Config |
| OWASP Mobile Top 10 | M9: Insecure Data Storage | JWT token in plaintext file | EncryptedSharedPreferences |
| OWASP Mobile Top 10 | M4: Insufficient Authentication | No MFA, OTP bypassable via MITM | Certificate Pinning first |
| ISO/IEC 27002:2022 | 8.24 — Use of cryptography | TLS misconfigured | TLS 1.2+, cert pinning |
| ISO/IEC 27002:2022 | 8.26 — Application security | Insecure design | Secure coding practices |
| ISO/IEC 27002:2022 | 8.10 — Information deletion | Token persists after logout | Token expiry + secure storage |
| GDPR Article 32 | Security of processing | Data in transit unprotected | Network Security Config |
| GDPR Article 32 | Security of processing | Data at rest unprotected | EncryptedSharedPreferences |

---

## 📚 References

- [OWASP Mobile Security Testing Guide (MSTG) 2024](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/network-security-config)
- [Android EncryptedSharedPreferences](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
- [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html)
- [GDPR Article 32](https://gdpr-info.eu/art-32-gdpr/)
- [PortSwigger — Burp Suite CA on Android](https://portswigger.net/burp/documentation/desktop/mobile-testing)

---

> ⚠️ **Disclaimer:** This project is created strictly for academic and security research purposes.
> Do not use any techniques demonstrated here against real systems without explicit written authorization.