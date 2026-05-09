# 🔐 Project 4 — Android MITM Attack Lab

> **Academic Security Demo** | OWASP Mobile Top 10 - M3: Insecure Communication

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org)
[![Android](https://img.shields.io/badge/Android-API%2029+-brightgreen.svg)](https://developer.android.com)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Community-orange.svg)](https://portswigger.net)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Demo Flow](#-demo-flow)
- [Compliance Mapping](#-compliance-mapping)
- [Troubleshooting](#-troubleshooting)
- [References](#-references)
- [Author](#-author)

---

## 📖 Overview

This project is an **academic security lab** demonstrating a **Man-In-The-Middle (MITM)** attack on an Android application using a forged CA certificate (Burp Suite CA).

The lab simulates a real-world attack scenario where a malicious actor installs a fake Certificate Authority into an Android device, intercepting HTTPS traffic and stealing user credentials in plaintext — even though the connection appears secure (HTTPS with padlock icon).

### Demo Phases:
| Phase | Description |
|-------|-------------|
| **2.1 — The Hack** | Install Burp CA → Configure proxy → Intercept HTTPS → Steal credentials |
| **2.2 — Security Hardening** | Apply Network Security Config → Trust System CAs only |
| **2.3 — Proof of Defense** | Re-attack → App throws SSLHandshakeException → No data intercepted |

### Vulnerability Exploited:
> **OWASP Mobile Top 10 - M3: Insecure Communication**
> The app accepts User-installed CA certificates, allowing an attacker to perform MITM and read credentials in plaintext despite HTTPS being used.

---

## 🗂️ Project Structure

```
Project4_MITM_Lab/
│
├── 📁 dummy-server/                # Node.js HTTPS dummy server
│   ├── server.js                   # HTTPS server with self-signed cert
│   └── package.json
│
├── 📁 python-tools/                # Analysis & reporting tools
│   ├── 📁 utils/
│   │   ├── __init__.py
│   │   ├── logger.py               # Rich logging utility
│   │   └── adb_helper.py           # ADB command wrapper
│   ├── requirements.txt
│   ├── 01_check_env.py             # Environment checker
│   ├── 02_capture_traffic.py       # Traffic analyzer
│   └── 04_security_audit.py        # HTML report generator
│
├── 📁 reports/                     # Auto-generated reports
│   └── 📁 raw_logs/
│
└── README.md
```

> **Android App** is stored separately at: [MITMDemo-Android](https://github.com/tienhardinng/MITMDemo-Android)# 🎬 DEMO RUNBOOK — Android MITM Attack Lab
### Complete Guide for Fresh Start / New Machine

---

## ⚡ QUICK CHECKLIST (Print this out!)

```
PRE-DEMO (15 phút trước):
[ ] 1. Start Burp Suite
[ ] 2. Start node server.js  
[ ] 3. Start Android Studio + AVD
[ ] 4. Verify Burp CA installed on AVD
[ ] 5. Verify AVD proxy configured
[ ] 6. Build & install app on AVD
[ ] 7. Test login once to confirm working

DEMO ORDER:
[ ] Phase 2.1 — Show password stolen in Burp
[ ] Phase 2.2 — Fix: change network_security_config.xml
[ ] Phase 2.3 — Re-attack: SSLHandshakeException
[ ] Certificate Pinning demo
[ ] Run Python tools + show HTML report
```

---

## 📦 PART 1 — ONE-TIME SOFTWARE INSTALLATION

### 1.1 Python 3.10+
- Download: https://python.org/downloads
- ✅ CHECK "Add Python to PATH" during install
```powershell
# Verify
python --version
# Expected: Python 3.10.x or higher
```

### 1.2 Node.js 18 LTS
- Download: https://nodejs.org (choose LTS)
```powershell
# Verify
node --version    # v18.x.x or higher
npm --version     # 9.x.x or higher
```

### 1.3 Android Studio
- Download: https://developer.android.com/studio
- Install with default settings
- On first launch → install Android SDK when prompted
```powershell
# Verify ADB
adb version
# If not found, add to PATH:
# C:\Users\YOUR_NAME\AppData\Local\Android\Sdk\platform-tools
```

### 1.4 Burp Suite Community Edition
- Download: https://portswigger.net/burp/communitydownload
- Install with default settings

### 1.5 Git
- Download: https://git-scm.com
```powershell
git --version
```

---

## 📥 PART 2 — ONE-TIME PROJECT SETUP

### 2.1 Clone repos
```powershell
cd C:\Users\YOUR_NAME\Downloads

# Clone Python tools + Server
git clone https://github.com/tienhardinng/Project4-MITM-Security-Information.git
cd Project4-MITM-Security-Information
```

### 2.2 Install Python dependencies
```powershell
# Inside Project4-MITM-Security-Information folder
pip install -r python-tools/requirements.txt
```

### 2.3 Install Node.js dependencies
```powershell
cd dummy-server
npm install
cd ..
```

### 2.4 Open Android project in Android Studio
```
Android Studio → Open → Select MITMDemo folder
Wait for Gradle sync (5-10 minutes first time)
```

### 2.5 Create AVD (one time only)
```
Android Studio → Tools → Device Manager → +
Device   : Pixel 6
API      : 34 (Android 14) → Download if needed
→ Next → Finish
```

---

## 🔐 PART 3 — ONE-TIME BURP CA SETUP

### 3.1 Open Burp Suite
```
Launch Burp Suite
→ Temporary project → Next
→ Use Burp defaults → Start Burp
```

### 3.2 Verify Proxy listener
```
Proxy → Proxy Settings → Proxy Listeners
→ Must show: 127.0.0.1:8080 Running ✓
→ If missing: Add → Port: 8080 → OK
```

### 3.3 Export Burp CA Certificate
```
Proxy → Proxy Settings
→ Import/export CA certificate
→ Export → Certificate in DER format → Next
→ Save as: C:\Users\YOUR_NAME\Downloads\cacert.der
```

### 3.4 Start AVD first
```
Android Studio → Device Manager → ▶ Play (Pixel 6)
Wait for AVD to fully boot
```

### 3.5 Push CA to AVD
```powershell
# Check which emulator is running
adb devices
# Expected: emulator-5556    device

# Push certificate
adb -s emulator-5556 push C:\Users\YOUR_NAME\Downloads\cacert.der /sdcard/Download/cacert.der
# Expected: 1 file pushed
```

### 3.6 Install CA on AVD
On AVD screen:
```
Settings
→ Security & Privacy
→ More Security Settings
→ Encryption & Credentials
→ Install a certificate
→ CA certificate
→ Install Anyway
→ Select cacert.der from Downloads
```

Verify:
```
Settings → Security → Trusted Credentials → USER tab
→ Must see: "PortSwigger" ✓
```

### 3.7 Configure AVD Proxy
On AVD screen:
```
Settings
→ Network & Internet
→ Wi-Fi
→ AndroidWifi → click ⚙️ gear icon
→ Edit ✏️ (pencil icon top right)
→ Advanced Options
→ Proxy: Manual
→ Proxy hostname: 10.0.2.2
→ Proxy port: 8080
→ Save
```

---

## 🔑 PART 4 — GET CERTIFICATE PIN (One time per machine)

### 4.1 Start server to generate cert
```powershell
cd C:\Users\YOUR_NAME\Downloads\Project4-MITM-Security-Information\dummy-server
node server.js
```

First run output:
```
[SERVER] Generated and saved new certificate
[SERVER] Certificate SHA-256 Pin: sha256/XXXX...   ← COPY THIS!
[SERVER] HTTPS Listening on port 3000
```

> ⚠️ If shows "Loaded existing certificate" → cert.pem already exists, hash is fixed.
> Run this to get hash:
```powershell
node -e "
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const pemCert = fs.readFileSync('cert.pem', 'utf8');
const cert = forge.pki.certificateFromPem(pemCert);
const publicKeyDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(cert.publicKey)).getBytes();
const derBuffer = Buffer.from(publicKeyDer, 'binary');
const hash = crypto.createHash('sha256').update(derBuffer).digest('base64');
console.log('sha256/' + hash);
"
```

### 4.2 Update pin in Android app
Open `MainActivity.kt` in Android Studio:
```kotlin
// Find this line and update hash:
private const val SERVER_PIN = "sha256/PASTE_YOUR_HASH_HERE="
```

> 💡 If pinning fails, the error message shows "Got: sha256/XXXX" — use THAT hash!

---

## 🎬 PART 5 — DEMO EXECUTION (Every time)

### ═══ STARTUP SEQUENCE ═══

**Step 1 — Terminal 1: Start Server**
```powershell
cd C:\Users\YOUR_NAME\Downloads\Project4-MITM-Security-Information\dummy-server
node server.js
# Must see: [SERVER] HTTPS Listening on port 3000
# KEEP THIS TERMINAL OPEN!
```

**Step 2 — Burp Suite**
```
Open Burp Suite → Temporary project → Start Burp
Proxy → Intercept → Intercept is OFF
Proxy → HTTP History (keep this tab open)
```

**Step 3 — Android Studio: Start AVD**
```
Tools → Device Manager → ▶ Play (Pixel 6)
Wait for AVD to fully boot
```

**Step 4 — Android Studio: Build & Install App**
```
Press Shift+F10  (or click ▶ green Run button)
Wait for build and install (~1-2 minutes)
App will auto-launch on AVD
```

**Step 5 — Verify setup**
```
AVD: Open Settings → Security → Trusted Credentials → User
→ Must see PortSwigger ✓

AVD: Settings → Network → Wi-Fi → AndroidWifi
→ Must show proxy 10.0.2.2:8080 ✓
```

---

### ═══ PHASE 2.1 — THE HACK ═══

**Goal: Show password stolen in Burp despite HTTPS**

1. On AVD, open MITMDemo app
2. Enter credentials:
   ```
   Username: admin
   Password: Secret@123
   ```
3. Tap **Login**
4. Switch to Burp Suite → HTTP History tab
5. Find row with `POST /api/login` → click it
6. Bottom panel shows:
   ```
   POST /api/login HTTP/1.1
   Host: 10.0.2.2:3000
   ...
   {"username":"admin","password":"Secret@123"}
   ```

**📸 SCREENSHOT THIS — Evidence of attack!**

---

### ═══ PHASE 2.2 — SECURITY HARDENING ═══

**Goal: Apply Network Security Config**

In Android Studio, open:
`app/src/main/res/xml/network_security_config.xml`

Change to (remove `src="user"`):
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

Rebuild: **Shift+F10**

---

### ═══ PHASE 2.3 — PROOF OF DEFENSE ═══

**Goal: Show attack fails after hardening**

1. Keep Burp CA still installed on AVD
2. Keep proxy still pointing to Burp
3. Login again on AVD
4. AVD shows: `SSLHandshakeException` ✓
5. Burp HTTP History: No new request ✓

**📸 SCREENSHOT BOTH — Evidence of defense!**

---

### ═══ CERTIFICATE PINNING DEMO ═══

**Goal: Show advanced protection against System CA attacks**

App already has Certificate Pinning in `MainActivity.kt`:
```kotlin
private const val SERVER_PIN = "sha256/YOUR_HASH"
```

**How it works:**
- Even if attacker installs CA into System store
- App checks certificate hash directly
- Any cert mismatch → connection refused immediately

**Demo:**
1. Login with correct server running → Success ✓
2. Stop server → Start different server (different cert)
3. Login → `Certificate pinning failed!` ✓

---

### ═══ PYTHON TOOLS ═══

**Terminal 2** (new terminal, keep server running in Terminal 1):
```powershell
cd C:\Users\YOUR_NAME\Downloads\Project4-MITM-Security-Information
$env:PYTHONPATH = "python-tools"

# Step 1: Check environment
python python-tools/01_check_env.py

# Step 2: Show vulnerable phase analysis
python python-tools/02_capture_traffic.py --phase vulnerable --file reports/raw_logs/captured.har

# Step 3: Show hardened phase analysis  
python python-tools/02_capture_traffic.py --phase hardened

# Step 4: Generate HTML report
python python-tools/04_security_audit.py

# Step 5: Open report in browser
start reports/final_report.html
```

---

## 🔄 PART 6 — RESTART AFTER CLOSING EVERYTHING

If you closed all apps and need to restart:

```
ORDER MATTERS!

1. Start Burp Suite first
   → Temporary project → Start Burp
   → Verify 127.0.0.1:8080 listening

2. Start server (Terminal 1)
   cd dummy-server
   node server.js

3. Start AVD
   Android Studio → Device Manager → ▶ Pixel 6

4. Build app
   Shift+F10

5. Verify AVD proxy still set
   Settings → Wi-Fi → AndroidWifi → check proxy
   (Sometimes resets after AVD restart — redo Step 3.7 if needed)

6. Ready to demo!
```

---

## ❗ TROUBLESHOOTING

| Problem | Fix |
|---------|-----|
| `adb: more than one device` | `adb -s emulator-5556 push ...` |
| Server port 3000 in use | `netstat -ano \| findstr :3000` → `taskkill /PID XXXX /F` |
| Burp not intercepting | Re-check AVD proxy: 10.0.2.2:8080 |
| `CertPathValidatorException` | Burp CA not installed → redo Part 3 |
| Certificate pinning failed | Use hash from "Got: sha256/XXXX" in error message |
| AVD proxy reset | Redo Step 3.7 after each AVD restart |
| Gradle sync failed | Delete `.gradle/caches` → re-sync |
| App not updating | Build → Clean Project → Shift+F10 |

---

## 📊 DEMO SCRIPT (What to say)

### Phase 2.1:
> "This app sends login credentials over HTTPS — normally considered secure.
> However, because the app accepts User-installed CA certificates,
> we can install Burp Suite's fake CA and intercept all traffic.
> Watch — I enter admin/Secret@123 and tap Login.
> In Burp, we can see the password in plaintext despite HTTPS."

### Phase 2.3:
> "After applying Network Security Config with only System CAs trusted,
> the app now rejects Burp's fake certificate.
> Same credentials, same Burp setup — but now we get SSLHandshakeException.
> Burp receives nothing. The attack completely fails."

### Certificate Pinning:
> "Certificate Pinning goes further — even if an attacker compromises
> a System CA, the app hardcodes the exact server certificate hash.
> Any certificate mismatch immediately terminates the connection."

---

*Last updated: Project 4 — MITM Attack Lab*
*Author: Tien Hardinng | github.com/tienhardinng*