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

> **Android App** is stored separately at: [MITMDemo-Android](https://github.com/tienhardinng/MITMDemo-Android)

---

## 💻 Prerequisites

### Host Machine:
| Tool | Version | Link |
|------|---------|------|
| Python | ≥ 3.10 | [python.org](https://python.org) |
| Node.js | ≥ 18 LTS | [nodejs.org](https://nodejs.org) |
| Android Studio | Latest | [developer.android.com](https://developer.android.com/studio) |
| Burp Suite Community | Latest | [portswigger.net](https://portswigger.net/burp) |
| ADB (Android SDK) | Latest | Installed with Android Studio |

### Android Virtual Device (AVD):
```
Device  : Pixel 6
API     : 34 (Android 14)
RAM     : 2048 MB (recommended)
```

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/tienhardinng/Project4-MITM-Lab.git
cd Project4-MITM-Lab
```

### 2. Install Python dependencies
```bash
pip install -r python-tools/requirements.txt
```

### 3. Install Node.js dependencies
```bash
cd dummy-server
npm install
cd ..
```

### 4. Verify environment
```powershell
$env:PYTHONPATH = "python-tools"
python python-tools/01_check_env.py
```

---

## 🚀 Usage

### Step 1 — Start HTTPS Server
```bash
cd dummy-server
node server.js
# Expected output: [SERVER] HTTPS Listening on port 3000
```

### Step 2 — Launch AVD
Open Android Studio → Device Manager → Play ▶ Pixel 6

### Step 3 — Configure Burp Suite
```
Proxy → Proxy Settings → Bind Address: 127.0.0.1:8080
```

### Step 4 — Install Burp CA into AVD
```powershell
# First export cacert.der from Burp Suite
# Proxy → Proxy Settings → Import/Export CA Certificate → Export DER
adb -s emulator-5556 push C:\Users\...\cacert.der /sdcard/Download/cacert.der
```
On AVD:
```
Settings → Security → Encryption & Credentials
→ Install a certificate → CA certificate → Select cacert.der
```

### Step 5 — Configure Proxy on AVD
```
Settings → Network & Internet → Wi-Fi → AndroidWifi ✏️
→ Proxy: Manual
→ Hostname: 10.0.2.2
→ Port: 8080
→ Save
```

### Step 6 — Run Python Tools
```powershell
# Set PYTHONPATH
$env:PYTHONPATH = "python-tools"

# Check environment
python python-tools/01_check_env.py

# Analyze vulnerable traffic (Phase 2.1)
python python-tools/02_capture_traffic.py --phase vulnerable --file reports/raw_logs/captured.har

# Analyze after hardening (Phase 2.3)
python python-tools/02_capture_traffic.py --phase hardened

# Generate HTML report
python python-tools/04_security_audit.py

# Open report
start reports/final_report.html
```

---

## 🎬 Demo Flow

### Phase 2.1 — The Hack (Vulnerable App)

```
Android App (trusts User CA)
         ↓
Login: admin / Secret@123
         ↓
Burp Suite intercepts HTTPS traffic
         ↓
POST /api/login HTTP/1.1
{"username":"admin","password":"Secret@123"}
         ↓
⚠️  CREDENTIALS EXPOSED IN PLAINTEXT!
```

**Evidence:** Burp HTTP History shows credentials in plaintext despite HTTPS being used.

---

### Phase 2.2 — Security Hardening

Modify `res/xml/network_security_config.xml`:
```xml


    
        
            
            
        
    

```

Reference in `AndroidManifest.xml`:
```xml

```

---

### Phase 2.3 — Proof of Defense (Hardened App)

```
Android App (System CAs only)
         ↓
Login attempt with Burp proxy active
         ↓
javax.net.ssl.SSLHandshakeException
         ↓
Burp Suite: TLS Failed — No data intercepted
         ↓
✅ PASSWORD PROTECTED — ATTACK FAILED
```

**Evidence:** App terminates connection. Burp cannot read any payload.

---

## 📊 Compliance Mapping

| Standard | Clause | Description |
|----------|--------|-------------|
| **OWASP Mobile Top 10** | M3: Insecure Communication | App accepts User CA → MITM attack succeeds |
| **ISO/IEC 27002:2022** | 8.24 — Use of cryptography | Must configure SSL/TLS correctly |
| **ISO/IEC 27002:2022** | 8.26 — Application security requirements | App code must follow secure design principles |
| **GDPR** | Article 32 — Security of processing | Requires encryption of personal data in transit |

### Risk Assessment:
| Factor | Assessment |
|--------|-----------|
| **Threat** | MITM attack on malicious public Wi-Fi |
| **Vulnerability** | App accepts User-installed CA certificates |
| **Likelihood** | HIGH — Easily performed with free tools (Burp Suite) |
| **Impact** | CRITICAL — Full Authentication Credentials exposed |
| **Overall Risk** | 🔴 CRITICAL |

---

## 🛠️ Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `adb: more than one device` | Multiple AVDs running | Use `adb -s emulator-XXXX` |
| `Connection timeout` | Server not running | Run `node server.js` first |
| `SSLHandshakeException` | App has been hardened | Expected result in Phase 2.3 ✅ |
| `Burp not intercepting` | Proxy not configured | Check AVD proxy points to `10.0.2.2:8080` |
| `Gradle sync failed` | Cache corrupted | Delete `.gradle/caches` and re-sync |

---

## 📚 References

- [OWASP Mobile Security Testing Guide (MSTG) 2024](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/network-security-config)
- [ISO/IEC 27002:2022 Information Security Controls](https://www.iso.org/standard/75652.html)
- [GDPR Article 32 — Security of processing](https://gdpr-info.eu/art-32-gdpr/)
- [PortSwigger — Installing Burp CA Certificate](https://portswigger.net/burp/documentation/desktop/mobile-testing)

---

## 👤 Author

**Tien Hardinng**
- GitHub: [@tienhardinng](https://github.com/tienhardinng)
- Project Repo: [Project4-MITM-Lab](https://github.com/tienhardinng/Project4-MITM-Lab)

---

> ⚠️ **Disclaimer:** This project is created strictly for academic and security research purposes. Do not use any techniques demonstrated here against real systems without explicit authorization.