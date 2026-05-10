// dummy-server/server.js — VULNERABLE version
// Có OTP hint trong response để demo MFA bypass
'use strict';

const https  = require('https');
const express = require('express');
const crypto  = require('crypto');
const forge   = require('node-forge');
const fs      = require('fs');

const app = express();
app.use(express.json());

// ─────────────────────────────────────────────
// POST /api/login — trả token + OTP hint
// ⚠️ LỖ HỔNG: OTP lộ trong response → Burp thấy
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    console.log(`[SERVER] Received credentials — username: ${username} | password: ${password}`);

    // Generate OTP 6 số
    const otp   = Math.floor(100000 + Math.random() * 900000).toString();
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123';

    console.log(`[SERVER] OTP generated: ${otp} (in production: sent via SMS)`);
    console.log(`[SERVER] Issuing token : ${token}`);

    // ⚠️ otp_hint lộ trong response — Burp đọc được toàn bộ
    res.status(200).json({
        status  : 'ok',
        message : 'Login received',
        token,
        mfa: {
            otp_generated : otp,       // ← Burp thấy OTP này
            delivery      : 'SMS',
            expires_in    : 30,
            note          : 'In production: OTP sent to registered phone number'
        }
    });
});
// ─────────────────────────────────────────────
// POST /api/verify-otp — demo MFA bypass
// Hacker dùng OTP lấy được từ MITM để xác thực
// ─────────────────────────────────────────────
app.post('/api/verify-otp', (req, res) => {
    const { username, otp } = req.body || {};
    console.log(`[SERVER] OTP verification — username: ${username} | otp: ${otp}`);

    // ⚠️ Demo: accept any OTP để chứng minh bypass
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123';
    console.log(`[SERVER] MFA bypassed! Token issued: ${token}`);

    res.status(200).json({
        status  : 'ok',
        message : 'MFA verified — Login successful',
        token,
    });
});
// ─────────────────────────────────────────────
// GET /api/health
// ─────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// Cert cố định — chỉ generate 1 lần, lưu vào file
// ─────────────────────────────────────────────
let pemCert, pemKey;

if (fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
    pemCert = fs.readFileSync('cert.pem', 'utf8');
    pemKey  = fs.readFileSync('key.pem',  'utf8');
    console.log('[SERVER] Loaded existing certificate (PIN unchanged)');
} else {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey    = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter  = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{ name: 'commonName', value: 'localhost' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    pemCert = forge.pki.certificateToPem(cert);
    pemKey  = forge.pki.privateKeyToPem(keys.privateKey);

    fs.writeFileSync('cert.pem', pemCert);
    fs.writeFileSync('key.pem',  pemKey);
    console.log('[SERVER] Generated and saved new certificate');

    const der    = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const hash   = crypto.createHash('sha256').update(Buffer.from(der, 'binary')).digest('base64');
    console.log(`[SERVER] Certificate SHA-256 Pin: sha256/${hash}`);
}
// GET /api/profile — demo token replay
app.get('/api/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    console.log(`[SERVER] Profile request — Authorization: ${authHeader}`);

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', message: 'Unauthorized' });
    }

    const token = authHeader.slice(7);
    console.log(`[SERVER] Token replay accepted: ${token}`);

    res.status(200).json({
        status   : 'ok',
        username : 'admin',
        role     : 'admin',
        message  : 'Token replay successful — attacker accessed profile without password'
    });
});
// ─────────────────────────────────────────────
// Start HTTPS server
// ─────────────────────────────────────────────
https.createServer({ key: pemKey, cert: pemCert }, app)
     .listen(3000, '0.0.0.0', () => {
         console.log('[SERVER] ─────────────────────────────────');
         console.log('[SERVER]  VULNERABLE HTTPS Server          ');
         console.log('[SERVER]  https://10.0.2.2:3000            ');
         console.log('[SERVER] ─────────────────────────────────');
     });