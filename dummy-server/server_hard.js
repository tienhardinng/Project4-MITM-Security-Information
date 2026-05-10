// dummy-server/server_hard.js
// ─────────────────────────────────────────────────────────────
// Hardened HTTPS Server — Project 4 MITM Lab
// Nâng cấp bảo mật: TLS 1.2+, HSTS, Rate Limiting, Proxy Detection
// ─────────────────────────────────────────────────────────────

'use strict';

const https      = require('https');
const express    = require('express');
const selfsigned = require('selfsigned');
const crypto     = require('crypto');
const fs         = require('fs');         
const forge      = require('node-forge');

const app = express();
app.use(express.json({ limit: '10kb' }));

// ─────────────────────────────────────────────
// [2][3] Security Headers Middleware
// ─────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options',    'nosniff');
    res.setHeader('X-Frame-Options',           'DENY');
    res.setHeader('X-XSS-Protection',          '1; mode=block');
    res.setHeader('Content-Security-Policy',   "default-src 'none'");
    res.setHeader('Cache-Control',             'no-store');
    next();
});

// ─────────────────────────────────────────────
// [7] Runtime Proxy Detection
// ─────────────────────────────────────────────
app.use((req, res, next) => {
    const suspiciousHeaders = ['x-forwarded-for', 'via', 'x-real-ip', 'forwarded', 'proxy-connection'];
    const detected = suspiciousHeaders.filter(h => req.headers[h]);
    if (detected.length > 0) {
        console.warn('[SECURITY] Proxy/Intercept headers detected:', detected.map(h => `${h}: ${req.headers[h]}`));
    }
    next();
});

// ─────────────────────────────────────────────
// [4] Rate Limiting Logic
// ─────────────────────────────────────────────
const loginAttempts = new Map();
const RATE_LIMIT    = 5;
const RATE_WINDOW   = 15 * 60 * 1000;

function checkRateLimit(ip) {
    const now   = Date.now();
    const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + RATE_WINDOW };
    if (now > entry.resetAt) {
        loginAttempts.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
        return { allowed: true, remaining: RATE_LIMIT - 1 };
    }
    if (entry.count >= RATE_LIMIT) {
        return { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    entry.count++;
    loginAttempts.set(ip, entry);
    return { allowed: true, remaining: RATE_LIMIT - entry.count };
}

// ─────────────────────────────────────────────
// [5] Token Management
// ─────────────────────────────────────────────
const tokenStore = new Map();
const TOKEN_TTL  = 15 * 60 * 1000;

function generateToken(username) {
    const raw    = crypto.randomBytes(32).toString('hex');
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const token  = `${header}.${raw}`;
    tokenStore.set(token, { username, expiresAt: Date.now() + TOKEN_TTL, issuedAt: Date.now() });
    return token;
}

function validateToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7);
    const entry = tokenStore.get(token);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { tokenStore.delete(token); return null; }
    return entry;
}

// ─────────────────────────────────────────────
// API Endpoints
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const rate = checkRateLimit(ip);
    
    if (!rate.allowed) {
        return res.status(429).json({ status: 'error', message: 'Too many attempts', retryAfter: rate.retryAfter });
    }

    const { username, password } = req.body;
    console.log(`[SERVER] Login Attempt — user: ${username} | pass: ${password} | IP: ${ip}`);

    if (username === 'admin' && password === 'Secret@123') {
        const token = generateToken(username);
        return res.status(200).json({ status: 'ok', token, expiresIn: TOKEN_TTL / 1000 });
    }
    return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
});

app.get('/api/profile', (req, res) => {
    const entry = validateToken(req.headers['authorization']);
    if (!entry) return res.status(401).json({ status: 'error', message: 'Unauthorized' });
    return res.status(200).json({ status: 'ok', user: entry.username, data: "Sensitive Secure Data" });
});

// ─────────────────────────────────────────────
// [1] TLS 1.2+ & Fixed Certificate Logic
// ─────────────────────────────────────────────
const attrs = [{ name: 'commonName', value: 'localhost' }];
let pems;

if (fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
    pems = {
        cert: fs.readFileSync('cert.pem', 'utf8'),
        private: fs.readFileSync('key.pem', 'utf8')
    };
    console.log('[SERVER] Loaded existing certificate');
} else {
    const generated = selfsigned.generate(attrs, {
        days: 365, keySize: 2048, algorithm: 'sha256',
        extensions: [{
            name: 'subjectAltName',
            altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '10.0.2.2' }],
        }],
    });
    
    pems = {
        cert: generated.cert || generated.public,
        private: generated.private
    };

    fs.writeFileSync('cert.pem', pems.cert);
    fs.writeFileSync('key.pem', pems.private);
    console.log('[SERVER] Generated and saved new certificate');
}

const certForge = forge.pki.certificateFromPem(pems.cert);
const der = forge.asn1.toDer(forge.pki.certificateToAsn1(certForge)).getBytes();
const hash = crypto.createHash('sha256').update(Buffer.from(der, 'binary')).digest('base64');

https.createServer({
    key:  pems.private,
    cert: pems.cert,
    minVersion: 'TLSv1.2',
    ciphers: [
        'TLS_AES_256_GCM_SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
    honorCipherOrder: true,
}, app).listen(3000, '0.0.0.0', () => {
    console.log('\n[SERVER] ─────────────────────────────────────');
    console.log('[SERVER]  HTTPS Server — Hardened Project 4   ');
    console.log('[SERVER]  Address    : https://10.0.2.2:3000  ');
    console.log(`[SERVER]  SHA-256 PIN: sha256/${hash}`);
    console.log('[SERVER] ─────────────────────────────────────');
    console.log('\n[ACTION] Copy mã Pin trên dán vào network_security_config.xml\n');
});