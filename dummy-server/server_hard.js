// dummy-server/server.js
// ─────────────────────────────────────────────────────────────
// Hardened HTTPS Server — Project 4 MITM Lab
// Nâng cấp bảo mật so với version gốc:
//   [1] TLS 1.2+ only  — block TLS 1.0, 1.1
//   [2] HSTS header    — force HTTPS cho mọi request
//   [3] Security headers — X-Content-Type, X-Frame, CSP
//   [4] Rate limiting  — chống brute force login
//   [5] Token expiry   — JWT-style token có thời hạn 15 phút
//   [6] Request validation — kiểm tra input trước khi xử lý
//   [7] Proxy detection — log cảnh báo nếu có proxy header
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
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); // [2] HSTS
    res.setHeader('X-Content-Type-Options',    'nosniff');
    res.setHeader('X-Frame-Options',           'DENY');
    res.setHeader('X-XSS-Protection',          '1; mode=block');
    res.setHeader('Content-Security-Policy',   "default-src 'none'");
    res.setHeader('Cache-Control',             'no-store');
    next();
});


// ─────────────────────────────────────────────
// [7] Runtime Proxy Detection Middleware
// Log cảnh báo nếu phát hiện dấu hiệu bị intercept
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
// [4] Rate Limiting — max 5 login / IP / 15 phút
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
// [5] Token Store — expiry 15 phút
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

// Dọn token hết hạn mỗi 5 phút
setInterval(() => {
    const now = Date.now();
    for (const [t, e] of tokenStore.entries()) { if (now > e.expiresAt) tokenStore.delete(t); }
}, 5 * 60 * 1000);


// ─────────────────────────────────────────────
// [6] Input Validation
// ─────────────────────────────────────────────
function validateLoginInput(body) {
    const errors = [];
    if (!body.username || typeof body.username !== 'string' || body.username.length < 1 || body.username.length > 64)
        errors.push('username: required string, 1–64 chars');
    if (!body.password || typeof body.password !== 'string' || body.password.length < 1 || body.password.length > 128)
        errors.push('password: required string, 1–128 chars');
    return errors;
}


// ─────────────────────────────────────────────
// POST /api/login
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';

    // [4] Rate limit
    const rate = checkRateLimit(ip);
    if (!rate.allowed) {
        console.warn(`[SECURITY] Rate limit exceeded — IP: ${ip}`);
        return res.status(429).json({ status: 'error', message: 'Too many attempts', retryAfter: rate.retryAfter });
    }

    // [6] Validate input
    const errs = validateLoginInput(req.body);
    if (errs.length > 0) return res.status(400).json({ status: 'error', message: 'Invalid input', errors: errs });

    const { username, password } = req.body;

    // Log credentials — đây là điểm Burp intercept được khi chưa hardened
    console.log(`[SERVER] Login — username: ${username} | password: ${password} | IP: ${ip} | remaining: ${rate.remaining}`);

    const VALID_USERS = { 'admin': 'Secret@123' };
    if (!VALID_USERS[username] || VALID_USERS[username] !== password) {
        return res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }

    // [5] Tạo token có thời hạn
    const token = generateToken(username);
    console.log(`[SERVER] Token issued for: ${username}`);

    return res.status(200).json({
        status:    'ok',
        message:   'Login successful',
        token,
        expiresIn: TOKEN_TTL / 1000,
        user:      username,
        issuedAt:  new Date().toISOString(),
    });
});


// ─────────────────────────────────────────────
// GET /api/profile — yêu cầu token hợp lệ
// Demo: dùng token đánh cắp → giả mạo được (trước hardening)
// ─────────────────────────────────────────────
app.get('/api/profile', (req, res) => {
    const entry = validateToken(req.headers['authorization']);
    if (!entry) return res.status(401).json({ status: 'error', message: 'Unauthorized — token invalid or expired' });
    console.log(`[SERVER] Profile accessed by: ${entry.username}`);
    return res.status(200).json({
        status:    'ok',
        username:  entry.username,
        role:      'admin',
        issuedAt:  new Date(entry.issuedAt).toISOString(),
        expiresAt: new Date(entry.expiresAt).toISOString(),
    });
});


// ─────────────────────────────────────────────
// GET /api/health
// ─────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok', tls: 'TLS 1.2+', timestamp: new Date().toISOString() });
});


// 404
app.use((_req, res) => res.status(404).json({ status: 'error', message: 'Not found' }));


// ─────────────────────────────────────────────
// [1] TLS 1.2+ với cơ chế lưu cert cố định
// ─────────────────────────────────────────────
const attrs = [{ name: 'commonName', value: 'localhost' }];
let pems;

// Kiểm tra xem đã có file chứng chỉ chưa
// [SỬA LẠI ĐOẠN NÀY]
if (fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
    pems = {
        cert: fs.readFileSync('cert.pem', 'utf8'),
        private: fs.readFileSync('key.pem', 'utf8')
    };
    console.log('[SERVER] Loaded existing certificate');
} else {
    // Tạo mới chứng chỉ
    const generatedPems = selfsigned.generate(attrs, {
        days: 365, keySize: 2048, algorithm: 'sha256',
        extensions: [{
            name: 'subjectAltName',
            altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '10.0.2.2' }],
        }],
    });
    
    // Đảm bảo lấy đúng thuộc tính tùy theo phiên bản thư viện
    pems = {
        cert: generatedPems.cert || generatedPems.public,
        private: generatedPems.private
    };

    fs.writeFileSync('cert.pem', pems.cert);
    fs.writeFileSync('key.pem', pems.private);
    console.log('[SERVER] Generated and saved new certificate');
}

// Tự động tính toán mã SHA-256 Pin
const certForge = forge.pki.certificateFromPem(pems.cert);
const der = forge.asn1.toDer(forge.pki.certificateToAsn1(certForge)).getBytes();
const hash = crypto.createHash('sha256').update(Buffer.from(der, 'binary')).digest('base64');

https.createServer({
    key:  pems.private,
    cert: pems.cert,
    minVersion:        'TLSv1.2',
    ciphers: [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
    honorCipherOrder: true,
}, app).listen(3000, '0.0.0.0', () => {
    console.log('[SERVER] ─────────────────────────────────────');
    console.log('[SERVER]  HTTPS Server — Project 4 MITM Lab   ');
    console.log('[SERVER]  Listening  : https://10.0.2.2:3000  ');
    console.log('[SERVER]  TLS        : v1.2+ only             ');
    console.log(`[SERVER]  SHA-256 PIN: sha256/${hash}       `); // <--- HIỆN MÃ PIN
    console.log('[SERVER] ─────────────────────────────────────');
    console.log('\n[ACTION] Copy mã Pin trên dán vào network_security_config.xml');
});
