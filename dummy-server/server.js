const https = require('https');
const express = require('express');
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');

const app = express();
app.use(express.json());

app.post('/api/login', (req, res) => {
    console.log('[SERVER] Received credentials:', req.body);
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret123';
    console.log('[SERVER] Issuing token:', token);
    res.json({ status: 'ok', message: 'Login received', token: token });
});

// Dùng cert cố định - chỉ generate 1 lần
let pemCert, pemKey;

if (fs.existsSync('cert.pem') && fs.existsSync('key.pem')) {
    // Load cert đã có
    pemCert = fs.readFileSync('cert.pem', 'utf8');
    pemKey = fs.readFileSync('key.pem', 'utf8');
    console.log('[SERVER] Loaded existing certificate');
} else {
    // Generate cert mới và lưu lại
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    const attrs = [{ name: 'commonName', value: 'localhost' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey, forge.md.sha256.create());

    pemCert = forge.pki.certificateToPem(cert);
    pemKey = forge.pki.privateKeyToPem(keys.privateKey);

    // Lưu cert ra file
    fs.writeFileSync('cert.pem', pemCert);
    fs.writeFileSync('key.pem', pemKey);
    console.log('[SERVER] Generated and saved new certificate');

    // Tính và in SHA-256 pin
    const derCert = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const derBuffer = Buffer.from(derCert, 'binary');
    const hash = crypto.createHash('sha256').update(derBuffer).digest('base64');
    console.log('[SERVER] Certificate SHA-256 Pin: sha256/' + hash);
}

const options = { key: pemKey, cert: pemCert };
https.createServer(options, app).listen(3000, '0.0.0.0', () => {
    console.log('[SERVER] HTTPS Listening on port 3000');
});
