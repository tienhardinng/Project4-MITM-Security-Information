const https = require('https');
const crypto = require('crypto');
const tls = require('tls');

const options = {
    host: '127.0.0.1',
    port: 3000,
    rejectUnauthorized: false
};

const socket = tls.connect(options, () => {
    const cert = socket.getPeerCertificate();
    const raw = cert.raw;
    const hash = crypto.createHash('sha256').update(raw).digest('base64');
    console.log('SHA-256 Pin: sha256/' + hash);
    socket.end();
});

socket.on('error', (err) => console.error('Error:', err.message));
