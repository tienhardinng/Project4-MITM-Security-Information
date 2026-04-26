// dummy-server/server.js
const https = require('https');
const express = require('express');
const selfsigned = require('selfsigned');

const app = express();
app.use(express.json());

app.post('/api/login', (req, res) => {
    console.log('[SERVER] Received credentials:', req.body);
    res.json({ status: 'ok', message: 'Login received' });
});

// Tạo self-signed certificate tự động
const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365 });

const options = {
    key:  pems.private,
    cert: pems.cert,
};

https.createServer(options, app).listen(3000, '0.0.0.0', () => {
    console.log('[SERVER] HTTPS Listening on port 3000');
});