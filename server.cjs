const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 5500;
const ROOT = __dirname;

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf'
};

const server = http.createServer((req, res) => {
    // Add CORS & No-Cache for dev ease
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');

    let reqPath = decodeURI(req.url.split('?')[0]);
    if (reqPath === '/' || reqPath === '') reqPath = '/index.html';

    const safePath = path.normalize(path.join(ROOT, reqPath));
    if (!safePath.startsWith(ROOT)) {
        res.writeHead(403);
        res.end('Access Denied');
        return;
    }

    fs.stat(safePath, (err, stats) => {
        if (err || !stats.isFile()) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('404 Not Found: ' + reqPath);
            return;
        }

        const ext = path.extname(safePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        res.writeHead(200, { 'Content-Type': contentType });
        const stream = fs.createReadStream(safePath);
        stream.pipe(res);
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n======================================================`);
    console.log(`🚀 DIAW SHOOP LOCAL SERVER IS LIVE`);
    console.log(`👉 http://localhost:${PORT}`);
    console.log(`👉 http://127.0.0.1:${PORT}`);
    console.log(`======================================================\n`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        const altPort = PORT + 1;
        console.log(`Port ${PORT} in use, trying ${altPort}...`);
        server.listen(altPort, '0.0.0.0', () => {
            console.log(`🚀 DIAW SHOOP server running at http://localhost:${altPort}`);
        });
    } else {
        console.error('Server error:', err);
    }
});
