// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());

/* ---------------- Data Masking (100% masking) ---------------- */
function maskValue100(val) {
  if (val === null || val === undefined) return val;
  const s = String(val);
  return '*'.repeat(s.length);
}

function maskObject100(obj, sensitiveKeys = [
  'password','token','authorization','auth','ssn','creditcard','cardnumber','cvv','secret','pass'
]) {
  if (!obj || typeof obj !== 'object') return obj;
  const cloned = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    const lower = key.toLowerCase();
    if (val && typeof val === 'object') {
      cloned[key] = maskObject100(val, sensitiveKeys);
    } else {
      if (sensitiveKeys.some(k => lower.includes(k))) {
        cloned[key] = maskValue100(val);
      } else if (typeof val === 'string' && /^\d{12,19}$/.test(val)) {
        // possible card number: mask fully
        cloned[key] = maskValue100(val);
      } else {
        cloned[key] = val;
      }
    }
  }
  return cloned;
}

/* ---------------- Log files ---------------- */
const accessLog = path.join(__dirname, 'access.log');
const securityLog = path.join(__dirname, 'security.log');

function appendLog(file, text) {
  fs.appendFile(file, text + '\n', err => {
    if (err) console.error('Error writing log:', err);
  });
}

/* ---------------- Logging middleware ---------------- */
function loggingMiddleware(req, res, next) {
  const start = Date.now();

  // Mask authorization header fully
  const headersForLog = {};
  for (const h of Object.keys(req.headers || {})) {
    if (h === 'authorization') headersForLog[h] = maskValue100(req.headers[h] || '');
    else headersForLog[h] = req.headers[h];
  }

  const maskedBody = maskObject100(req.body || {});

  res.on('finish', () => {
    const duration = Date.now() - start;
    const logEntry = {
      time: new Date().toISOString(),
      method: req.method,
      path: req.originalUrl || req.url,
      status: res.statusCode,
      durationMs: duration,
      headers: maskObject100(headersForLog),
      body: maskedBody,
      protocol: req.protocol,
      ip: req.ip || req.connection.remoteAddress,
      Host: maskValue100(req.headers['host'] || ''),
      UserAgent: maskValue100(req.headers['user-agent'] || ''),
      Referrer: maskValue100(req.headers['referer'] || req.headers['referrer'] || ''),
      query: maskObject100(req.query || {}),
      params: maskObject100(req.params || {}),
      bodyRaw: maskObject100(req.body || {})
    };
    const line = JSON.stringify(logEntry);
    console.log('[ACCESS]', line);
    appendLog(accessLog, line);
  });

  next();
}

/* ---------------- SQL injection detector (existing) ---------------- */
function bodySqlDetector(req, res, next) {
  if ((req.method === 'POST' || req.method === 'DELETE') && req.body && Object.keys(req.body).length > 0) {
    const bodyString = JSON.stringify(req.body);
    if (/('|;|--)/.test(bodyString)) {
      const masked = maskObject100(req.body);
      const alert = {
        time: new Date().toISOString(),
        reason: 'SQL injection / invalid input detected',
        method: req.method,
        path: req.originalUrl || req.url,
        maskedBody: masked,
        rawLength: bodyString.length
      };
      const line = JSON.stringify(alert);
      console.warn('[SEC]', line);
      appendLog(securityLog, line);
      return res.status(400).json({ error: "Input tidak valid / terdeteksi SQL injection attempt" });
    }
  }
  next();
}

/* ---------------- ID validator (existing) ---------------- */
function validateIdParam(req, res, next) {
  if (req.params && req.params.id) {
    if (!/^\d+$/.test(String(req.params.id))) {
      return res.status(400).json({ message: 'Invalid id parameter' });
    }
  }
  next();
}

/* ---------------- Auth middleware (existing token-based) ---------------- */
const JWT_SECRET = 'tokenrahasia';

function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: Token missing' });
    }
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized: Invalid token' });
        }
        req.user = decoded;
        next();
    });
}
//route tambahan untuk mendapatkan token JWT
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'password123') {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    }
    return res.status(401).json({ message: 'Invalid credentials' });
});

/* ---------------- Apply middlewares ---------------- */
app.use(loggingMiddleware);
app.use(bodySqlDetector);

/* ---------------- Routes ---------------- */
app.get('/', (req, res) => res.send(`Congratulations! Server running on port ${port}`));
app.get('/dummy-get', (req, res) => res.json({ message: 'This is a dummy GET API' }));

app.post('/dummy-post', authMiddleware, (req, res) => {
  // For developer console, show masked body (never print raw sensitive)
  console.log('Received (masked):', JSON.stringify(maskObject100(req.body || {})));
  res.json({ message: `This is a dummy POST API, you sent: ${JSON.stringify(req.body)}` });
});

app.delete('/dummy-delete/:id', authMiddleware, validateIdParam, (req, res) => {
  const { id } = req.params;
  res.json({ message: `This is a dummy DELETE API. Item with id ${id} has been deleted (simulated).` });
});

/* ---------------- Start server ---------------- */
app.listen(port, () => console.log(`Example app listening on port ${port}!`));