// app.js (versi perbaikan)
const express = require('express');
const app = express();
const port = 3000;

app.use(express.json());

// simple SQL detector for POST bodies (field-level)
// only check suspicious chars or SQL comment tokens
function bodySqlDetector(req, res, next) {
  // Apply to POST and DELETE methods
  if ((req.method === 'POST' || req.method === 'DELETE') && req.body) {
    const bodyString = JSON.stringify(req.body);
    // detect quotes, semicolon, or double-dash comment (simple)
    if (/('|;|--)/.test(bodyString)) {
      console.log(`[SEC] SQL injection / invalid input detected: ${bodyString}`);
      return res.status(400).json({ error: "Input tidak valid / terdeteksi SQL injection attempt" });
    }
  }
  next();
}

// ID validator for DELETE route
function validateIdParam(req, res, next) {
  if (req.params && req.params.id) {
    if (!/^\d+$/.test(String(req.params.id))) {
      return res.status(400).json({ message: 'Invalid id parameter' });
    }
  }
  next();
}

// auth middleware (parse Bearer token)
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  if (token === 'tokenrahasia13') {
    return next();
  }
  return res.status(401).json({ message: 'Unauthorized' });
}

// apply body detector globally (or you can apply only to specific routes)
app.use(bodySqlDetector);

// routes
app.get('/', (req, res) => res.send(`Congratulations! Server running on port ${port}`));
app.get('/dummy-get', (req, res) => res.json({ message: 'This is a dummy GET API' }));

app.post('/dummy-post', authMiddleware, (req, res) => {
  const { body } = req;
  console.log('Received body:', body);
  res.json({ message: `This is a dummy POST API, you sent: ${JSON.stringify(body)}` });
});

app.delete('/dummy-delete/:id', authMiddleware, validateIdParam, (req, res) => {
  const { id } = req.params;
  res.json({ message: `This is a dummy DELETE API. Item with id ${id} has been deleted (simulated).` });
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
