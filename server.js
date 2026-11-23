const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- [STRIDE: Denial of Service] Límite estricto de payload ---
app.use(express.json({ limit: '10kb' }));

// --- [STRIDE: Information Disclosure] Cabeceras de seguridad ---
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
  );
  res.removeHeader('X-Powered-By');
  next();
});

// --- [STRIDE: Denial of Service] Rate limiting básico por IP ---
const rateLimitMap = new Map();
function rateLimiter(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const record = rateLimitMap.get(ip) || { count: 0, start: now };

    if (now - record.start > windowMs) {
      record.count = 1;
      record.start = now;
    } else {
      record.count += 1;
    }
    rateLimitMap.set(ip, record);

    if (record.count > maxRequests) {
      auditLog('RATE_LIMIT_EXCEEDED', ip, 'N/A', 'BLOCKED');
      return res.status(429).json({ error: 'Demasiadas solicitudes. Intente más tarde.' });
    }
    next();
  };
}

// --- [STRIDE: Repudiation] Log de auditoría inmutable (append-only) ---
function auditLog(action, ip, user, status, detail = '') {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    action,
    ip,
    user,
    status,
    detail
  }) + '\n';
  fs.appendFileSync(path.join(__dirname, 'audit.log'), entry);
}

// --- Base de datos simulada en memoria ---
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

const saltAgent = 'salt_seguro_agente_2026';
const saltAdmin = 'salt_seguro_admin_2026';

const USERS = {
  'agente.bogota': {
    username: 'agente.bogota',
    role: 'agente',
    salt: saltAgent,
    hash: hashPassword('Seguros2026!', saltAgent)
  },
  'admin.central': {
    username: 'admin.central',
    role: 'admin',
    salt: saltAdmin,
    hash: hashPassword('AdminCentral2026!', saltAdmin)
  }
};

const SESSIONS = new Map(); // token -> { username, role, expiresAt }
const POLICIES = [];
let THREAT_KEYWORDS = ['ransomware', 'phishing', 'fortigate', 'mpls', 'api-seguros'];

// --- [STRIDE: Spoofing & Elevation of Privilege] Middlewares de sesión y rol ---
function parseCookies(req) {
  const header = req.headers.cookie || '';
  return Object.fromEntries(
    header.split(';').map(c => c.trim().split('=')).filter(p => p.length === 2)
  );
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.session_token;
  if (!token || !SESSIONS.has(token)) {
    return res.status(401).json({ error: 'No autenticado.' });
  }
  const session = SESSIONS.get(token);
  if (Date.now() > session.expiresAt) {
    SESSIONS.delete(token);
    return res.status(401).json({ error: 'Sesión expirada.' });
  }
  req.user = session;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      auditLog('UNAUTHORIZED_ROLE_ACCESS', req.ip, req.user?.username || 'anon', 'DENIED', req.originalUrl);
      return res.status(403).json({ error: 'No tiene permisos para esta operación.' });
    }
    next();
  };
}

app.use(express.static(path.join(__dirname, 'public')));

// --- Rutas de Negocio ---

// 1. Login seguro
app.post('/api/login', rateLimiter(10, 60_000), (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Formato de credenciales inválido.' });
  }

  const user = USERS[username.trim()];
  if (!user) {
    auditLog('LOGIN_ATTEMPT', req.ip, username, 'FAILED', 'Usuario inexistente');
    return res.status(401).json({ error: 'Credenciales inválidas.' });
  }

  const candidateHash = hashPassword(password, user.salt);
  const valid = crypto.timingSafeEqual(Buffer.from(candidateHash, 'hex'), Buffer.from(user.hash, 'hex'));

  if (!valid) {
    auditLog('LOGIN_ATTEMPT', req.ip, username, 'FAILED', 'Contraseña incorrecta');
    return res.status(401).json({ error: 'Credenciales inválidas.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  SESSIONS.set(token, {
    username: user.username,
    role: user.role,
    expiresAt: Date.now() + 30 * 60 * 1000 // 30 min
  });

  res.setHeader('Set-Cookie', `session_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`);
  auditLog('LOGIN_SUCCESS', req.ip, user.username, 'OK', `Rol: ${user.role}`);
  res.json({ username: user.username, role: user.role });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const cookies = parseCookies(req);
  SESSIONS.delete(cookies.session_token);
  res.setHeader('Set-Cookie', 'session_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  auditLog('LOGOUT', req.ip, req.user.username, 'OK');
  res.json({ ok: true });
});

// 2. Registro y aprobación de venta de póliza (Flujo Insurance Global Company)
app.post('/api/policies', requireAuth, rateLimiter(30, 60_000), (req, res) => {
  const { clientName, policyType, amount, channel } = req.body || {};

  // [STRIDE: Tampering] Validación estricta de entradas
  const allowedTypes = ['Vida', 'Vehículo', 'Hogar', 'Empresarial'];
  const allowedChannels = ['Oficina', 'Web'];
  const numericAmount = Number(amount);

  if (
    typeof clientName !== 'string' ||
    !/^[a-zA-ZÀ-ÿ\s]{3,60}$/.test(clientName.trim()) ||
    !allowedTypes.includes(policyType) ||
    !allowedChannels.includes(channel) ||
    !Number.isFinite(numericAmount) ||
    numericAmount <= 0 ||
    numericAmount > 1_000_000_000
  ) {
    auditLog('POLICY_CREATE_INVALID', req.ip, req.user.username, 'REJECTED');
    return res.status(400).json({ error: 'Datos de póliza inválidos.' });
  }

  const approvalCode = 'APR-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const policy = {
    id: POLICIES.length + 1,
    approvalCode,
    clientName: clientName.trim(),
    policyType,
    amount: numericAmount,
    channel,
    approvedBy: req.user.username,
    createdAt: new Date().toISOString()
  };

  POLICIES.push(policy);
  auditLog('POLICY_APPROVED', req.ip, req.user.username, 'OK', `${approvalCode} (${channel})`);
  res.status(201).json(policy);
});

app.get('/api/policies', requireAuth, (req, res) => {
  res.json(POLICIES);
});

// 3. Módulo reutilizable para Punto 3: Gestión de 5 palabras clave (Solo Admin)
app.get('/api/keywords', requireAuth, (req, res) => {
  res.json({ keywords: THREAT_KEYWORDS });
});

app.post('/api/keywords', requireAuth, requireRole('admin'), (req, res) => {
  const { keywords } = req.body || {};
  if (!Array.isArray(keywords) || keywords.length !== 5) {
    return res.status(400).json({ error: 'Debe enviar exactamente 5 palabras clave.' });
  }
  const clean = keywords.map(k => (typeof k === 'string' ? k.trim().toLowerCase() : ''));
  if (clean.some(k => !/^[a-z0-9-_]{2,30}$/.test(k))) {
    return res.status(400).json({ error: 'Palabras clave inválidas (solo letras, números, - y _).' });
  }

  THREAT_KEYWORDS = clean;
  auditLog('KEYWORDS_UPDATED', req.ip, req.user.username, 'OK', clean.join(','));
  res.json({ keywords: THREAT_KEYWORDS });
});

// 4. Endpoint de auditoría (Solo Admin)
app.get('/api/audit', requireAuth, requireRole('admin'), (req, res) => {
  const logPath = path.join(__dirname, 'audit.log');
  if (!fs.existsSync(logPath)) return res.json([]);
  const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').slice(-20);
  res.json(lines.map(l => JSON.parse(l)));
});

// Manejo genérico de errores (evita fuga de información)
app.use((err, req, res, next) => {
  auditLog('SERVER_ERROR', req.ip, 'system', 'ERROR');
  res.status(500).json({ error: 'Error interno procesando la solicitud.' });
});

app.listen(PORT, () => {
  console.log(`Portal Insurance Global Company ejecutándose en http://localhost:${PORT}`);
});
