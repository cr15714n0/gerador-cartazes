const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 80;

// Configurações via Variáveis de Ambiente (com fallback seguro padrão)
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cartazes2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Armazenamento de sessões ativas em memória
const activeSessions = new Map();

// Limpeza de sessões expiradas a cada 30 minutos
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of activeSessions.entries()) {
    if (data.expiresAt < now) {
      activeSessions.delete(token);
    }
  }
}, 30 * 60 * 1000);

// Headers de segurança HTTP
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

// Rate Limiter: Máximo de 5 tentativas de login a cada 15 minutos por IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Muitas tentativas incorretas. Por segurança, tente novamente em 15 minutos.'
  }
});

// Comparação segura contra Timing Attacks
function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Middleware de Autenticação Server-Side
function requireAuth(req, res, next) {
  const sessionToken = req.signedCookies.cartazes_session;
  if (!sessionToken) {
    return res.redirect('/login');
  }

  const session = activeSessions.get(sessionToken);
  if (!session || session.expiresAt < Date.now()) {
    if (sessionToken) activeSessions.delete(sessionToken);
    res.clearCookie('cartazes_session');
    return res.redirect('/login');
  }

  session.expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  req.user = session.user;
  next();
}

// Rota pública de login
app.get('/login', (req, res) => {
  const sessionToken = req.signedCookies.cartazes_session;
  if (sessionToken && activeSessions.has(sessionToken)) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Endpoint seguro de Login (com Rate Limit)
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password, remember } = req.body;

  const validUser = timingSafeCompare(username || '', ADMIN_USER);
  const validPass = timingSafeCompare(password || '', ADMIN_PASSWORD);

  if (validUser && validPass) {
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const sessionDuration = remember ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;

    activeSessions.set(sessionToken, {
      user: ADMIN_USER,
      expiresAt: Date.now() + sessionDuration
    });

    res.cookie('cartazes_session', sessionToken, {
      httpOnly: true,
      signed: true,
      sameSite: 'lax',
      secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
      maxAge: sessionDuration
    });

    return res.json({ success: true, user: ADMIN_USER });
  }

  return res.status(401).json({
    success: false,
    message: 'Usuário ou senha incorretos.'
  });
});

// Endpoint de Logout
app.post('/api/logout', (req, res) => {
  const sessionToken = req.signedCookies.cartazes_session;
  if (sessionToken) {
    activeSessions.delete(sessionToken);
  }
  res.clearCookie('cartazes_session');
  res.json({ success: true });
});

// Endpoint para verificar usuário logado
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Rota Protegida: O arquivo app.html NUNCA é entregue sem login
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'app.html'));
});

// Redireciona qualquer rota desconhecida
app.use((req, res) => {
  res.redirect('/login');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Servidor Seguro Ativo] Porta ${PORT}`);
});
