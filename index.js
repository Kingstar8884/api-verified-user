const express = require('express');
const axios = require('axios');
const { verify } = require('hcaptcha');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.use(express.json());
const PORT = 3000;

const pendingTokens = new Set();
const usedTokens = new Set();
const nonces = new Map();


const accessTokens = ["12345-Demo-Client"];
const NONCE_EXPIRY_MS = 10_000;

const globalLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  message: { error: 'Too many verification attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const perClientLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  keyGenerator: req => `${getIP(req)}:${req.body.clientId || 'unknown'}`,
  message: { error: 'Too many verification attempts for this client, please wait.' }
});

const perIPLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  keyGenerator: req => getIP(req),
  message: { error: 'Too many requests from this IP, please wait.' }
});

function getIP(req) {
  return req.headers['cf-connecting-ip'] ||
         req.headers['x-forwarded-for']?.split(',')[0] ||
         req.socket.remoteAddress;
}

function isValidWebhook(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:';
  } catch {
    return false;
  }
}

function hashUA(ua) {
  return crypto.createHash('sha256').update(ua).digest('hex');
}


app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device Verification</title>

<style>
:root{
  --primary:#3b82f6;
  --cyan:#22d3ee;
  --bg:#020617;
}

*{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}

body{
  user-select: none;
  margin:0;
  height:100vh;
  background:
    radial-gradient(600px circle at 20% 20%, rgba(59,130,246,.15), transparent),
    radial-gradient(800px circle at 80% 80%, rgba(34,211,238,.15), transparent),
    var(--bg);
  display:flex;
  align-items:center;
  justify-content:center;
  overflow:hidden;
  color:#e5e7eb;
}

.card{
  width:100%;
  max-width:460px;
  padding:32px 28px;
  border-radius:24px;
  background:rgba(2,6,23,.75);
  backdrop-filter:blur(14px);
  border:1px solid rgba(148,163,184,.15);
  box-shadow:0 30px 80px rgba(0,0,0,.6);
  animation:floatIn .6s ease forwards;
}

@keyframes floatIn{
  from{opacity:0;transform:translateY(20px) scale(.98)}
  to{opacity:1;transform:none}
}

.icon-wrap{
  width:72px;
  height:72px;
  border-radius:18px;
  background:linear-gradient(135deg,var(--cyan),var(--primary));
  display:flex;
  align-items:center;
  justify-content:center;
  margin:0 auto 18px;
  box-shadow:0 10px 30px rgba(59,130,246,.45);
}

h1{
  margin:10px 0 8px;
  text-align:center;
  font-size:24px;
}

p{
  text-align:center;
  color:#94a3b8;
  font-size:14px;
  line-height:1.7;
}

.info{
  margin-top:22px;
  display:grid;
  gap:12px;
}

.info div{
  display:flex;
  align-items:center;
  gap:10px;
  font-size:13px;
  color:#cbd5f5;
}

.verify-btn{
  width:100%;
  padding:16px;
  border:none;
  border-radius:14px;
  font-size:15px;
  font-weight:600;
  cursor:pointer;
  background:linear-gradient(135deg,var(--cyan),var(--primary));
  color:#020617;
  transition:.2s;
}

.verify-btn:hover{transform:translateY(-1px);box-shadow:0 12px 30px rgba(59,130,246,.45)}
.verify-btn:disabled{opacity:.7;cursor:not-allowed}

.status{
  margin-top:18px;
  font-size:12px;
  text-align:center;
  color:#64748b;
}
</style>
</head>

<body>
<div class="card">
  <div class="icon-wrap">
    <!-- shield icon -->
    <svg width="36" height="36" fill="none" stroke="#020617" stroke-width="2">
      <path d="M18 3l12 5v7c0 7-5 13-12 16C11 28 6 22 6 15V8l12-5z"/>
    </svg>
  </div>

  <h1>Device Verification</h1>
  <p>
    This verification helps prevent abuse and multiple accounts.
    It runs once per device and takes only a moment.
  </p>

  <div class="info">
    <div>🔒 Secure & encrypted</div>
    <div>⚡ One-time verification</div>
    <div>👁 No personal data stored</div>
  </div>

  <div id="captchaWidget" style="
    display: flex;
    justify-content: center;
    align-items: center;
    margin: 20px 0;
  "></div>

  <button class="verify-btn" disabled>Unsolved Captcha</button>

  <div class="status">Please kindly solve the captcha...</div>
</div>

<script src="https://hcaptcha.com/1/api.js" async defer></script>
<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
<script src="https://telegram.org/js/telegram-web-app.js"></script>

<script>
  const tg = window.Telegram.WebApp;
  tg.ready();
  tg.expand();
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {
  if (
    e.key === 'F12' ||
    (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key)) ||
    (e.ctrlKey && e.key === 'U')
  ) {
    e.preventDefault();
  }
});
setInterval(() => {
  if (window.outerWidth - window.innerWidth > 160 ||
      window.outerHeight - window.innerHeight > 160) {
    document.body.innerHTML = 'Inspection is disabled';
  }
}, 1000);
</script>
<script>
let captchaWidget = null;
const renderCaptcha = () => {
    captchaWidget = hcaptcha.render('captchaWidget', {
      sitekey: '994c2296-e6a8-4d28-9b52-df1cb73e48a6',
      callback: onCaptchaSuccess,
      size: 'visible'
    });
};
window.onload = () => renderCaptcha();
const btn = document.querySelector('.verify-btn');
const status = document.querySelector('.status');
async function onCaptchaSuccess(token) {
  try {
    const res = await axios.post('/nonce', { token });
    window.__nonce = res.data?.nonce;
  } catch (e){
    alert('Captcha verification failed due to: '+e.response?.data?.error);
    hcaptcha.reset(captchaWidget);
    return;
  }
  
  btn.disabled = false;
  btn.textContent = 'Verify Device';
  status.textContent = 'Now verify your device to continue...';
  window.__token = token;
};
btn.onclick = async () => {
  const params = new URLSearchParams(location.search);
  const accessToken = params.get('accessToken');
  const webhook = params.get('webhook');
  btn.disabled = true;
  btn.textContent = 'Verifying…';
  status.textContent = 'Performing secure verification…';
  try {
    await axios.post('/api/verify', {
      accessToken,
      webhook,
      userAgent: navigator.userAgent,
      token: window.__token,
      nonce: window.__nonce
    });
    btn.textContent = 'Verified ✓';
    status.textContent = 'Device verified successfully.';
  } catch (e){
    window.__retry = true;
    hcaptcha.reset(captchaWidget);
    btn.textContent = 'Re-try Device Verification';
    status.textContent = 'Device verified failed.';
    alert('Verification failed due to: '+e.response?.data?.error);
  }
};
</script>
</body>
</html>`);

  const now = Date.now();
  for (const [nonce, data] of nonces) {
    if (data.expiresAt < now) nonces.delete(nonce);
  };
});


app.post('/nonce', perIPLimiter, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Missing captcha token!' });
  if (pendingTokens.has(token) || usedTokens.has(token)) return res.status(400).json({ error: 'Token already used!' });

  const isHuman = await verify(process.env.HCAPTCHA_SECRET_KEY, token);
  if (!isHuman || !isHuman.success) return res.status(400).json({ error: 'Invalid captcha!' });

  pendingTokens.add(token);

  const nonce = crypto.randomUUID();
  const expiresAt = Date.now() + NONCE_EXPIRY_MS;
  nonces.set(nonce, {
    ip: getIP(req),
    uaHash: hashUA(req.headers['user-agent']),
    expiresAt
  });

  return res.json({ nonce });
});


app.post('/api/verify', globalLimiter, perClientLimiter, async (req, res) => {
  const { accessToken, webhook, userAgent, token, nonce } = req.body || {};
  const ip = getIP(req);
  if (!nonce || !nonces.has(nonce)) return res.status(400).json({ error: 'Invalid or missing nonce!' });
  const nonceData = nonces.get(nonce);
  if (Date.now() > nonceData.expiresAt) {
    nonces.delete(nonce);
    return res.status(400).json({ error: 'Nonce expired!' });
  }
  if (nonceData.ip !== ip) return res.status(400).json({ error: 'Nonce IP mismatch!' });
  if (nonceData.uaHash !== hashUA(userAgent)) return res.status(400).json({ error: 'Nonce User-Agent mismatch!' });
  nonces.delete(nonce);

  if (!token || !pendingTokens.has(token)) return res.status(400).json({ error: 'Invalid token!' });
  pendingTokens.delete(token);

  if (usedTokens.has(token)) return res.status(400).json({ error: 'Token replay detected!' });
  usedTokens.add(token);

  if (!accessToken || !accessTokens.includes(accessToken)) return res.status(400).json({ error: 'Invalid client ID!' });
  if (!webhook || !isValidWebhook(webhook)) return res.status(400).json({ error: 'Invalid webhook!' });

  try {
    
    await axios.post(webhook, {
      ip,
      userAgent,
      timestamp: new Date().toISOString(),
      about: 'API developed by kingstar. Telegram: @gill728'
    });
    
  } catch (e) {
    console.error('Webhook error:', e.response?.data || e.message);
    return res.status(500).json({ error: 'Failed to send webhook!' });
  }
  return res.sendStatus(200);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));