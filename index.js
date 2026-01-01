const express = require('express');
const axios = require('axios');
const {verify} = require('hcaptcha');

const app = express();
const PORT = 3000;

const clientIds = ["12345-Demo-Client"];

app.use(express.json());

function getIP(req) {
  return (
    req.headers['cf-connecting-ip'] ||
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress
  );
}

function isValidWebhook(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:';
  } catch {
    return false;
  }
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
function onCaptchaSuccess(token) {
  btn.disabled = false;
  btn.textContent = 'Verify Device';
  status.textContent = 'Now verify your device to continue...';
  window.__token = token;
};
btn.onclick = async () => {
  await navigator.clipboard.writeText(window.__token);
  const params = new URLSearchParams(location.search);
  const clientId = params.get('clientId');
  const webhook = params.get('webhook');
  btn.disabled = true;
  btn.textContent = 'Verifying…';
  status.textContent = 'Performing secure verification…';
  try {
    await axios.post('/api/verify', {
      clientId,
      webhook,
      userAgent: navigator.userAgent,
      token: window.__token
    });
    btn.textContent = 'Verified ✓';
    status.textContent = 'Device verified successfully.';
  } catch (e){
    btn.disabled = false;
    btn.textContent = 'Re-try Device Verification';
    status.textContent = 'Device verified failed.';
    alert('Verification failed due to: '+e.response?.data?.error);
  }
};
</script>
</body>
</html>`);
});


app.post('/api/verify', async (req, res) => {
  const ip = getIP(req);
  const { clientId, webhook, userAgent, token } = req.body;
  if (!clientId) return res.status(400).json({ error: 'Missing client ID!' });
  if (!webhook) return res.status(400).json({ error: 'Missing webhook Url!' });
  if (!userAgent) return res.status(400).json({ error: 'Missing user agent!' });
  if (!isValidWebhook(webhook)) {
    return res.status(400).json({ error: 'Invalid webhook!' });
  }
  if (!clientIds.includes(clientId)){
    return res.status(400).json({ error: 'Unregistered client ID!' });
  };
  if (!token) return res.status(400).json({ error: 'Missing captcha token! Refresh the page and try again.' });

  const isHuman = await verify(process.env.HCAPTCHA_SECRET_KEY, token);

  console.log(isHuman);
  if (!isHuman || !isHuman.success) return res.status(400).json({ error: 'Invalid captcha! Refresh the page and try again.' });
  
  try {
    await axios.post(webhook, {
      ip,
      userAgent,
      timestamp: new Date().toISOString()
    });
  } catch (e){
    console.error('Webhook error:', e.response?.data || e.message);
    return res.status(500).json({ error: 'Failed to send webhook!' });
  }
  
  return res.sendStatus(200);
});

app.post('/webhook', (req, res) => {
  console.log('Webhook received:', req.body);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log('Running → http://localhost:' + PORT);
});