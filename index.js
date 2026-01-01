const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { verify } = require("hcaptcha");

const app = express();
const PORT = 3000;

app.use(express.json());

/* ================= CONFIG ================= */

const ACCESS_TOKENS = ["12345-Demo-Client"];
const NONCE_EXPIRY_MS = 10_000;

/* ================= MEMORY STORES ================= */
/* NOTE: For production, replace with Redis / DB */

const nonces = new Map(); // nonce -> { fpHash, expiresAt }
const pendingTokens = new Set(); // captcha tokens
const usedTokens = new Set(); // replay protection
const fingerprints = new Map(); // fpHash -> count (multi detect)

/* ================= RATE LIMITS ================= */

const globalLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ================= HELPERS ================= */

function hash(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function isValidWebhook(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:";
  } catch {
    return false;
  }
}

app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Device Verification</title>

    <style>
      :root {
        --primary: #3b82f6;
        --cyan: #22d3ee;
        --bg: #020617;
      }

      * {
        box-sizing: border-box;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
          sans-serif;
      }

      body {
        user-select: none;
        margin: 0;
        height: 100vh;
        background: radial-gradient(
            600px circle at 20% 20%,
            rgba(59, 130, 246, 0.15),
            transparent
          ),
          radial-gradient(
            800px circle at 80% 80%,
            rgba(34, 211, 238, 0.15),
            transparent
          ),
          var(--bg);
        display: flex;
        align-items: center;
        justify-content: center;
        overflow: hidden;
        color: #e5e7eb;
      }

      .card {
        width: 100%;
        max-width: 460px;
        padding: 32px 28px;
        border-radius: 24px;
        background: rgba(2, 6, 23, 0.75);
        backdrop-filter: blur(14px);
        border: 1px solid rgba(148, 163, 184, 0.15);
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.6);
        animation: floatIn 0.6s ease forwards;
      }

      @keyframes floatIn {
        from {
          opacity: 0;
          transform: translateY(20px) scale(0.98);
        }
        to {
          opacity: 1;
          transform: none;
        }
      }

      .icon-wrap {
        width: 72px;
        height: 72px;
        border-radius: 18px;
        background: linear-gradient(135deg, var(--cyan), var(--primary));
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 18px;
        box-shadow: 0 10px 30px rgba(59, 130, 246, 0.45);
      }

      h1 {
        margin: 10px 0 8px;
        text-align: center;
        font-size: 24px;
      }

      p {
        text-align: center;
        color: #94a3b8;
        font-size: 14px;
        line-height: 1.7;
      }

      .info {
        margin-top: 22px;
        display: grid;
        gap: 12px;
      }

      .info div {
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 13px;
        color: #cbd5f5;
      }

      .verify-btn {
        width: 100%;
        padding: 16px;
        border: none;
        border-radius: 14px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        background: linear-gradient(135deg, var(--cyan), var(--primary));
        color: #020617;
        transition: 0.2s;
      }

      .verify-btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 12px 30px rgba(59, 130, 246, 0.45);
      }
      .verify-btn:disabled {
        opacity: 0.7;
        cursor: not-allowed;
      }

      .status {
        margin-top: 18px;
        font-size: 12px;
        text-align: center;
        color: #64748b;
      }
    </style>
  </head>

  <body>
    <div class="card">
      <div class="icon-wrap">
        <svg
          width="36"
          height="36"
          fill="none"
          stroke="#020617"
          stroke-width="2"
        >
          <path d="M18 3l12 5v7c0 7-5 13-12 16C11 28 6 22 6 15V8l12-5z" />
        </svg>
      </div>

      <h1>Device Verification</h1>
      <p>
        This verification helps prevent abuse and multiple accounts. It runs
        once per device and takes only a moment.
      </p>

      <div class="info">
        <div>🔒 Secure & encrypted</div>
        <div>⚡ One-time verification</div>
        <div>👁 No personal data stored</div>
      </div>

      <div
        id="captchaWidget"
        style="
          display: flex;
          justify-content: center;
          align-items: center;
          margin: 20px 0;
        "
      ></div>

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
      document.addEventListener("contextmenu", (e) => e.preventDefault());
      document.addEventListener("keydown", (e) => {
        if (
          e.key === "F12" ||
          (e.ctrlKey && e.shiftKey && ["I", "J", "C"].includes(e.key)) ||
          (e.ctrlKey && e.key === "U")
        ) {
          e.preventDefault();
        }
      });
      setInterval(() => {
        if (
          window.outerWidth - window.innerWidth > 160 ||
          window.outerHeight - window.innerHeight > 160
        ) {
          document.body.innerHTML = "Inspection is disabled";
        }
      }, 1000);
    </script>

    <script>
      async function sha256(input) {
        const buf = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(input)
        );
        return [...new Uint8Array(buf)]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      function canvasFP() {
        const c = document.createElement("canvas");
        const x = c.getContext("2d");
        x.font = "14px Arial";
        x.fillText("fp_test", 2, 15);
        return c.toDataURL();
      }

      function webglFP() {
        const c = document.createElement("canvas");
        const g = c.getContext("webgl");
        if (!g) return "no-webgl";
        const d = g.getExtension("WEBGL_debug_renderer_info");
        return d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : "unknown";
      }

      async function getFingerprint() {
        return sha256(
          [
            navigator.userAgent,
            navigator.language,
            navigator.platform,
            navigator.hardwareConcurrency,
            screen.width + "x" + screen.height,
            canvasFP(),
            webglFP(),
          ].join("|")
        );
      }

      let TOKEN = null,
        NONCE = null,
        FP = null;

      const verifyBtn = document.querySelector(".verify-btn");
      const status = document.querySelector(".status");

      window.onload = async () => {
        hcaptcha.render("captchaWidget", {
          sitekey: "994c2296-e6a8-4d28-9b52-df1cb73e48a6",
          callback: async (t) => {
            TOKEN = t;
            FP = await getFingerprint();
            const r = await axios.post("/nonce", { token: t, fingerprint: FP });
            NONCE = r.data.nonce;
            verifyBtn.disabled = false;
            verifyBtn.textContent = 'Verify Device';
            status.textContent = 'Now verify your device to continue...';
          },
        });
      };
      
      verifyBtn.onclick = async () => {
        verifyBtn.disabled = true;
        verifyBtn.textContent = "Verifying…";
        status.textContent = 'Performing secure verification…';

        const params = new URLSearchParams(location.search);

        try {
        await axios.post("/api/verify", {
          acessToken: params.get("acessToken"),
          webhook: params.get("webhook"),
          token: TOKEN,
          nonce: NONCE,
          fingerprint: FP,
        });
        verifyBtn.textContent = "Verified ✔";
        status.textContent = 'Device verified successfully.';
        if (params.get('redirect')) window.location.href = params.get('redirect');
        } catch (e) {
        verifyBtn.textContent = "Retry Verification ✔";
        status.textContent = 'Device verification failed.';
        alert(JSON.stringify(e.response?.data || e.message))
        }

        
      };
    </script>
  </body>
</html>
`);
});

app.post("/nonce", globalLimiter, async (req, res) => {
  const { token, fingerprint } = req.body;

  if (!token || !fingerprint)
    return res.status(400).json({ error: "Missing token or fingerprint" });

  if (pendingTokens.has(token) || usedTokens.has(token))
    return res.status(400).json({ error: "Token already used" });

  const human = await verify(process.env.HCAPTCHA_SECRET_KEY, token);
  if (!human.success) return res.status(400).json({ error: "Invalid captcha" });

  pendingTokens.add(token);

  const nonce = crypto.randomUUID();
  nonces.set(nonce, {
    fpHash: hash(fingerprint),
    expiresAt: Date.now() + NONCE_EXPIRY_MS,
  });

  res.json({ nonce });
});

app.post("/api/verify", globalLimiter, async (req, res) => {
  const { acessToken, webhook, token, nonce, fingerprint } = req.body;
  
  if (!ACCESS_TOKENS.includes(acessToken))
    return res.status(400).json({ error: 'Invalid Access Token' });

  if (!webhook || !isValidWebhook(webhook))
    return res.status(400).json({ error: 'Invalid webhook' });

  if (!nonce || !nonces.has(nonce))
    return res.status(400).json({ error: "Invalid nonce" });

  const nonceData = nonces.get(nonce);
  nonces.delete(nonce);

  if (Date.now() > nonceData.expiresAt)
    return res.status(400).json({ error: "Nonce expired" });

  const fpHash = hash(fingerprint);
  if (fpHash !== nonceData.fpHash)
    return res.status(400).json({ error: "Fingerprint mismatch" });

  if (usedTokens.has(token))
    return res.status(400).json({ error: "Invalid token state (used)" });

  if (!pendingTokens.has(token))
    return res.status(400).json({ error: "Invalid token state" });

  pendingTokens.delete(token);
  usedTokens.add(token);

  console.log(fingerprint, fpHash);
  
  await axios.post(webhook, {
    fingerprint: fpHash,
    timestamp: new Date().toISOString()
  });

  res.sendStatus(200);
});

app.listen(PORT, () => console.log(`Running → http://localhost:${PORT}`));
