"""
Build script: encrypts app.html into index.html with login gate.
Uses the same primitives as Web Crypto API:
  - PBKDF2-HMAC-SHA256 (600,000 iterations) → 256-bit AES key
  - AES-GCM-256 encryption
"""
import base64, os, re, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

USER = "payroll@benisonsolvers.co.uk"
PASS = "benison@sarv14"
ITER = 600_000

# --- Read original app ---
with open("app.html", "r", encoding="utf-8") as f:
    full = f.read()

style_match = re.search(r"<style>[\s\S]*?</style>", full)
body_match  = re.search(r"<body>([\s\S]*?)</body>", full)
if not style_match or not body_match:
    sys.exit("Could not parse app.html")

bundle = style_match.group(0) + "\n" + body_match.group(1)
bundle_bytes = bundle.encode("utf-8")
print(f"Bundle: {len(bundle_bytes)} bytes")

# --- Derive key ---
salt = os.urandom(16)
iv   = os.urandom(12)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=ITER,
)
key = kdf.derive((USER + ":" + PASS).encode("utf-8"))

# --- Encrypt ---
aesgcm = AESGCM(key)
ct = aesgcm.encrypt(iv, bundle_bytes, associated_data=None)
# Python's AESGCM returns ciphertext || tag (same order as Web Crypto API)

b64 = lambda b: base64.b64encode(b).decode("ascii")
SALT_B64 = b64(salt)
IV_B64   = b64(iv)
CT_B64   = b64(ct)

print(f"salt={SALT_B64}  iv={IV_B64}  ct_b64_len={len(CT_B64)}")

# --- Build index.html ---
template = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Payslip Generator</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:Arial,Helvetica,sans-serif;
  background:linear-gradient(135deg,#1e3a5f 0%,#3b82f6 100%);
  color:#1f2937;display:flex;align-items:center;justify-content:center;
  min-height:100vh;padding:20px;
}
.login-card{
  background:#fff;border-radius:10px;
  box-shadow:0 20px 60px rgba(0,0,0,.25);
  width:100%;max-width:380px;padding:32px 28px;
}
.brand{text-align:center;margin-bottom:24px}
.brand-title{font-size:20px;font-weight:700;color:#0f172a}
.brand-sub{font-size:11px;color:#6b7280;margin-top:4px;letter-spacing:.5px;text-transform:uppercase}
.field{display:flex;flex-direction:column;gap:5px;margin-bottom:14px}
.field label{font-size:11px;font-weight:600;color:#374151}
.field input{
  width:100%;padding:9px 11px;
  border:1px solid #d1d5db;border-radius:5px;
  font-size:13px;background:#fff;color:#111827;
  transition:border-color .15s;
}
.field input:focus{outline:none;border-color:#3b82f6}
.btn-signin{
  width:100%;padding:11px;margin-top:6px;
  background:#3b82f6;color:#fff;border:none;border-radius:5px;
  font-size:13px;font-weight:700;cursor:pointer;transition:filter .15s;
}
.btn-signin:hover{filter:brightness(.92)}
.btn-signin:disabled{background:#9ca3af;cursor:wait}
.err{
  min-height:18px;margin-top:10px;text-align:center;
  font-size:12px;color:#dc2626;font-weight:600;
}
.foot{font-size:10px;color:#9ca3af;text-align:center;margin-top:18px}
</style>
</head>
<body>

<div class="login-card" id="loginCard">
  <div class="brand">
    <div class="brand-title">Payslip Generator</div>
    <div class="brand-sub">Secure Sign-In</div>
  </div>
  <form id="loginForm" autocomplete="on">
    <div class="field">
      <label for="u">Username</label>
      <input id="u" type="text" autocomplete="username" required>
    </div>
    <div class="field">
      <label for="p">Password</label>
      <input id="p" type="password" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn-signin" id="btnSignin">Sign in</button>
    <div class="err" id="err"></div>
  </form>
  <div class="foot">Your data is encrypted. Credentials never leave your browser.</div>
</div>

<script>
const SALT_B64 = "__SALT__";
const IV_B64   = "__IV__";
const ITER     = __ITER__;
const CT_B64   = "__CT__";

const b64dec = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function unlock(user, pass) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(user + ":" + pass),
    { name: "PBKDF2" }, false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64dec(SALT_B64), iterations: ITER, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false, ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64dec(IV_B64) },
    key, b64dec(CT_B64)
  );
  return new TextDecoder().decode(plain);
}

function mountApp(html) {
  document.body.innerHTML = html;
  document.body.style.cssText = "";
  document.body.querySelectorAll("script").forEach(old => {
    const s = document.createElement("script");
    if (old.src) s.src = old.src;
    else s.textContent = old.textContent;
    old.replaceWith(s);
  });
}

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("btnSignin");
  const err = document.getElementById("err");
  const user = document.getElementById("u").value.trim();
  const pass = document.getElementById("p").value;
  btn.disabled = true;
  btn.textContent = "Verifying…";
  err.textContent = "";
  try {
    const html = await unlock(user, pass);
    mountApp(html);
  } catch {
    err.textContent = "Invalid username or password";
    btn.disabled = false;
    btn.textContent = "Sign in";
    document.getElementById("p").value = "";
    document.getElementById("p").focus();
  }
});

document.getElementById("u").focus();
</script>

</body>
</html>
'''

out = (template
       .replace("__SALT__", SALT_B64)
       .replace("__IV__", IV_B64)
       .replace("__ITER__", str(ITER))
       .replace("__CT__", CT_B64))

with open("index.html", "w", encoding="utf-8", newline="\n") as f:
    f.write(out)

print(f"Wrote index.html ({len(out)} chars)")
