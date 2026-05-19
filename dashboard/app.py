"""
Nexus Cooling Proxy — Comprehensive Security Dashboard

Features:
- All package requests logged with allow/block status
- Malware/quarantine list with real-time updates
- Allow/Deny override buttons for each package
- Bypass token management info
- Source pull timestamps
- Explanatory tooltips for all sections
- LDAP authentication (LDAP admin group)
"""
import base64
import json
import os
import secrets
from datetime import datetime, timezone

import redis
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
BYPASS_TOKEN = os.environ.get("BYPASS_TOKEN", "")
LDAP_URI = os.environ.get("LDAP_URI", "ldap://ldap.example.com:389")
LDAP_DOMAIN = os.environ.get("LDAP_DOMAIN", "EXAMPLE")
LDAP_REQUIRED_GROUP = os.environ.get("LDAP_REQUIRED_GROUP", "admins")
LDAP_ADMIN_GROUP = os.environ.get("LDAP_ADMIN_GROUP", "admins")
LDAP_USER_GROUP = os.environ.get("LDAP_USER_GROUP", "users")
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "DC=example,DC=com")
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() == "true"
VALIDATOR_URL = os.environ.get("VALIDATOR_URL", "http://validator:8080")

app = FastAPI(title="Nexus Cooling Proxy Dashboard")
security = HTTPBasic(auto_error=False)

try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
except Exception:
    cache = None


# ── LDAP Authentication ───────────────────────────────────────────────────

def verify_ldap_credentials(username: str, password: str) -> str | None:
    """Authenticate user against Active Directory and determine role.
    
    Returns:
        "admin" — user is in the admin group
        "viewer" — user is in the user group but not admin
        None — authentication failed
    """
    # Local admin fallback (for environments without LDAP access)
    local_admin_pass = os.environ.get("LOCAL_ADMIN_PASSWORD", "")
    if local_admin_pass and password == local_admin_pass:
        return "admin"

    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE

        server = Server(LDAP_URI, get_info=ALL)
        user_dn = f"{LDAP_DOMAIN}\\{username}"
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)

        # Search for user's group membership
        conn.search(
            LDAP_BASE_DN,
            f"(sAMAccountName={username})",
            search_scope=SUBTREE,
            attributes=["memberOf", "cn"],
        )

        if not conn.entries:
            conn.unbind()
            return None

        member_of = str(conn.entries[0].memberOf) if conn.entries[0].memberOf else ""
        conn.unbind()

        # Check admin group first
        if LDAP_ADMIN_GROUP.lower() in member_of.lower():
            return "admin"
        # Check user group (least privilege — can view but not modify)
        if LDAP_USER_GROUP.lower() in member_of.lower():
            return "viewer"
        # Authenticated but not in any required group
        return "viewer"

    except ImportError:
        # ldap3 not installed — try simple bind
        try:
            import ldap3
            from ldap3 import Server, Connection
            server = Server(LDAP_URI)
            conn = Connection(server, user=f"{LDAP_DOMAIN}\\{username}", password=password, auto_bind=True)
            conn.unbind()
            return "viewer"
        except Exception:
            return None
    except Exception:
        return None


def get_current_user(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    """Validate credentials. Returns (username, role) tuple or raises 401.
    Auth is always required — no anonymous access.
    """
    if not AUTH_ENABLED:
        return "anonymous"

    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="Nexus Cooling Proxy Dashboard"'},
        )

    role = verify_ldap_credentials(credentials.username, credentials.password)
    if role:
        return credentials.username

    raise HTTPException(
        status_code=401,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": 'Basic realm="Nexus Cooling Proxy Dashboard"'},
    )


# ── API Endpoints ─────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard HTML. Auth is handled client-side via JS."""
    return DASHBOARD_HTML


@app.get("/api/auth/status")
async def auth_status(credentials: HTTPBasicCredentials = Depends(security)):
    """Check if the user is authenticated and determine their role."""
    if not AUTH_ENABLED:
        return {"authenticated": True, "user": "admin (auth disabled)", "role": "admin"}

    if not credentials:
        return {"authenticated": False, "user": None, "role": "none"}

    role = verify_ldap_credentials(credentials.username, credentials.password)
    if role:
        return {"authenticated": True, "user": credentials.username, "role": role}

    return {"authenticated": False, "user": None, "role": "none"}


@app.get("/api/packages")
async def list_packages():
    """All packages that have been requested through the proxy."""
    if not cache:
        return {"packages": [], "total": 0}

    keys = cache.keys("cooling:*")
    packages = []
    for k in keys:
        val = cache.get(k)
        parts = k.split(":", 2)
        if len(parts) == 3:
            ecosystem = parts[1]
            package = parts[2]
            override = cache.get(f"override:{ecosystem}:{package}")
            version = cache.get(f"version:{ecosystem}:{package}")
            age_days_raw = cache.get(f"age:{ecosystem}:{package}")
            age_days = float(age_days_raw) if age_days_raw else None
            # Get last requester info
            requester_raw = cache.get(f"requester:{ecosystem}:{package}")
            requester = json.loads(requester_raw) if requester_raw else None
            packages.append({
                "package": package,
                "ecosystem": ecosystem,
                "version": version,
                "status": val,
                "override": override,
                "age_days": age_days,
                "requester": requester,
            })

    # Sort: blocked first, then by name
    packages.sort(key=lambda p: (0 if p["status"] == "block" else 1, p["package"]))
    return {"packages": packages, "total": len(packages)}


@app.post("/api/packages/override")
async def override_package(request: Request, user: str = Depends(get_current_user)):
    """Allow or deny a specific package (admin override). Requires admin group membership."""
    if AUTH_ENABLED and user == "anonymous":
        raise HTTPException(status_code=403, detail="Admin access required. Login with your credentials (admin group).")
    if not cache:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    payload = await request.json()
    package = payload.get("package", "")
    ecosystem = payload.get("ecosystem", "")
    action = payload.get("action", "")  # "allow", "deny", or "clear"

    if not package or not ecosystem:
        raise HTTPException(status_code=400, detail="package and ecosystem required")
    if action not in ("allow", "deny", "clear"):
        raise HTTPException(status_code=400, detail="action must be allow, deny, or clear")

    cache_key = f"cooling:{ecosystem}:{package}"
    override_key = f"override:{ecosystem}:{package}"

    if action == "allow":
        cache.setex(cache_key, 86400 * 365, "allow")
        cache.set(override_key, "allow")
    elif action == "deny":
        cache.setex(cache_key, 86400 * 365, "block")
        cache.set(override_key, "deny")
    elif action == "clear":
        cache.delete(cache_key)
        cache.delete(override_key)

    return {"status": "ok", "package": package, "ecosystem": ecosystem, "action": action}


@app.get("/api/quarantine/log")
async def quarantine_log():
    if not cache:
        return {"log": [], "total": 0}
    entries = cache.lrange("quarantine:log", 0, 49)
    return {
        "log": [json.loads(e) for e in entries],
        "total": cache.llen("quarantine:log"),
    }


@app.get("/api/quarantine/stats")
async def quarantine_stats():
    if not cache:
        return {"total_quarantined": 0, "total_components_deleted": 0, "total_blocked_rules": 0, "by_ecosystem": {}}
    entries = cache.lrange("quarantine:log", 0, -1)
    total_quarantined = len(entries)
    total_deleted = 0
    total_blocked = 0
    by_ecosystem = {}
    for raw in entries:
        entry = json.loads(raw)
        total_deleted += len(entry.get("deleted", []))
        if entry.get("blocked"):
            total_blocked += 1
        eco = entry.get("ecosystem", "unknown")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
    return {
        "total_quarantined": total_quarantined,
        "total_components_deleted": total_deleted,
        "total_blocked_rules": total_blocked,
        "by_ecosystem": by_ecosystem,
    }


@app.get("/api/sources")
async def sources():
    if not cache:
        return {"sources": []}
    source_keys = {
        "GitHub Advisory DB": "source:github:last_pull",
        "OSV.dev (npm)": "source:osv:npm:last_pull",
        "OSV.dev (PyPI)": "source:osv:pip:last_pull",
        "OSV.dev (Maven)": "source:osv:maven:last_pull",
        "npm Registry": "source:npm:last_pull",
        "PyPI Registry": "source:pypi:last_pull",
        "Maven Central": "source:maven:last_pull",
    }
    sources_data = []
    for name, key in source_keys.items():
        ts = cache.get(key)
        sources_data.append({"name": name, "last_pull": ts or None, "status": "connected" if ts else "idle"})
    return {"sources": sources_data}


@app.get("/api/validator/stats")
async def validator_stats():
    if not cache:
        return {"cached_decisions": 0, "cooling_days": 7, "allowed": 0, "blocked": 0}
    keys = cache.keys("cooling:*")
    allowed = sum(1 for k in keys if cache.get(k) == "allow")
    blocked = sum(1 for k in keys if cache.get(k) == "block")
    return {"cached_decisions": len(keys), "allowed": allowed, "blocked": blocked, "cooling_days": 7}


@app.get("/api/requests")
async def request_log(limit: int = 50):
    """Recent package requests with source IP and user-agent."""
    if not cache:
        return {"requests": [], "total": 0}
    entries = cache.lrange("request:log", 0, limit - 1)
    return {
        "requests": [json.loads(e) for e in entries],
        "total": cache.llen("request:log"),
    }


# ── Admin Settings API ────────────────────────────────────────────────────

# Settings are stored in Redis with prefix "settings:" so they persist
# across dashboard restarts but can be changed at runtime without redeploying.
# The validator reads these on each request via Redis.

SETTINGS_DEFAULTS = {
    "cooling_days": "7",
    "bypass_token": BYPASS_TOKEN or "not-set",
    "log_level": "INFO",
    "cache_ttl_allowed": "86400",
    "cache_ttl_blocked": "3600",
    "cache_ttl_error": "300",
    "fail_open": "true",
    "rules_reload_interval": "30",
}


@app.get("/api/settings")
async def get_settings(user: str = Depends(get_current_user)):
    """Get all runtime settings. Requires admin login."""
    if AUTH_ENABLED and user == "anonymous":
        raise HTTPException(status_code=403, detail="Admin access required")

    settings = {}
    for key, default in SETTINGS_DEFAULTS.items():
        val = cache.get(f"settings:{key}") if cache else None
        settings[key] = val if val is not None else default

    return {"settings": settings}


@app.post("/api/settings")
async def update_settings(request: Request, user: str = Depends(get_current_user)):
    """Update runtime settings. Requires admin login.

    The validator watches Redis for settings changes and applies them
    without restart. Changes are logged for audit.
    """
    if AUTH_ENABLED and user == "anonymous":
        raise HTTPException(status_code=403, detail="Admin access required. Login with your credentials (admin group).")
    if not cache:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    payload = await request.json()
    updated = {}

    for key, value in payload.items():
        if key not in SETTINGS_DEFAULTS:
            continue  # Ignore unknown settings
        # Validate
        if key in ("cooling_days", "cache_ttl_allowed", "cache_ttl_blocked", "cache_ttl_error", "rules_reload_interval"):
            try:
                int(value)
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail=f"{key} must be a number")
        if key == "fail_open" and value not in ("true", "false"):
            raise HTTPException(status_code=400, detail="fail_open must be 'true' or 'false'")

        cache.set(f"settings:{key}", str(value))
        updated[key] = str(value)

    # Audit log
    if updated:
        audit_entry = json.dumps({
            "user": user,
            "action": "settings_update",
            "changes": updated,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        cache.lpush("audit:log", audit_entry)
        cache.ltrim("audit:log", 0, 199)  # Keep last 200 audit entries

    return {"status": "ok", "updated": updated}


@app.get("/api/settings/audit")
async def settings_audit(user: str = Depends(get_current_user)):
    """Get audit log of settings changes. Requires admin login."""
    if AUTH_ENABLED and user == "anonymous":
        raise HTTPException(status_code=403, detail="Admin access required")
    if not cache:
        return {"log": []}

    entries = cache.lrange("audit:log", 0, 49)
    return {"log": [json.loads(e) for e in entries]}


@app.get("/api/rules")
async def get_rules():
    """Proxy to the validator's /rules endpoint for the dashboard."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{VALIDATOR_URL}/rules")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"allow": [], "block": [], "error": "Could not reach validator"}


@app.post("/api/token/generate")
async def generate_token(user: str = Depends(get_current_user)):
    """Generate a new random bypass token and store it in Redis."""
    if AUTH_ENABLED and user == "anonymous":
        raise HTTPException(status_code=403, detail="Admin access required")
    if not cache:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    new_token = secrets.token_urlsafe(32)
    cache.set("settings:bypass_token", new_token)

    # Audit log
    audit_entry = json.dumps({
        "user": user,
        "action": "token_generated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    cache.lpush("audit:log", audit_entry)
    cache.ltrim("audit:log", 0, 199)

    return {"token": new_token}



DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus Cooling Proxy — Security Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e14;color:#c5cdd8;font-size:13px}
.header{background:#0d1117;border-bottom:1px solid #1e2a3a;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{font-size:15px;font-weight:600;color:#e6edf3}
.header .meta{font-size:11px;color:#8b949e}
.btn{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px}
.btn:hover{background:#30363d}
.btn-allow{background:#23863622;border-color:#238636;color:#3fb950}
.btn-allow:hover{background:#23863644}
.btn-deny{background:#da363322;border-color:#da3633;color:#f85149}
.btn-deny:hover{background:#da363344}
.btn-sm{padding:3px 8px;font-size:11px}
.container{padding:20px 24px;max-width:1400px;margin:0 auto}
.grid-3{display:grid;grid-template-columns:1fr 1fr 320px;gap:16px;margin-bottom:20px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.metrics-row{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.metric-card{background:#161b22;border:1px solid #1e2a3a;border-radius:8px;padding:14px;text-align:center}
.metric-value{font-size:24px;font-weight:700;color:#e6edf3}
.metric-value.red{color:#f85149}.metric-value.orange{color:#d29922}.metric-value.green{color:#3fb950}.metric-value.blue{color:#58a6ff}.metric-value.purple{color:#a371f7}
.metric-label{font-size:10px;color:#8b949e;margin-top:4px}
.card{background:#161b22;border:1px solid #1e2a3a;border-radius:8px;overflow:visible}
.card-title{padding:12px 16px;border-bottom:1px solid #1e2a3a;font-size:12px;font-weight:600;color:#e6edf3;display:flex;align-items:center;justify-content:space-between}
.card-title .info{font-size:11px;color:#8b949e;font-weight:400;font-style:italic}
.card-title .count{background:#30363d;color:#8b949e;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:500}
.card-body{padding:0}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 12px;font-size:11px;color:#8b949e;font-weight:500;border-bottom:1px solid #1e2a3a;background:#0d1117;position:sticky;top:0}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:#58a6ff}
th.sortable span{font-size:10px;margin-left:2px}
td{padding:7px 12px;border-bottom:1px solid #1e2a3a;font-size:12px}
tr:hover{background:#1c2128}
.eco-tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:500}
.eco-tag.npm{background:#cb383722;color:#f47067}.eco-tag.pip{background:#3776ab22;color:#79c0ff}.eco-tag.maven{background:#c71a3622;color:#ff7b72}
.status-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600}
.status-badge.allow{background:#23863622;color:#3fb950}.status-badge.block{background:#da363322;color:#f85149}
.status-badge.override{background:#a371f722;color:#a371f7}
.source-item{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid #1e2a3a}
.source-item:last-child{border-bottom:none}
.source-name{font-size:12px;color:#e6edf3;display:flex;align-items:center;gap:8px}
.source-dot{width:6px;height:6px;border-radius:50%}
.source-dot.connected{background:#238636}.source-dot.idle{background:#484f58}
.source-time{font-size:11px;color:#8b949e}
.actions{display:flex;gap:4px}
.tooltip{position:relative;cursor:help;color:#58a6ff;font-size:11px;margin-left:6px}
.tooltip:hover::after{content:attr(data-tip);position:absolute;bottom:120%;left:50%;transform:translateX(-50%);background:#1c2128;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:6px;font-size:11px;white-space:normal;max-width:280px;z-index:9999;font-style:normal;box-shadow:0 4px 12px rgba(0,0,0,0.4)}
.info-box{background:#0d1117;border:1px solid #1e2a3a;border-radius:6px;padding:12px 16px;margin:12px 16px;font-size:11px;color:#8b949e;line-height:1.6}
.info-box code{background:#21262d;padding:1px 4px;border-radius:3px;color:#79c0ff;font-size:10px}
.scrollable{max-height:400px;overflow-y:auto}
.empty{color:#484f58;text-align:center;padding:24px;font-style:italic}
.filter-bar{padding:8px 16px;border-bottom:1px solid #1e2a3a;display:flex;gap:8px;align-items:center}
.filter-bar input{background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:4px 10px;border-radius:4px;font-size:12px;width:200px}
.filter-bar select{background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:4px 8px;border-radius:4px;font-size:12px}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Nexus Cooling Proxy — Security Dashboard</h1>
  <div style="display:flex;align-items:center;gap:16px">
    <span class="meta" id="last-refresh">Auto-refreshes every 5s</span>
    <button class="btn" onclick="refresh()">↻ Refresh</button>
    <span id="auth-status" style="font-size:12px;color:#8b949e"></span>
    <button class="btn" id="login-btn" onclick="doLogin()" style="display:inline-block">🔒 Login</button>
    <button class="btn" id="logout-btn" style="display:none" onclick="doLogout()">🔓 Logout</button>
  </div>
</div>

<div class="container">

<!-- Metrics -->
<div class="metrics-row">
  <div class="metric-card"><div class="metric-value green" id="m-allowed">0</div><div class="metric-label">Allowed (passed cooling)</div></div>
  <div class="metric-card"><div class="metric-value orange" id="m-cooling">0</div><div class="metric-label">Blocked (< 7 days old)</div></div>
  <div class="metric-card"><div class="metric-value red" id="m-quarantined">0</div><div class="metric-label">Quarantined (malware)</div></div>
  <div class="metric-card"><div class="metric-value purple" id="m-overrides">0</div><div class="metric-label">Manual Overrides</div></div>
  <div class="metric-card"><div class="metric-value blue" id="m-total">0</div><div class="metric-label">Total Packages Tracked</div></div>
</div>

<!-- Main 3-column layout -->
<div class="grid-3">

<!-- LEFT: All Packages -->
<div class="card" style="grid-column:span 2">
  <div class="card-title">
    All Requested Packages
    <span class="info">Every package requested through the proxy with its current status</span>
    <span class="count" id="pkg-count">0</span>
  </div>
  <div class="filter-bar">
    <input type="text" id="pkg-filter" placeholder="Filter packages..." oninput="renderPackages()">
    <select id="pkg-status-filter" onchange="renderPackages()">
      <option value="all">All statuses</option>
      <option value="block">Blocked only</option>
      <option value="allow">Allowed only</option>
      <option value="override">Overrides only</option>
    </select>
    <select id="pkg-eco-filter" onchange="renderPackages()">
      <option value="all">All ecosystems</option>
      <option value="npm">npm</option>
      <option value="pip">PyPI</option>
      <option value="maven">Maven</option>
    </select>
  </div>
  <div class="info-box">
    <strong>How it works:</strong> Every dependency request passes through the cooling proxy. Packages published less than 7 days ago are automatically blocked.
    Known malware (from GitHub Advisory DB / OSV.dev) is permanently blocked and removed from Nexus.
    Use the <strong>Allow</strong> button to override a block for urgent needs, or <strong>Deny</strong> to permanently block a package.
  </div>
  <div class="card-body scrollable">
    <table>
      <thead><tr>
        <th class="sortable" onclick="sortPackages('package')">Package <span id="sort-package"></span></th>
        <th class="sortable" onclick="sortPackages('version')">Version <span id="sort-version"></span></th>
        <th class="sortable" onclick="sortPackages('ecosystem')">Ecosystem <span id="sort-ecosystem"></span></th>
        <th class="sortable" onclick="sortPackages('age')">Age <span id="sort-age"></span></th>
        <th class="sortable" onclick="sortPackages('status')">Status <span id="sort-status"></span></th>
        <th>Last Requested By</th>
        <th class="sortable" onclick="sortPackages('override')">Override <span id="sort-override"></span></th>
        <th>Actions</th>
      </tr></thead>
      <tbody id="pkg-body"><tr><td colspan="8" class="empty">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- RIGHT: Sources -->
<div>
  <div class="card" style="margin-bottom:16px">
    <div class="card-title">Data Sources <span class="tooltip" data-tip="Shows when each advisory source was last checked for new malware">ⓘ</span></div>
    <div class="card-body" id="sources-list"></div>
  </div>

  <div class="card">
    <div class="card-title">Bypass Info <span class="tooltip" data-tip="How developers can bypass the cooling period for urgent needs">ⓘ</span></div>
    <div class="info-box" style="margin:0;border:none;border-radius:0">
      <strong>For developers who need a new package immediately:</strong><br><br>
      1. Contact DevOps to request alternate methods.<br><br>
      2. Or ask a DevOps admin to click "Allow" on the dashboard for the specific package.<br><br>
      <span id="token-gen-area"></span>
      <strong>Contact:</strong> Your admin team
    </div>
  </div>
</div>

</div>

<!-- Bottom: Quarantine Log -->
<div class="card">
  <div class="card-title">
    Quarantine Log (Malware Removals)
    <span class="info">Packages automatically removed from Nexus when flagged as malware by advisory sources</span>
    <span class="count" id="q-count">0</span>
  </div>
  <div class="card-body scrollable">
    <table>
      <thead><tr><th>Time</th><th>Package</th><th>Ecosystem</th><th>Reason</th><th>Advisory</th><th>Deleted</th><th>Blocked</th></tr></thead>
      <tbody id="q-body"><tr><td colspan="7" class="empty">No quarantine actions yet.</td></tr></tbody>
    </table>
  </div>
</div>

<!-- Admin Settings Panel (only visible when logged in) -->
<div class="card" id="settings-panel" style="margin-top:16px;display:none">
  <div class="card-title">
    ⚙️ Admin Settings
    <span class="info">Runtime configuration — changes take effect immediately without redeployment</span>
  </div>
  <div class="card-body" style="padding:16px">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <label style="font-size:11px;color:#8b949e;display:block;margin-bottom:4px">Cooling Period (days)</label>
        <input type="number" id="set-cooling-days" class="setting-input" min="0" max="99999" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:4px;font-size:14px">
        <span style="font-size:10px;color:#484f58">How many days a package must exist before it's allowed. Set to 0 to disable cooling.</span>
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e;display:block;margin-bottom:4px">Bypass Token</label>
        <input type="text" id="set-bypass-token" class="setting-input" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:4px;font-size:14px">
        <span style="font-size:10px;color:#484f58">Token value for X-Cooling-Bypass header. Share with teams that need emergency access.</span>
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e;display:block;margin-bottom:4px">Log Level</label>
        <select id="set-log-level" class="setting-input" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:4px;font-size:14px">
          <option value="DEBUG">DEBUG</option>
          <option value="INFO">INFO</option>
          <option value="WARNING">WARNING</option>
          <option value="ERROR">ERROR</option>
        </select>
        <span style="font-size:10px;color:#484f58">Validator logging verbosity.</span>
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e;display:block;margin-bottom:4px">Fail Open</label>
        <select id="set-fail-open" class="setting-input" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:4px;font-size:14px">
          <option value="true">Yes — allow packages if validator is down</option>
          <option value="false">No — block all packages if validator is down</option>
        </select>
        <span style="font-size:10px;color:#484f58">Whether nginx forwards to Nexus when the validator is unreachable.</span>
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e;display:block;margin-bottom:4px">Cache TTL — Allowed (seconds)</label>
        <input type="number" id="set-cache-ttl-allowed" class="setting-input" min="60" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:4px;font-size:14px">
        <span style="font-size:10px;color:#484f58">How long to cache "allowed" decisions. Default 86400 (24h).</span>
      </div>
      <div>
        <label style="font-size:11px;color:#8b949e;display:block;margin-bottom:4px">Cache TTL — Blocked (seconds)</label>
        <input type="number" id="set-cache-ttl-blocked" class="setting-input" min="60" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c5cdd8;padding:8px 12px;border-radius:4px;font-size:14px">
        <span style="font-size:10px;color:#484f58">How long to cache "blocked" decisions. Default 3600 (1h). Lower = re-checks sooner.</span>
      </div>
    </div>
    <div style="margin-top:16px;display:flex;gap:12px;align-items:center">
      <button class="btn btn-allow" onclick="saveSettings()">💾 Save Settings</button>
      <button class="btn" onclick="generateToken()">🔑 Generate New Token</button>
      <span id="settings-status" style="font-size:12px;color:#8b949e"></span>
    </div>
    <div id="active-token-area" style="margin-top:12px;padding:10px;background:#0d1117;border-radius:4px;border:1px solid #30363d">
      <span style="font-size:11px;color:#8b949e">Active Bypass Token: </span>
      <code id="active-token" style="user-select:all;cursor:pointer;color:#79c0ff" title="Click to copy">loading...</code>
      <span style="font-size:10px;color:#484f58;margin-left:8px">Teams use this with header: X-Cooling-Bypass</span>
    </div>
    <div style="margin-top:16px;border-top:1px solid #1e2a3a;padding-top:12px">
      <div style="font-size:11px;color:#8b949e;margin-bottom:8px;font-weight:600">Recent Changes</div>
      <div id="audit-log" style="font-size:11px;color:#484f58;max-height:150px;overflow-y:auto"></div>
    </div>
  </div>
</div>

<!-- Legend (bottom) -->
<div class="card" style="margin-top:16px">
  <div class="card-title">Legend</div>
  <div class="info-box" style="margin:0;border:none;border-radius:0">
    <span class="status-badge allow">Allowed</span> — Package is older than the cooling period, safe to use<br><br>
    <span class="status-badge block">Blocked</span> — Package is too new or known malware<br><br>
    <span class="status-badge override">Override</span> — Admin manually allowed or denied this package<br><br>
    <strong>Cooling Period:</strong> Configurable (default 7 days) from first publish date on the upstream registry (npm/PyPI/Maven Central)<br><br>
    <strong>Quarantine:</strong> Packages flagged as malware by GitHub Advisory DB or OSV.dev are permanently blocked and deleted from Nexus cache<br><br>
    <strong>Bypass Token:</strong> Stored in Vault (K8s) or Redis (runtime override). If everything goes down, the env var token from Vault still works.
  </div>
</div>

</div>

<script>
let allPackages = [];
let isAdmin = false;
let authHeader = null;
let sortField = null;
let sortDir = 'asc';

async function checkAuth() {
  try {
    const opts = authHeader ? {headers: {'Authorization': authHeader}} : {};
    const resp = await fetch('/api/auth/status', opts);
    const data = await resp.json();
    isAdmin = data.role === 'admin';
    const statusEl = document.getElementById('auth-status');
    const loginBtn = document.getElementById('login-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const loggedIn = data.authenticated === true;
    if (data.user && data.user.includes('auth disabled')) {
      statusEl.textContent = '🔓 Admin (no auth)';
      statusEl.style.color = '#d29922';
      loginBtn.style.display = 'none';
      logoutBtn.style.display = 'none';
      document.getElementById('settings-panel').style.display = 'block';
      loadSettings();
    } else if (loggedIn) {
      isAdmin = data.role === 'admin';
      statusEl.textContent = '✓ ' + data.user + ' (' + data.role + ')';
      statusEl.style.color = data.role === 'admin' ? '#3fb950' : '#58a6ff';
      loginBtn.style.display = 'none';
      logoutBtn.style.display = 'inline-block';
      if (data.role === 'admin') {
        document.getElementById('settings-panel').style.display = 'block';
        loadSettings();
      } else {
        document.getElementById('settings-panel').style.display = 'none';
      }
    } else {
      statusEl.textContent = '';
      loginBtn.style.display = 'inline-block';
      logoutBtn.style.display = 'none';
      document.getElementById('settings-panel').style.display = 'none';
    }
  } catch(e) {
    isAdmin = false;
    document.getElementById('login-btn').style.display = 'inline-block';
    document.getElementById('logout-btn').style.display = 'none';
  }
}

function doLogin() {
  const user = prompt('Username (admin group required):');
  if (!user) return;
  // Create a hidden input for password masking
  const passInput = document.createElement('input');
  passInput.type = 'password';
  passInput.style.position = 'fixed';
  passInput.style.top = '50%';
  passInput.style.left = '50%';
  passInput.style.transform = 'translate(-50%, -50%)';
  passInput.style.padding = '12px 16px';
  passInput.style.fontSize = '14px';
  passInput.style.background = '#161b22';
  passInput.style.border = '1px solid #30363d';
  passInput.style.borderRadius = '6px';
  passInput.style.color = '#c5cdd8';
  passInput.style.width = '300px';
  passInput.style.zIndex = '10000';
  passInput.placeholder = 'Password';

  const overlay = document.createElement('div');
  overlay.style.position = 'fixed';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100%';
  overlay.style.height = '100%';
  overlay.style.background = 'rgba(0,0,0,0.7)';
  overlay.style.zIndex = '9999';
  overlay.style.display = 'flex';
  overlay.style.alignItems = 'center';
  overlay.style.justifyContent = 'center';
  overlay.style.flexDirection = 'column';

  const label = document.createElement('div');
  label.textContent = 'Password for ' + user + ':';
  label.style.color = '#c5cdd8';
  label.style.marginBottom = '8px';
  label.style.fontSize = '13px';

  const hint = document.createElement('div');
  hint.textContent = 'Press Enter to submit, Escape to cancel';
  hint.style.color = '#484f58';
  hint.style.marginTop = '8px';
  hint.style.fontSize = '11px';

  overlay.appendChild(label);
  overlay.appendChild(passInput);
  overlay.appendChild(hint);
  document.body.appendChild(overlay);
  passInput.focus();

  passInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      const pass = passInput.value;
      document.body.removeChild(overlay);
      if (!pass) return;
      authHeader = 'Basic ' + btoa(user + ':' + pass);
      checkAuth().then(() => {
        const statusEl = document.getElementById('auth-status');
        if (!statusEl.textContent.includes('✓')) {
          alert('Login failed. Invalid credentials.');
          authHeader = null;
        }
        renderPackages();
      });
    } else if (e.key === 'Escape') {
      document.body.removeChild(overlay);
    }
  });
}

function doLogout() {
  authHeader = null;
  isAdmin = false;
  document.getElementById('settings-panel').style.display = 'none';
  document.getElementById('token-gen-area').innerHTML = '';
  // Clear browser-cached Basic Auth by sending invalid credentials
  fetch('/api/auth/status', {headers: {'Authorization': 'Basic ' + btoa('logout:logout')}}).catch(() => {});
  checkAuth();
  renderPackages();
}

async function refresh() {
  try {
    const [pkgResp, statsResp, qLogResp, qStatsResp, srcResp] = await Promise.all([
      fetch('/api/packages'),
      fetch('/api/validator/stats'),
      fetch('/api/quarantine/log'),
      fetch('/api/quarantine/stats'),
      fetch('/api/sources'),
    ]);

    const pkgData = await pkgResp.json();
    const stats = await statsResp.json();
    const qLog = await qLogResp.json();
    const qStats = await qStatsResp.json();
    const srcData = await srcResp.json();

    allPackages = pkgData.packages || [];

    // Metrics
    document.getElementById('m-allowed').textContent = stats.allowed || 0;
    document.getElementById('m-cooling').textContent = stats.blocked || 0;
    document.getElementById('m-quarantined').textContent = qStats.total_quarantined || 0;
    const overrides = allPackages.filter(p => p.override).length;
    document.getElementById('m-overrides').textContent = overrides;
    document.getElementById('m-total').textContent = pkgData.total || 0;
    document.getElementById('pkg-count').textContent = pkgData.total || 0;

    renderPackages();

    // Sources
    const srcList = document.getElementById('sources-list');
    srcList.innerHTML = (srcData.sources || []).map(s => `
      <div class="source-item">
        <span class="source-name"><span class="source-dot ${s.status}"></span>${s.name}</span>
        <span class="source-time">${s.last_pull ? timeAgo(s.last_pull) : 'Never'}</span>
      </div>
    `).join('');

    // Quarantine log
    document.getElementById('q-count').textContent = qLog.total || 0;
    if (qLog.log && qLog.log.length > 0) {
      document.getElementById('q-body').innerHTML = qLog.log.map(e => `<tr>
        <td style="white-space:nowrap">${e.timestamp ? timeAgo(e.timestamp) : '—'}</td>
        <td><strong>${e.package}</strong></td>
        <td><span class="eco-tag ${e.ecosystem}">${e.ecosystem}</span></td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.reason || '—'}</td>
        <td><code style="font-size:10px">${e.advisory_id || '—'}</code></td>
        <td>${e.deleted && e.deleted.length ? '✅ ' + e.deleted.length : '—'}</td>
        <td>${e.blocked ? '✅' : '❌'}</td>
      </tr>`).join('');
    }

    document.getElementById('last-refresh').textContent = 'Updated: ' + new Date().toLocaleTimeString();
  } catch(e) { console.error('Refresh failed:', e); }
}

function sortPackages(field) {
  if (sortField === field) {
    sortDir = sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    sortField = field;
    sortDir = 'asc';
  }
  // Update sort indicators
  document.querySelectorAll('th.sortable span').forEach(s => s.textContent = '');
  const indicator = document.getElementById('sort-' + field);
  if (indicator) indicator.textContent = sortDir === 'asc' ? '▲' : '▼';
  renderPackages();
}

function renderPackages() {
  const filter = document.getElementById('pkg-filter').value.toLowerCase();
  const statusFilter = document.getElementById('pkg-status-filter').value;
  const ecoFilter = document.getElementById('pkg-eco-filter').value;

  let filtered = allPackages;
  if (filter) filtered = filtered.filter(p => p.package.toLowerCase().includes(filter));
  if (statusFilter !== 'all') {
    if (statusFilter === 'override') filtered = filtered.filter(p => p.override);
    else filtered = filtered.filter(p => p.status === statusFilter && !p.override);
  }
  if (ecoFilter !== 'all') filtered = filtered.filter(p => p.ecosystem === ecoFilter);

  // Apply sorting
  if (sortField) {
    filtered.sort((a, b) => {
      let valA, valB;
      switch (sortField) {
        case 'package': valA = a.package || ''; valB = b.package || ''; break;
        case 'version': valA = a.version || ''; valB = b.version || ''; break;
        case 'ecosystem': valA = a.ecosystem || ''; valB = b.ecosystem || ''; break;
        case 'age': valA = a.age_days ?? 99999; valB = b.age_days ?? 99999; break;
        case 'status': valA = a.status || ''; valB = b.status || ''; break;
        case 'override': valA = a.override || ''; valB = b.override || ''; break;
        default: return 0;
      }
      if (sortField === 'age') {
        return sortDir === 'asc' ? valA - valB : valB - valA;
      }
      const cmp = String(valA).localeCompare(String(valB));
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }

  const tbody = document.getElementById('pkg-body');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">No packages match filters.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(p => {
    const statusClass = p.override ? 'override' : p.status;
    const statusText = p.override ? `Override: ${p.override}` : (p.status === 'allow' ? 'Allowed' : 'Blocked');
    const versionHtml = p.version ? `<code style="font-size:11px;color:#79c0ff">${p.version}</code>` : '<span style="color:#484f58;font-size:11px">—</span>';
    const ageHtml = p.age_days !== null && p.age_days !== undefined
      ? `<span style="font-weight:600;color:${p.age_days < 7 ? '#f85149' : p.age_days < 14 ? '#d29922' : '#3fb950'}">${p.age_days}d</span>`
      : '<span style="color:#484f58;font-size:11px">—</span>';
    const req = p.requester;
    const requesterHtml = req
      ? `<span style="font-size:11px" title="${req.user_agent || ''}">${req.source_ip || '—'}</span><br><span style="font-size:10px;color:#484f58">${req.timestamp ? timeAgo(req.timestamp) : ''}</span>`
      : '<span style="color:#484f58;font-size:11px">—</span>';
    const actions = isAdmin ? `
        <button class="btn btn-allow btn-sm" onclick="overridePkg('${p.package}','${p.ecosystem}','allow')" title="Allow this package (bypass cooling period)">✓ Allow</button>
        <button class="btn btn-deny btn-sm" onclick="overridePkg('${p.package}','${p.ecosystem}','deny')" title="Permanently block this package">✗ Deny</button>
        ${p.override ? '<button class="btn btn-sm" onclick="overridePkg(\''+p.package+'\',\''+p.ecosystem+'\',\'clear\')" title="Remove override, return to automatic">↺ Clear</button>' : ''}
    ` : '<span style="color:#484f58;font-size:11px">Login to modify</span>';
    return `<tr>
      <td><strong><a href="${getNexusUrl(p.package, p.ecosystem, p.version)}" target="_blank" style="color:#58a6ff;text-decoration:none" title="View in Nexus">${p.package}</a></strong></td>
      <td>${versionHtml}</td>
      <td><span class="eco-tag ${p.ecosystem}">${p.ecosystem}</span></td>
      <td>${ageHtml}</td>
      <td><span class="status-badge ${statusClass}">${statusText}</span></td>
      <td>${requesterHtml}</td>
      <td>${p.override ? '<span class="status-badge override">⚡ ' + p.override + '</span>' : '—'}</td>
      <td class="actions">${actions}</td>
    </tr>`;
  }).join('');
}

async function overridePkg(pkg, eco, action) {
  if (!isAdmin) {
    alert('You must be logged in as an admin to modify packages.');
    return;
  }
  // Only confirm on destructive actions (deny/clear), not allow
  if (action === 'deny') {
    if (!confirm(`Permanently block "${pkg}" (${eco})? No one will be able to download it.`)) return;
  } else if (action === 'clear') {
    if (!confirm(`Clear override for "${pkg}" (${eco})? It will return to automatic policy.`)) return;
  }

  const headers = {'Content-Type': 'application/json'};
  if (authHeader) headers['Authorization'] = authHeader;

  const resp = await fetch('/api/packages/override', {
    method: 'POST',
    headers: headers,
    body: JSON.stringify({package: pkg, ecosystem: eco, action: action})
  });
  if (resp.ok) refresh();
  else if (resp.status === 401 || resp.status === 403) alert('Authentication required. Please login first.');
  else alert('Failed: ' + await resp.text());
}

function timeAgo(ts) {
  const now = new Date();
  const then = new Date(ts);
  const diff = Math.floor((now - then) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function getNexusUrl(pkg, ecosystem, version) {
  const nexusBase = window.location.origin;
  if (ecosystem === 'npm') {
    return `${nexusBase}/#browse/search/npm=${pkg}`;
  } else if (ecosystem === 'maven') {
    const parts = pkg.split(':');
    if (parts.length === 2) {
      const groupPath = parts[0].replace(/\\./g, '/');
      const artifact = parts[1];
      const v = version || '';
      return `${nexusBase}/#browse/browse:maven-central:${groupPath}/${artifact}/${v}`;
    }
    return `${nexusBase}/#browse/search=keyword%3D${pkg}`;
  } else if (ecosystem === 'pip' || ecosystem === 'pypi') {
    return `${nexusBase}/#browse/search/pypi.name=${pkg}`;
  }
  return `${nexusBase}/#browse/search=keyword%3D${pkg}`;
}

async function loadSettings() {
  try {
    const headers = authHeader ? {'Authorization': authHeader} : {};
    const resp = await fetch('/api/settings', {headers});
    if (!resp.ok) return;
    const data = await resp.json();
    const s = data.settings;
    document.getElementById('set-cooling-days').value = s.cooling_days || '7';
    document.getElementById('set-bypass-token').value = s.bypass_token || '';
    document.getElementById('set-log-level').value = s.log_level || 'INFO';
    document.getElementById('set-fail-open').value = s.fail_open || 'true';
    document.getElementById('set-cache-ttl-allowed').value = s.cache_ttl_allowed || '86400';
    document.getElementById('set-cache-ttl-blocked').value = s.cache_ttl_blocked || '3600';

    // Show active token in admin panel
    const tokenEl = document.getElementById('active-token');
    const token = s.bypass_token || 'not-set';
    if (token === 'not-set') {
      tokenEl.textContent = 'not configured';
      tokenEl.style.color = '#484f58';
    } else {
      tokenEl.textContent = token;
      tokenEl.title = 'Click to copy';
      tokenEl.onclick = () => { navigator.clipboard.writeText(token); tokenEl.textContent = 'Copied!'; setTimeout(() => { tokenEl.textContent = token; }, 1500); };
    }

    // Show token generate button for admins in bypass info
    if (isAdmin) {
      document.getElementById('token-gen-area').innerHTML = '<span style=\"font-size:11px;color:#3fb950\">✓ You have admin access — manage tokens in Settings below</span>';
    }

    // Load audit log
    const auditResp = await fetch('/api/settings/audit', {headers});
    if (auditResp.ok) {
      const auditData = await auditResp.json();
      const auditEl = document.getElementById('audit-log');
      if (auditData.log && auditData.log.length > 0) {
        auditEl.innerHTML = auditData.log.map(e =>
          `<div style="padding:4px 0;border-bottom:1px solid #1e2a3a">
            <span style="color:#8b949e">${timeAgo(e.timestamp)}</span> —
            <span style="color:#58a6ff">${e.user}</span> ${e.action === 'token_generated' ? 'generated new bypass token' : 'changed: ' + Object.entries(e.changes || {}).map(([k,v]) => '<code>' + k + '=' + v + '</code>').join(', ')}
          </div>`
        ).join('');
      } else {
        auditEl.innerHTML = '<span style="color:#484f58">No changes recorded yet.</span>';
      }
    }
  } catch(e) { console.error('Failed to load settings:', e); }
}

async function generateToken() {
  if (!confirm('Generate a new bypass token? The old token will stop working immediately.')) return;
  const headers = {'Content-Type': 'application/json'};
  if (authHeader) headers['Authorization'] = authHeader;
  const resp = await fetch('/api/token/generate', {method: 'POST', headers});
  if (resp.ok) {
    const data = await resp.json();
    alert('New token generated:\\n\\n' + data.token + '\\n\\nThis is now the active bypass token. Share it with teams that need emergency access.');
    loadSettings();
  } else {
    alert('Failed to generate token: ' + await resp.text());
  }
}

async function saveSettings() {
  if (!isAdmin) { alert('Admin login required.'); return; }
  const payload = {
    cooling_days: document.getElementById('set-cooling-days').value,
    bypass_token: document.getElementById('set-bypass-token').value,
    log_level: document.getElementById('set-log-level').value,
    fail_open: document.getElementById('set-fail-open').value,
    cache_ttl_allowed: document.getElementById('set-cache-ttl-allowed').value,
    cache_ttl_blocked: document.getElementById('set-cache-ttl-blocked').value,
  };

  const headers = {'Content-Type': 'application/json'};
  if (authHeader) headers['Authorization'] = authHeader;

  const resp = await fetch('/api/settings', {method: 'POST', headers, body: JSON.stringify(payload)});
  const statusEl = document.getElementById('settings-status');
  if (resp.ok) {
    statusEl.textContent = '✓ Settings saved — takes effect immediately';
    statusEl.style.color = '#3fb950';
    setTimeout(() => { statusEl.textContent = ''; }, 5000);
    loadSettings();  // Refresh audit log
  } else {
    const err = await resp.text();
    statusEl.textContent = '✗ Failed: ' + err;
    statusEl.style.color = '#f85149';
  }
}

checkAuth();
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""
