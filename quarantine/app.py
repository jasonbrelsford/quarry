"""
Nexus Quarantine Webhook — Automatic Malware Removal

Listens for security advisory webhooks (GitHub, OSV.dev) and automatically:
1. Deletes affected artifacts from Nexus proxy caches
2. Blocks re-download via Nexus routing rules
3. Logs all actions to Redis for dashboard visibility
4. Polls advisory sources every hour for new malware

Endpoints:
  POST /webhook/github    — GitHub Advisory webhook
  POST /webhook/osv       — OSV.dev webhook (or manual trigger)
  POST /quarantine        — Manual quarantine (package name + ecosystem)
  GET  /quarantine/log    — Recent quarantine actions (for dashboard)
  GET  /health            — Health check
  POST /poll              — Manually trigger a poll of all advisory sources
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
import redis
from fastapi import FastAPI, Request, Response, HTTPException

# ── Config ────────────────────────────────────────────────────────────────

NEXUS_URL = os.environ.get("NEXUS_URL", "https://nexus.example.com")
NEXUS_USER = os.environ.get("NEXUS_USER", "")
NEXUS_PASSWORD = os.environ.get("NEXUS_PASSWORD", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Max quarantine log entries to keep
MAX_LOG_ENTRIES = 5000

# Nexus routing rule name for blocking
ROUTING_RULE_NAME = "block_malware"

# Ecosystem → Nexus repo mapping
ECOSYSTEM_REPOS = {
    "npm": ["npm-central"],
    "pip": ["pypi-proxy"],
    "maven": ["maven-public-central", "maven-public-sonatype"],
}

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "3600"))  # 1 hour
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")  # Optional, increases rate limit

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("quarantine")


# ── Background polling task ───────────────────────────────────────────────

async def poll_advisory_sources():
    """Background task that polls GitHub Advisory DB and OSV.dev for new malware every hour."""
    while True:
        try:
            await _poll_github_advisories()
            await _poll_osv_dev()
        except Exception as e:
            log.error(f"Poll failed: {e}")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def _poll_github_advisories():
    """Fetch recent malware advisories from GitHub and quarantine any new ones."""
    log.info("Polling GitHub Advisory DB for new malware...")
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    ecosystems = {"npm": "npm", "pip": "pip", "maven": "maven"}

    for gh_eco, our_eco in ecosystems.items():
        try:
            page = 1
            total_checked = 0
            total_new = 0
            async with httpx.AsyncClient(timeout=30) as client:
                while True:
                    resp = await client.get(
                        "https://api.github.com/advisories",
                        params={"type": "malware", "ecosystem": gh_eco, "per_page": 100, "page": page},
                        headers=headers,
                    )
                    if resp.status_code != 200:
                        log.warning(f"GitHub API returned {resp.status_code} for {gh_eco} (page {page})")
                        break

                    advisories = resp.json()
                    if not advisories:
                        break  # No more pages

                    for adv in advisories:
                        ghsa_id = adv.get("ghsa_id", "")
                        summary = adv.get("summary", "")

                        for vuln in adv.get("vulnerabilities", []):
                            pkg = vuln.get("package", {})
                            name = pkg.get("name", "")
                            if not name:
                                continue

                            total_checked += 1

                            # Check if already quarantined
                            if cache:
                                cache_key = f"cooling:{our_eco}:{name}"
                                existing = cache.get(cache_key)
                                if existing == "block":
                                    continue  # Already handled

                            # Quarantine it
                            quarantine_package(name, our_eco, f"Malware: {summary[:80]}", ghsa_id)
                            total_new += 1

                    # If we got fewer than 100, we've reached the last page
                    if len(advisories) < 100:
                        break
                    page += 1

                # Update source timestamp
                if cache:
                    cache.set(f"source:github:last_pull", datetime.now(timezone.utc).isoformat())
                    cache.set(f"source:{our_eco}:last_pull", datetime.now(timezone.utc).isoformat())

                log.info(f"Polled {gh_eco}: {total_checked} packages checked across {page} pages, {total_new} new quarantines")

        except Exception as e:
            log.warning(f"Poll failed for {gh_eco}: {e}")


async def _poll_osv_dev():
    """Fetch recent malware entries from OSV.dev for each ecosystem.
    
    Uses the OSV.dev vuln API to check for recent MAL- entries.
    Since OSV doesn't have a simple 'list recent malware' endpoint,
    we query a range of recent MAL IDs (they're sequential).
    """
    log.info("Polling OSV.dev for new malware...")

    osv_ecosystems = {"npm": "npm", "PyPI": "pip", "Maven": "maven"}

    # Get the latest MAL ID we've seen (or start from a recent one)
    last_mal_id = int(cache.get("osv:last_mal_id") or "8000") if cache else 8000

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            quarantined_count = 0
            checked = 0

            # Check the next 20 MAL IDs after our last known
            for i in range(last_mal_id, last_mal_id + 20):
                mal_id = f"MAL-2026-{i}"
                resp = await client.get(f"https://api.osv.dev/v1/vulns/{mal_id}")

                if resp.status_code == 404:
                    continue  # Doesn't exist yet
                if resp.status_code != 200:
                    continue

                checked += 1
                detail = resp.json()
                summary = detail.get("summary", "")

                for affected in detail.get("affected", []):
                    pkg = affected.get("package", {})
                    name = pkg.get("name", "")
                    eco = pkg.get("ecosystem", "")

                    if not name or eco not in osv_ecosystems:
                        continue

                    our_eco = osv_ecosystems[eco]

                    # Check if already quarantined
                    if cache:
                        cache_key = f"cooling:{our_eco}:{name}"
                        if cache.get(cache_key) == "block":
                            continue

                    quarantine_package(name, our_eco, f"Malware: {summary[:80]}", mal_id)
                    quarantined_count += 1

                # Update high water mark
                if cache:
                    cache.set("osv:last_mal_id", str(i))

            log.info(f"OSV.dev: checked {checked} MAL entries, quarantined {quarantined_count} new")

    except Exception as e:
        log.warning(f"OSV.dev poll failed: {e}")

    # Update all OSV source timestamps
    if cache:
        now = datetime.now(timezone.utc).isoformat()
        for our_eco in osv_ecosystems.values():
            cache.set(f"source:osv:{our_eco}:last_pull", now)


@asynccontextmanager
async def lifespan(app):
    """Start background polling on app startup."""
    task = asyncio.create_task(poll_advisory_sources())
    log.info(f"Background advisory polling started (interval: {POLL_INTERVAL_SECONDS}s)")
    yield
    task.cancel()


app = FastAPI(title="Nexus Quarantine Webhook", lifespan=lifespan)

# ── Redis ─────────────────────────────────────────────────────────────────

try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    log.info(f"Connected to Redis at {REDIS_URL}")
except Exception:
    log.warning("Redis unavailable — quarantine log will not persist")
    cache = None


# ── Nexus API helpers ─────────────────────────────────────────────────────

def _nexus_auth():
    if NEXUS_USER and NEXUS_PASSWORD:
        return httpx.BasicAuth(NEXUS_USER, NEXUS_PASSWORD)
    return None


def search_nexus(repo: str, package_name: str) -> list:
    """Search Nexus for components matching a package name."""
    url = f"{NEXUS_URL}/service/rest/v1/search"
    params = {"repository": repo, "name": package_name}
    try:
        resp = httpx.get(url, params=params, auth=_nexus_auth(), verify=False, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("items", [])
    except httpx.RequestError as e:
        log.error(f"Nexus search failed: {e}")
    return []


def delete_component(component_id: str) -> bool:
    """Delete a component from Nexus by ID."""
    url = f"{NEXUS_URL}/service/rest/v1/components/{component_id}"
    try:
        resp = httpx.delete(url, auth=_nexus_auth(), verify=False, timeout=30)
        return resp.status_code == 204
    except httpx.RequestError as e:
        log.error(f"Nexus delete failed: {e}")
        return False


def update_routing_rule(matchers: list) -> bool:
    """Add matchers to the block-malware routing rule."""
    auth = _nexus_auth()
    if not auth:
        return False

    # Get existing rule
    url = f"{NEXUS_URL}/service/rest/v1/routing-rules/{ROUTING_RULE_NAME}"
    try:
        resp = httpx.get(url, auth=auth, verify=False, timeout=30)
        if resp.status_code == 200:
            existing = resp.json()
            all_matchers = list(set(existing.get("matchers", []) + matchers))
            payload = {
                "name": ROUTING_RULE_NAME,
                "description": "Auto-managed by quarantine webhook. Blocks known malware.",
                "mode": "BLOCK",
                "matchers": all_matchers,
            }
            resp2 = httpx.put(url, auth=auth, json=payload, verify=False, timeout=30)
            success = resp2.status_code in (200, 204)
        else:
            # Create new rule
            payload = {
                "name": ROUTING_RULE_NAME,
                "description": "Auto-managed by quarantine webhook. Blocks known malware.",
                "mode": "BLOCK",
                "matchers": matchers,
            }
            create_url = f"{NEXUS_URL}/service/rest/v1/routing-rules"
            resp2 = httpx.post(create_url, auth=auth, json=payload, verify=False, timeout=30)
            success = resp2.status_code in (200, 201, 204)

        # Auto-assign the rule to all proxy repos if successful
        if success:
            _assign_routing_rule_to_proxy_repos(auth)
        return success

    except httpx.RequestError as e:
        log.error(f"Routing rule update failed: {e}")
        return False


def _assign_routing_rule_to_proxy_repos(auth):
    """Assign the block_malware routing rule to all known proxy repos."""
    # Discover proxy repos from Nexus
    try:
        resp = httpx.get(f"{NEXUS_URL}/service/rest/v1/repositories", auth=auth, verify=False, timeout=30)
        if resp.status_code != 200:
            return

        repos = resp.json()
        proxy_repos = [r for r in repos if r.get("type") == "proxy"]

        for repo in proxy_repos:
            name = repo["name"]
            fmt = repo["format"]
            # Map Nexus format names to API path segments
            fmt_path = fmt  # e.g., "maven2" → "maven", "nuget" → "nuget"
            if fmt == "maven2":
                fmt_path = "maven"

            # Get full config
            config_url = f"{NEXUS_URL}/service/rest/v1/repositories/{fmt_path}/proxy/{name}"
            cfg_resp = httpx.get(config_url, auth=auth, verify=False, timeout=30)
            if cfg_resp.status_code != 200:
                continue

            config = cfg_resp.json()
            if config.get("routingRuleName") == ROUTING_RULE_NAME:
                continue  # Already assigned

            # Assign the rule
            config["routingRuleName"] = ROUTING_RULE_NAME
            config.pop("url", None)
            config.pop("format", None)
            config.pop("type", None)

            put_resp = httpx.put(config_url, auth=auth, json=config, verify=False, timeout=30)
            if put_resp.status_code in (200, 204):
                log.info(f"Assigned routing rule to {name}")
            else:
                log.warning(f"Failed to assign routing rule to {name}: {put_resp.status_code}")

    except httpx.RequestError as e:
        log.warning(f"Failed to auto-assign routing rules: {e}")
        return False


def package_to_matcher(package_name: str, ecosystem: str) -> str:
    """Convert package name to a Nexus routing rule regex matcher."""
    escaped = package_name.replace(".", "\\.").replace("-", "\\-")

    if ecosystem == "npm":
        return f"^/{escaped}(/.*)?$"
    elif ecosystem == "maven":
        parts = package_name.split(":")
        if len(parts) == 2:
            group_path = parts[0].replace(".", "/").replace("-", "\\-")
            artifact = parts[1].replace(".", "\\.").replace("-", "\\-")
            return f"^/{group_path}/{artifact}/.*$"
        return f"^/.*/{escaped}/.*$"
    elif ecosystem in ("pip", "pypi"):
        normalized = escaped.replace("_", "[-_]").replace("\\-", "[-_]")
        return f"^/(simple|packages)/{normalized}(/.*)?$"

    return f"^/.*{escaped}.*$"


# ── Quarantine logic ──────────────────────────────────────────────────────

def quarantine_package(package_name: str, ecosystem: str, reason: str, advisory_id: str = "") -> dict:
    """Remove a package from Nexus and block re-download.

    Returns a summary of actions taken.
    """
    result = {
        "package": package_name,
        "ecosystem": ecosystem,
        "reason": reason,
        "advisory_id": advisory_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "deleted": [],
        "blocked": False,
        "errors": [],
    }

    repos = ECOSYSTEM_REPOS.get(ecosystem, [])
    if not repos:
        result["errors"].append(f"Unknown ecosystem: {ecosystem}")
        _log_action(result)
        return result

    # 1. Search and delete from Nexus
    for repo in repos:
        components = search_nexus(repo, package_name)
        for comp in components:
            comp_id = comp.get("id", "")
            version = comp.get("version", "unknown")
            if delete_component(comp_id):
                result["deleted"].append(f"{package_name}@{version} from {repo}")
                log.warning(f"DELETED: {package_name}@{version} from {repo} ({reason})")
            else:
                result["errors"].append(f"Failed to delete {package_name}@{version} from {repo}")

    # 2. Block re-download via routing rule
    matcher = package_to_matcher(package_name, ecosystem)
    if update_routing_rule([matcher]):
        result["blocked"] = True
        log.info(f"BLOCKED: {package_name} ({ecosystem}) via routing rule")
    else:
        result["errors"].append("Failed to update routing rule")

    # 3. Invalidate cooling proxy cache (mark as blocked)
    if cache:
        cache_key = f"cooling:{ecosystem}:{package_name}"
        cache.setex(cache_key, 86400 * 30, "block")  # Block for 30 days

    _log_action(result)
    return result


def _log_action(result: dict):
    """Persist quarantine action to Redis list for dashboard."""
    if not cache:
        return
    cache.lpush("quarantine:log", json.dumps(result))
    cache.ltrim("quarantine:log", 0, MAX_LOG_ENTRIES - 1)

    # Update source timestamps for dashboard
    now = datetime.now(timezone.utc).isoformat()
    advisory_id = result.get("advisory_id", "")
    if advisory_id.startswith("GHSA"):
        cache.set("source:github:last_pull", now)
    elif advisory_id.startswith("MAL"):
        ecosystem = result.get("ecosystem", "")
        cache.set(f"source:osv:{ecosystem}:last_pull", now)

    # Always update the ecosystem registry source
    ecosystem = result.get("ecosystem", "")
    eco_map = {"npm": "source:npm:last_pull", "pip": "source:pypi:last_pull", "maven": "source:maven:last_pull"}
    if ecosystem in eco_map:
        cache.set(eco_map[ecosystem], now)


# ── Webhook signature verification ───────────────────────────────────────

def verify_github_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not GITHUB_WEBHOOK_SECRET:
        return True  # No secret configured, skip verification
    expected = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Endpoints ─────────────────────────────────────────────────────────────

@app.post("/webhook/github")
async def github_webhook(request: Request):
    """Handle GitHub Security Advisory webhooks.

    GitHub sends these when new advisories are published.
    We filter for type=malware and quarantine affected packages.
    """
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_github_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = json.loads(body)
    action = payload.get("action", "")
    advisory = payload.get("security_advisory", {})

    # Only act on published/updated malware advisories
    if action not in ("published", "updated"):
        return {"status": "ignored", "reason": f"action={action}"}

    # Check if it's malware type
    advisory_type = advisory.get("type", "")
    if advisory_type != "malware":
        return {"status": "ignored", "reason": f"type={advisory_type}"}

    ghsa_id = advisory.get("ghsa_id", "")
    summary = advisory.get("summary", "")
    results = []

    for vuln in advisory.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "").lower()

        if not name:
            continue

        # Normalize ecosystem names
        if ecosystem == "pypi":
            ecosystem = "pip"

        result = quarantine_package(
            package_name=name,
            ecosystem=ecosystem,
            reason=f"Malware: {summary[:100]}",
            advisory_id=ghsa_id,
        )
        results.append(result)

    return {
        "status": "processed",
        "advisory": ghsa_id,
        "packages_quarantined": len(results),
        "results": results,
    }


@app.post("/webhook/osv")
async def osv_webhook(request: Request):
    """Handle OSV.dev notifications or manual triggers.

    Accepts a JSON body with: {"id": "MAL-...", "package": "...", "ecosystem": "..."}
    """
    payload = await request.json()

    name = payload.get("package", "")
    ecosystem = payload.get("ecosystem", "").lower()
    osv_id = payload.get("id", "")
    summary = payload.get("summary", "Malware detected via OSV.dev")

    if not name or not ecosystem:
        raise HTTPException(status_code=400, detail="package and ecosystem required")

    if ecosystem == "pypi":
        ecosystem = "pip"

    result = quarantine_package(
        package_name=name,
        ecosystem=ecosystem,
        reason=summary[:100],
        advisory_id=osv_id,
    )

    return {"status": "processed", "result": result}


@app.post("/quarantine")
async def manual_quarantine(request: Request):
    """Manually quarantine a package.

    Body: {"package": "evil-pkg", "ecosystem": "npm", "reason": "..."}
    """
    payload = await request.json()

    name = payload.get("package", "")
    ecosystem = payload.get("ecosystem", "").lower()
    reason = payload.get("reason", "Manual quarantine")

    if not name or not ecosystem:
        raise HTTPException(status_code=400, detail="package and ecosystem required")

    if ecosystem == "pypi":
        ecosystem = "pip"

    result = quarantine_package(
        package_name=name,
        ecosystem=ecosystem,
        reason=reason,
        advisory_id="manual",
    )

    return {"status": "processed", "result": result}


@app.get("/quarantine/log")
async def quarantine_log(limit: int = 50):
    """Return recent quarantine actions for the dashboard."""
    if not cache:
        return {"log": [], "error": "Redis unavailable"}

    entries = cache.lrange("quarantine:log", 0, limit - 1)
    return {
        "log": [json.loads(e) for e in entries],
        "total": cache.llen("quarantine:log"),
    }


@app.get("/quarantine/stats")
async def quarantine_stats():
    """Aggregate stats for the dashboard."""
    if not cache:
        return {"error": "Redis unavailable"}

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


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "nexus_url": NEXUS_URL,
        "nexus_user": NEXUS_USER or "not configured",
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "github_token_configured": bool(GITHUB_TOKEN),
        "github_webhook_secret_configured": bool(GITHUB_WEBHOOK_SECRET),
        "redis_connected": cache is not None,
    }


@app.post("/poll")
async def manual_poll():
    """Manually trigger a poll of all advisory sources."""
    await _poll_github_advisories()
    await _poll_osv_dev()
    return {"status": "polled", "timestamp": datetime.now(timezone.utc).isoformat()}
