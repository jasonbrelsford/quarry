"""
Quarry — Validation Service

Checks package publish dates against upstream registries.
Returns 200 (allow) or 403 (too new) for nginx auth_request.

Override rules are loaded from a YAML file (rules.yaml) which takes
precedence over the hold period check. This file persists across
Redis restarts and pod migrations.
"""
import os
import re
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import redis
import yaml
from fastapi import FastAPI, Request, Response

# ── Config ────────────────────────────────────────────────────────────────

COOLING_DAYS = int(os.environ.get("COOLING_DAYS", "7"))
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
BYPASS_HEADER = os.environ.get("BYPASS_HEADER", "X-Cooling-Bypass")
BYPASS_TOKEN = os.environ.get("BYPASS_TOKEN", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
RULES_FILE = os.environ.get("RULES_FILE", "/app/rules.yaml")

# Cache TTLs
CACHE_TTL_BLOCKED = 3600       # 1h for "too new" (re-check frequently)
CACHE_TTL_ALLOWED = 86400      # 24h for "allowed" (stable, won't change)
CACHE_TTL_ERROR = 300          # 5min for upstream errors (retry soon)

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("quarry")

app = FastAPI(title="Quarry Validator")


# ── Redis connection ──────────────────────────────────────────────────────

try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    log.info(f"Connected to Redis at {REDIS_URL}")
except Exception:
    log.warning("Redis unavailable — running without cache (every request hits upstream)")
    cache = None


# ── Rules File Loading ─────────────────────────────────────────────────────

class RulesEngine:
    """Loads and checks package override rules from a YAML file.

    Rules take precedence over the hold period check.
    The file is reloaded automatically when modified (checked every 30s).
    """

    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self._allow_rules: list[dict] = []
        self._block_rules: list[dict] = []
        self._last_mtime: float = 0
        self._lock = threading.Lock()
        self._load()
        # Start background reload thread
        self._reload_thread = threading.Thread(target=self._watch, daemon=True)
        self._reload_thread.start()

    def _load(self):
        """Load rules from YAML file."""
        if not self.rules_path.exists():
            log.warning(f"Rules file not found: {self.rules_path}")
            return

        try:
            mtime = self.rules_path.stat().st_mtime
            if mtime == self._last_mtime:
                return  # No change

            with open(self.rules_path) as f:
                data = yaml.safe_load(f) or {}

            overrides = data.get("overrides", {})
            with self._lock:
                self._allow_rules = overrides.get("allow", []) or []
                self._block_rules = overrides.get("block", []) or []
                self._last_mtime = mtime

            log.info(
                f"Loaded rules: {len(self._allow_rules)} allow, "
                f"{len(self._block_rules)} block overrides"
            )
        except Exception as e:
            log.error(f"Failed to load rules file: {e}")

    def _watch(self):
        """Background thread that reloads rules when the file changes."""
        import time
        while True:
            time.sleep(30)
            try:
                self._load()
            except Exception:
                pass

    def check(self, ecosystem: str, package: str, version: str = None) -> str | None:
        """Check if a package matches any override rule.

        Returns:
            "allow" — package is explicitly allowed
            "block" — package is explicitly blocked
            None    — no override, proceed with normal hold check
        """
        with self._lock:
            # Check block rules first (block takes priority over allow)
            for rule in self._block_rules:
                if self._matches(rule, ecosystem, package, version):
                    return "block"

            # Check allow rules
            for rule in self._allow_rules:
                if self._matches(rule, ecosystem, package, version):
                    return "allow"

        return None

    def _matches(self, rule: dict, ecosystem: str, package: str, version: str = None) -> bool:
        """Check if a rule matches the given package."""
        if not rule:
            return False
        if rule.get("ecosystem", "").lower() != ecosystem.lower():
            return False
        if rule.get("package", "").lower() != package.lower():
            return False
        # If rule specifies a version, only match that version
        rule_version = rule.get("version")
        if rule_version and version and rule_version != version:
            return False
        return True

    def get_all_rules(self) -> dict:
        """Return all rules for the dashboard/stats endpoint."""
        with self._lock:
            return {
                "allow": list(self._allow_rules),
                "block": list(self._block_rules),
            }


rules = RulesEngine(RULES_FILE)


# ── Request Logging ────────────────────────────────────────────────────────

def _log_request(ecosystem: str, package: str, decision: str, request, age_days: float = None):
    """Log a package request with source IP and user-agent to Redis for dashboard."""
    if not cache:
        return
    source_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    # Extract machine/tool info from user-agent
    # Maven: "Apache-Maven/3.9.6 (Java 17.0.9; Mac OS X 14.2.1)"
    # pip: "pip/24.0 {\"ci\":null,\"cpu\":\"arm64\"...}"
    # npm: "npm/10.2.4 node/v20.10.0 darwin arm64"
    entry = json.dumps({
        "ecosystem": ecosystem,
        "package": package,
        "decision": decision,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "age_days": age_days,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    cache.lpush("request:log", entry)
    cache.ltrim("request:log", 0, 499)  # Keep last 500 requests
    # Store age_days per-package for dashboard display
    if age_days is not None:
        cache.set(f"age:{ecosystem}:{package}", str(round(age_days, 1)))
    # Also store per-package last requester
    cache.set(f"requester:{ecosystem}:{package}", json.dumps({
        "source_ip": source_ip,
        "user_agent": user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
    }))


# ── URL Parsing ───────────────────────────────────────────────────────────

# Nexus proxy repo URL patterns:
# npm:   /repository/npm-central/{package}/-/{package}-{version}.tgz
#         /repository/npm-central/@scope/{package}/-/{package}-{version}.tgz
# PyPI:  /repository/pypi-proxy/packages/{package}/{version}/{filename}
#         /repository/pypi-proxy/simple/{package}/
# Maven: /repository/maven-public-central/org/example/artifact/1.0/artifact-1.0.jar

# Repo name patterns to identify ecosystem
NPM_REPOS = re.compile(r"/repository/(npm[^/]*)/")
PYPI_REPOS = re.compile(r"/repository/([^/]*pypi[^/]*)/")
MAVEN_REPOS = re.compile(r"/repository/(maven[^/]*)/")

# Package extraction patterns
NPM_PKG_PATTERN = re.compile(
    r"/repository/[^/]+/((?:@[^/]+/)?[^/]+)(?:/-/.*)?$"
)
PYPI_PKG_PATTERN = re.compile(
    r"/repository/[^/]+/(?:simple|packages)/([^/]+)"
)
MAVEN_PKG_PATTERN = re.compile(
    r"/repository/[^/]+/(.+)/([^/]+)/([^/]+)/[^/]+$"
)


def parse_request_path(path: str) -> dict | None:
    """Extract ecosystem, package name, and version from a Nexus request path."""

    if NPM_REPOS.search(path):
        m = NPM_PKG_PATTERN.search(path)
        if m:
            return {"ecosystem": "npm", "package": m.group(1), "version": None}

    elif PYPI_REPOS.search(path):
        m = PYPI_PKG_PATTERN.search(path)
        if m:
            # Normalize PyPI package name (PEP 503)
            name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
            return {"ecosystem": "pypi", "package": name, "version": None}

    elif MAVEN_REPOS.search(path):
        m = MAVEN_PKG_PATTERN.search(path)
        if m:
            group_path = m.group(1)  # e.g., "org/apache/commons"
            artifact = m.group(2)     # e.g., "commons-lang3"
            version = m.group(3)      # e.g., "3.14.0"
            group_id = group_path.replace("/", ".")
            return {
                "ecosystem": "maven",
                "package": f"{group_id}:{artifact}",
                "version": version,
            }

    return None


# ── Upstream Registry Lookups ─────────────────────────────────────────────

async def get_npm_publish_date(package: str) -> datetime | None:
    """Get the publish date of an npm package from the registry."""
    url = f"https://registry.npmjs.org/{package}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                return None

            data = resp.json()

            # Full metadata has "time" field with per-version dates
            time_info = data.get("time", {})
            if time_info:
                # "created" = when the package was first published
                created = time_info.get("created")
                if created:
                    return datetime.fromisoformat(created.replace("Z", "+00:00"))

    except Exception as e:
        log.warning(f"npm lookup failed for {package}: {e}")
    return None


async def get_pypi_publish_date(package: str) -> datetime | None:
    """Get the publish date of a PyPI package."""
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None

            data = resp.json()
            # Get the earliest upload time across all releases
            releases = data.get("releases", {})
            earliest = None
            for version, files in releases.items():
                for f in files:
                    upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                    if upload_time:
                        try:
                            dt = datetime.fromisoformat(
                                upload_time.replace("Z", "+00:00")
                            )
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            if earliest is None or dt < earliest:
                                earliest = dt
                        except ValueError:
                            continue
            return earliest

    except Exception as e:
        log.warning(f"PyPI lookup failed for {package}: {e}")
    return None


async def get_maven_publish_date(package: str, version: str = None) -> datetime | None:
    """Get the publish date of a Maven artifact from Maven Central."""
    parts = package.split(":")
    if len(parts) != 2:
        return None
    group_id, artifact_id = parts

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Search Maven Central
            q = f'g:"{group_id}" AND a:"{artifact_id}"'
            if version:
                q += f' AND v:"{version}"'
                core = "gav"
            else:
                core = "ga"

            url = "https://search.maven.org/solrsearch/select"
            resp = await client.get(url, params={
                "q": q, "core": core, "rows": 1, "wt": "json"
            })
            if resp.status_code != 200:
                return None

            data = resp.json()
            docs = data.get("response", {}).get("docs", [])
            if docs:
                ts = docs[0].get("timestamp", 0)
                if ts:
                    return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)

    except Exception as e:
        log.warning(f"Maven lookup failed for {package}: {e}")
    return None


async def get_publish_date(ecosystem: str, package: str, version: str = None) -> datetime | None:
    """Route to the appropriate registry lookup."""
    if ecosystem == "npm":
        return await get_npm_publish_date(package)
    elif ecosystem == "pypi":
        return await get_pypi_publish_date(package)
    elif ecosystem == "maven":
        return await get_maven_publish_date(package, version)
    return None


# ── Validation Endpoint ───────────────────────────────────────────────────

@app.get("/validate")
async def validate(request: Request):
    """Called by nginx auth_request. Returns 200 (allow) or 403 (block).

    Priority order:
    1. Bypass token (emergency override)
    2. Rules file (persistent allow/block overrides)
    3. Redis cache (cached hold decisions)
    4. Upstream registry lookup (hold period check)
    """
    # Check bypass token (env var OR Redis runtime override)
    bypass_token_header = request.headers.get(BYPASS_HEADER)
    if bypass_token_header:
        # Check against env var token
        if BYPASS_TOKEN and bypass_token_header == BYPASS_TOKEN:
            return Response(status_code=200)
        # Check against Redis runtime token (set via dashboard admin)
        if cache:
            runtime_token = cache.get("settings:bypass_token")
            if runtime_token and bypass_token_header == runtime_token:
                return Response(status_code=200)

    # Get the original request path from nginx
    original_uri = request.headers.get("X-Original-URI", "")
    if not original_uri:
        # No URI to validate — allow (might be health check or non-repo request)
        return Response(status_code=200)

    # Parse the path to identify ecosystem + package
    parsed = parse_request_path(original_uri)
    if not parsed:
        # Can't identify the package — allow (might be metadata, index, etc.)
        return Response(status_code=200)

    ecosystem = parsed["ecosystem"]
    package = parsed["package"]
    version = parsed.get("version")
    # Include version in cache key so metadata lookups don't mask versioned blocks
    cache_key = f"cooling:{ecosystem}:{package}:{version or '_metadata'}"

    # Store version info for dashboard display
    if cache and version:
        cache.set(f"version:{ecosystem}:{package}", version)

    # Check rules file overrides (takes precedence over hold period)
    rule_decision = rules.check(ecosystem, package, version)
    if rule_decision == "block":
        log.warning(f"BLOCK (rule override): {ecosystem}/{package}")
        _log_request(ecosystem, package, "block_rule", request)
        return Response(
            status_code=403,
            content=f"Package '{package}' is permanently blocked by policy rule.\n"
                    f"Contact DevOps if you believe this is an error.",
            media_type="text/plain",
            headers={"X-Block-Reason": f"Package '{package}' is permanently blocked by policy rule."},
        )
    elif rule_decision == "allow":
        log.info(f"ALLOW (rule override): {ecosystem}/{package}")
        _log_request(ecosystem, package, "allow_rule", request)
        return Response(status_code=200)

    # Check manual override (from dashboard/CLI) — takes precedence over cache
    if cache:
        override = cache.get(f"override:{ecosystem}:{package}")
        if override == "allow":
            return Response(status_code=200)
        elif override == "deny":
            return Response(
                status_code=403,
                content=f"Package '{package}' has been manually sealed by an admin.",
                media_type="text/plain",
            )

    # Check cache
    if cache:
        cached = cache.get(cache_key)
        if cached == "allow":
            return Response(status_code=200)
        elif cached == "block":
            return Response(
                status_code=403,
                content=f"Package '{package}' is less than {COOLING_DAYS} days old. "
                        f"Blocked by hold period policy.",
                media_type="text/plain",
            )

    # Look up publish date from upstream registry
    publish_date = await get_publish_date(ecosystem, package, version)

    if publish_date is None:
        # Can't determine age — allow but cache briefly (might be private/internal)
        log.info(f"ALLOW (unknown age): {ecosystem}/{package}")
        if cache:
            cache.setex(cache_key, CACHE_TTL_ERROR, "allow")
        return Response(status_code=200)

    # Check age
    age = datetime.now(timezone.utc) - publish_date
    age_days = age.total_seconds() / 86400

    # Read cooling_days from Redis settings (allows runtime override from dashboard)
    effective_cooling_days = COOLING_DAYS
    if cache:
        override_days = cache.get("settings:cooling_days")
        if override_days:
            try:
                effective_cooling_days = int(override_days)
            except ValueError:
                pass

    if age_days < effective_cooling_days:
        # Too new — block
        log.warning(
            f"BLOCK: {ecosystem}/{package} is {age_days:.1f} days old "
            f"(published {publish_date.strftime('%Y-%m-%d')})"
        )
        _log_request(ecosystem, package, "block", request, age_days)
        if cache:
            cache.setex(cache_key, CACHE_TTL_BLOCKED, "block")
        block_msg = (
            f"Package '{package}' was published {age_days:.1f} days ago "
            f"({publish_date.strftime('%Y-%m-%d')}). "
            f"Minimum age is {effective_cooling_days} days."
        )
        return Response(
            status_code=403,
            content=block_msg + " Blocked by hold period policy.",
            media_type="text/plain",
            headers={"X-Block-Reason": block_msg},
        )

    # Old enough — allow
    log.info(f"ALLOW: {ecosystem}/{package} is {age_days:.0f} days old")
    _log_request(ecosystem, package, "allow", request, age_days)
    if cache:
        cache.setex(cache_key, CACHE_TTL_ALLOWED, "allow")
    return Response(status_code=200)


@app.get("/validate-internal")
async def validate_internal(request: Request):
    """Called by nginx for hosted/internal repos. Block-list only, no hold period.

    Internal packages are allowed immediately UNLESS:
    1. Explicitly blocked in rules.yaml
    2. Manually sealed via dashboard/CLI override
    """
    original_uri = request.headers.get("X-Original-URI", "")
    if not original_uri:
        return Response(status_code=200)

    parsed = parse_request_path(original_uri)
    if not parsed:
        return Response(status_code=200)

    ecosystem = parsed["ecosystem"]
    package = parsed["package"]
    version = parsed.get("version")

    # Store version info for dashboard display
    if cache and version:
        cache.set(f"version:{ecosystem}:{package}", version)

    # Check rules file overrides
    rule_decision = rules.check(ecosystem, package, version)
    if rule_decision == "block":
        log.warning(f"BLOCK (internal, rule override): {ecosystem}/{package}")
        _log_request(ecosystem, package, "block_rule_internal", request)
        return Response(
            status_code=403,
            content=f"Package '{package}' is sealed by policy rule.\n"
                    f"Contact your admin if you believe this is an error.",
            media_type="text/plain",
            headers={"X-Block-Reason": f"Package '{package}' is sealed by policy rule."},
        )

    # Check manual override (sealed via dashboard/CLI)
    if cache:
        override = cache.get(f"override:{ecosystem}:{package}")
        if override == "deny":
            log.warning(f"BLOCK (internal, manual seal): {ecosystem}/{package}")
            _log_request(ecosystem, package, "block_sealed", request)
            return Response(
                status_code=403,
                content=f"Package '{package}' has been manually sealed by an admin.\n"
                        f"Contact your admin to unseal it.",
                media_type="text/plain",
                headers={"X-Block-Reason": f"Package '{package}' has been manually sealed."},
            )

        cached = cache.get(f"cooling:{ecosystem}:{package}")
        if cached == "block":
            log.warning(f"BLOCK (internal, cached seal): {ecosystem}/{package}")
            return Response(
                status_code=403,
                content=f"Package '{package}' is blocked.",
                media_type="text/plain",
            )

    # Internal package, not sealed — allow immediately
    _log_request(ecosystem, package, "allow_internal", request)
    return Response(status_code=200)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "cooling_days": COOLING_DAYS}


@app.get("/stats")
async def stats():
    """Basic stats from cache and rules."""
    all_rules = rules.get_all_rules()
    if not cache:
        return {
            "cache": "disabled",
            "rules": {
                "allow_count": len(all_rules["allow"]),
                "block_count": len(all_rules["block"]),
            },
        }

    blocked = len(cache.keys("cooling:*"))
    return {
        "cache": "connected",
        "cooling_days": COOLING_DAYS,
        "cached_decisions": blocked,
        "rules": {
            "allow_count": len(all_rules["allow"]),
            "block_count": len(all_rules["block"]),
            "allow": all_rules["allow"],
            "block": all_rules["block"],
        },
    }


@app.get("/requests")
async def request_log(limit: int = 50):
    """Recent package requests with decision and age."""
    if not cache:
        return {"requests": [], "total": 0}
    entries = cache.lrange("request:log", 0, limit - 1)
    return {
        "requests": [json.loads(e) for e in entries],
        "total": cache.llen("request:log"),
    }


@app.get("/rules")
async def get_rules():
    """Return all active override rules."""
    return rules.get_all_rules()


# ── Test & Demo API ───────────────────────────────────────────────────────
# These endpoints let you test all proxy scenarios from Swagger UI at /docs
# without needing curl or package managers.

from fastapi import Query
from enum import Enum


class Ecosystem(str, Enum):
    npm = "npm"
    pypi = "pypi"
    maven = "maven"


@app.get("/test/lookup", tags=["Testing"])
async def test_lookup(
    package: str = Query("express", description="Package name (e.g. 'express', 'requests', 'org.apache.commons:commons-lang3')", json_schema_extra={"examples": ["express", "event-stream", "requests", "ctx", "org.apache.commons:commons-lang3"]}),
    ecosystem: Ecosystem = Query("npm", description="Package ecosystem"),
    version: str = Query(None, description="Specific version (optional, mainly for Maven)", json_schema_extra={"examples": ["4.18.2", "3.14.0", ""]}),
):
    """Look up a package's publish date from the upstream registry.

    Use this to check how old a package is before testing the proxy.
    Shows whether the package would be allowed or blocked by the hold period.
    """
    publish_date = await get_publish_date(ecosystem.value, package, version)

    effective_cooling_days = COOLING_DAYS
    if cache:
        override_days = cache.get("settings:cooling_days")
        if override_days:
            try:
                effective_cooling_days = int(override_days)
            except ValueError:
                pass

    if publish_date is None:
        return {
            "package": package,
            "ecosystem": ecosystem.value,
            "publish_date": None,
            "age_days": None,
            "decision": "allow",
            "reason": "Could not determine publish date — allowed by default",
        }

    age = datetime.now(timezone.utc) - publish_date
    age_days = age.total_seconds() / 86400
    decision = "block" if age_days < effective_cooling_days else "allow"

    return {
        "package": package,
        "ecosystem": ecosystem.value,
        "publish_date": publish_date.isoformat(),
        "age_days": round(age_days, 1),
        "cooling_days": effective_cooling_days,
        "decision": decision,
        "reason": f"{'Too new' if decision == 'block' else 'Old enough'} — {age_days:.1f} days old, threshold is {effective_cooling_days} days",
    }


@app.get("/test/simulate", tags=["Testing"])
async def test_simulate(
    request: Request,
    ecosystem: Ecosystem = Query("npm", description="Package ecosystem"),
    package: str = Query("express", description="Package name", json_schema_extra={"examples": ["express", "event-stream", "requests", "ctx", "org.apache.commons:commons-lang3"]}),
    bypass_token: str = Query(None, description="Bypass token to test (optional)", json_schema_extra={"examples": ["dev-bypass-token", "wrong-token", ""]}),
):
    """Simulate a full validation request as if it came through nginx.

    Tests the complete flow: bypass check → rules file → cache → upstream lookup.
    Returns the decision with full details about why.
    """
    # Build a fake URI like nginx would send
    if ecosystem == Ecosystem.npm:
        uri = f"/repository/npm-central/{package}/-/{package}-1.0.0.tgz"
    elif ecosystem == Ecosystem.pypi:
        uri = f"/repository/pypi-proxy/simple/{package}/"
    elif ecosystem == Ecosystem.maven:
        parts = package.split(":")
        if len(parts) == 2:
            group_path = parts[0].replace(".", "/")
            uri = f"/repository/maven-public-central/{group_path}/{parts[1]}/1.0.0/{parts[1]}-1.0.0.jar"
        else:
            uri = f"/repository/maven-public-central/{package}/1.0.0/artifact-1.0.0.jar"

    # Check bypass
    if bypass_token:
        if (BYPASS_TOKEN and bypass_token == BYPASS_TOKEN):
            return {"decision": "allow", "reason": "Bypass token matched (env var)", "uri": uri}
        if cache:
            runtime_token = cache.get("settings:bypass_token")
            if runtime_token and bypass_token == runtime_token:
                return {"decision": "allow", "reason": "Bypass token matched (runtime)", "uri": uri}
        return {"decision": "deny", "reason": "Invalid bypass token", "uri": uri}

    # Check rules
    rule_decision = rules.check(ecosystem.value, package)
    if rule_decision == "block":
        return {"decision": "block", "reason": "Permanently blocked by rules.yaml", "uri": uri, "source": "rules_file"}
    elif rule_decision == "allow":
        return {"decision": "allow", "reason": "Permanently allowed by rules.yaml", "uri": uri, "source": "rules_file"}

    # Check cache
    cache_key = f"cooling:{ecosystem.value}:{package}:{version or '_metadata'}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            return {"decision": cached, "reason": f"Cached decision: {cached}", "uri": uri, "source": "redis_cache"}

    # Lookup upstream
    publish_date = await get_publish_date(ecosystem.value, package)
    if publish_date is None:
        return {"decision": "allow", "reason": "Unknown publish date — allowed by default", "uri": uri, "source": "upstream_unknown"}

    age = datetime.now(timezone.utc) - publish_date
    age_days = age.total_seconds() / 86400

    effective_cooling_days = COOLING_DAYS
    if cache:
        override_days = cache.get("settings:cooling_days")
        if override_days:
            try:
                effective_cooling_days = int(override_days)
            except ValueError:
                pass

    if age_days < effective_cooling_days:
        return {
            "decision": "block",
            "reason": f"Published {age_days:.1f} days ago, hold period is {effective_cooling_days} days",
            "uri": uri,
            "source": "upstream_lookup",
            "publish_date": publish_date.isoformat(),
            "age_days": round(age_days, 1),
        }

    return {
        "decision": "allow",
        "reason": f"Published {age_days:.0f} days ago, past {effective_cooling_days}-day hold period",
        "uri": uri,
        "source": "upstream_lookup",
        "publish_date": publish_date.isoformat(),
        "age_days": round(age_days, 1),
    }


@app.get("/test/proxy-request", tags=["Testing"])
async def test_proxy_request(
    ecosystem: Ecosystem = Query("npm", description="Package ecosystem"),
    package: str = Query("express", description="Package name", json_schema_extra={"examples": ["express", "event-stream", "requests", "ctx", "org.apache.commons:commons-lang3"]}),
):
    """Test a request through the actual nginx proxy (localhost:8888).

    Makes a real HTTP request through the full proxy stack and returns the result.
    Requires the nginx container to be running.
    """
    if ecosystem == Ecosystem.npm:
        url = f"http://nginx:80/repository/npm-central/{package}"
    elif ecosystem == Ecosystem.pypi:
        url = f"http://nginx:80/repository/pypi-proxy/simple/{package}/"
    elif ecosystem == Ecosystem.maven:
        parts = package.split(":")
        if len(parts) == 2:
            group_path = parts[0].replace(".", "/")
            url = f"http://nginx:80/repository/maven-public-central/{group_path}/{parts[1]}/maven-metadata.xml"
        else:
            url = f"http://nginx:80/repository/maven-public-central/{package}"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            return {
                "url": url,
                "status_code": resp.status_code,
                "decision": "allow" if resp.status_code == 200 else "block",
                "body_preview": resp.text[:500] if resp.status_code != 200 else f"({len(resp.content)} bytes)",
            }
    except Exception as e:
        return {"url": url, "error": str(e)}


@app.get("/test/find-new-packages", tags=["Testing"])
async def find_new_packages():
    """Find recently published packages across all ecosystems.

    Returns packages published in the last 7 days that WOULD be blocked
    by the Quarry. Useful for finding test candidates.
    """
    results = {"maven": [], "pypi": [], "npm": []}

    # Maven — search for recent Apache artifacts
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://search.maven.org/solrsearch/select",
                params={"q": "g:org.apache*", "rows": 10, "wt": "json", "sort": "timestamp desc"},
            )
            if resp.status_code == 200:
                data = resp.json()
                now = datetime.now(timezone.utc)
                for doc in data.get("response", {}).get("docs", []):
                    ts = doc.get("timestamp", 0)
                    dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
                    age = (now - dt).days
                    if age < 7:
                        results["maven"].append({
                            "package": f"{doc.get('g')}:{doc.get('a')}",
                            "version": doc.get("latestVersion"),
                            "age_days": age,
                            "published": dt.strftime("%Y-%m-%d"),
                        })
    except Exception:
        pass

    # PyPI — RSS feed of latest updates
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get("https://pypi.org/rss/updates.xml")
            if resp.status_code == 200:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(resp.text)
                items = root.findall("./channel/item")[:10]
                for item in items:
                    title = item.find("title").text if item.find("title") is not None else ""
                    pub = item.find("pubDate").text if item.find("pubDate") is not None else ""
                    parts = title.rsplit(" ", 1)
                    name = parts[0] if parts else title
                    ver = parts[1] if len(parts) > 1 else ""
                    results["pypi"].append({
                        "package": name,
                        "version": ver,
                        "age_days": 0,
                        "published": pub,
                    })
    except Exception:
        pass

    # npm — recently updated
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://registry.npmjs.org/-/v1/search",
                params={"text": "boost-exact:false", "size": 10, "quality": "0.0", "popularity": "0.0", "maintenance": "0.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for obj in data.get("objects", []):
                    pkg = obj.get("package", {})
                    results["npm"].append({
                        "package": pkg.get("name"),
                        "version": pkg.get("version"),
                        "published": pkg.get("date", ""),
                    })
    except Exception:
        pass

    return results


@app.post("/test/clear-cache", tags=["Testing"])
async def clear_cache(
    package: str = Query(None, description="Specific package to clear (omit to clear all)", json_schema_extra={"examples": ["express", "requests", "org.apache.commons:commons-lang3"]}),
    ecosystem: Ecosystem = Query(None, description="Ecosystem of the package to clear"),
):
    """Clear cached decisions from Redis.

    Use this to re-test a package after changing settings or rules.
    Omit parameters to clear ALL cached decisions.
    """
    if not cache:
        return {"status": "error", "message": "Redis not connected"}

    if package and ecosystem:
        key = f"cooling:{ecosystem.value}:{package}"
        cache.delete(key)
        return {"status": "ok", "cleared": key}
    else:
        keys = cache.keys("cooling:*")
        if keys:
            cache.delete(*keys)
        return {"status": "ok", "cleared": len(keys), "message": "All cooling cache cleared"}

