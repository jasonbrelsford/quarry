# Quarry

Reverse proxy that sits in front of Nexus and blocks packages published less than 7 days ago.
Prevents supply chain attacks that exploit the window between package publication and malware detection.

## Test Render Deployment - takes a minute to startup
https://nexus-cooling-proxy.onrender.com

## Architecture

```
Developer (pip/npm/mvn) → nginx (auth_request) → validation service → Nexus
```

1. nginx receives the package request
2. nginx calls the validation service via auth_request
3. Validation service extracts package name + version from the URL path
4. Checks decision sources in priority order:
   1. Bypass token (emergency override via header)
   2. Rules file (`rules.yaml` — persistent allow/block overrides)
   3. Redis cache (cached hold decisions)
   4. Upstream registry lookup (npm/PyPI/Maven Central publish date)
5. If published < 7 days ago → returns 403 (nginx blocks the request)
6. If published ≥ 7 days ago → returns 200 (nginx forwards to Nexus)
7. Results are cached in Redis (1h for "too new", 24h for "allowed")

## Components

- `validator/` — Python FastAPI service that checks package publish dates
- `nginx/` — nginx config with auth_request module
- `quarantine/` — Webhook service that auto-removes known malware from Nexus (GitHub Advisory + OSV.dev webhooks, manual quarantine API)
- `dashboard/` — Security dashboard with real-time package request log (allow/block status), admin allow/deny overrides per package, quarantine log, data source status, and block/quarantine counts (polls Redis, auto-refreshes). Protected by LDAP authentication with role-based access (admin: admins, viewer: users)
- `helm/` — Helm chart for K8s deployment
- `Dockerfile.validator` — Container image for the validation service

## Request Logging

The validator logs every package request to Redis for the dashboard to consume:
- Last 500 requests stored in `request:log` (source IP, user-agent, ecosystem, package, decision, age)
- Per-package last requester stored in `requester:{ecosystem}:{package}`

This powers the dashboard's real-time request log and per-package audit trail.

## Configuration

Environment variables for the validator:

| Variable | Default | Description |
|----------|---------|-------------|
| COOLING_DAYS | 7 | Minimum age (days) before a package is allowed |
| REDIS_URL | redis://localhost:6379 | Redis for caching publish dates |
| NEXUS_UPSTREAM | http://nexus:8081 | Internal Nexus URL |
| BYPASS_HEADER | X-Cooling-Bypass | Header name for bypass token |
| BYPASS_TOKEN | (none) | Token value to skip validation (for emergencies) |
| RULES_FILE | /app/rules.yaml | Path to the rules.yaml override file |
| LOG_LEVEL | INFO | Logging verbosity |

## Package Override Rules

The `rules.yaml` file defines static allow/block overrides that take precedence over the hold period check. Changes persist across Redis restarts and pod migrations.

```yaml
overrides:
  allow:
    - package: "@myorg/internal-lib"
      ecosystem: npm
      reason: "Internal package, not on public registry"

  block:
    - package: "event-stream"
      ecosystem: npm
      reason: "Known supply chain attack"
```

| Field | Required | Description |
|-------|----------|-------------|
| package | Yes | Package name |
| ecosystem | Yes | `npm`, `pypi`, or `maven` |
| version | No | Specific version (omit to match all) |
| reason | Yes | Why this override exists |
| added_by | No | Who added it |
| added_on | No | Date added |

Actions:
- `allow` — always permit, skip hold period (useful for internal packages not on public registries)
- `block` — always deny, regardless of age (useful for known malware/protestware)

Edit via PR for audit trail.

## Bypass / Escape Hatch

For emergencies where a team needs a brand-new package immediately:
- Set the `X-Cooling-Bypass: <token>` header in their package manager config
- Or use a separate "unrestricted" Nexus repo that doesn't go through the proxy

## Quarantine Webhook

The `quarantine/` service listens for security advisory webhooks and automatically removes known malware from Nexus. It also polls advisory sources (GitHub Advisory Database, OSV.dev) every hour for new malware. After quarantining a package, it auto-assigns a `block_malware` routing rule to all Nexus proxy repositories, preventing the malware from being re-fetched from upstream.

| Endpoint | Method | Description |
|----------|--------|-------------|
| /webhook/github | POST | GitHub Security Advisory webhook (filters for type=malware) |
| /webhook/osv | POST | OSV.dev notification or manual trigger |
| /quarantine | POST | Manual quarantine: `{"package": "...", "ecosystem": "...", "reason": "..."}` |
| /quarantine/log | GET | Recent quarantine actions (for dashboard) |
| /quarantine/stats | GET | Aggregate quarantine statistics |
| /poll | POST | Manually trigger a poll of all advisory sources |
| /health | GET | Health check |

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| NEXUS_URL | https://nexus.example.com | Nexus instance to quarantine from |
| NEXUS_USER | (none) | Nexus admin credentials |
| NEXUS_PASSWORD | (none) | Nexus admin credentials |
| REDIS_URL | redis://localhost:6379 | Redis for quarantine log persistence |
| GITHUB_WEBHOOK_SECRET | (none) | HMAC secret for GitHub webhook verification |
| GITHUB_TOKEN | (none) | GitHub PAT for advisory polling (increases rate limit from 60 to 5000 req/hr) |
| POLL_INTERVAL_SECONDS | 3600 | Interval between advisory source polls (seconds) |
| LOG_LEVEL | INFO | Logging verbosity |

## Dashboard

The dashboard requires LDAP authentication by default and supports role-based access:

- **Admin** (members of `LDAP_ADMIN_GROUP`): Full access — view dashboard, modify settings, generate tokens, override packages
- **Viewer** (members of `LDAP_USER_GROUP`): Read-only access — view dashboard and request log, no modifications

The admin panel displays the active bypass token (truncated) with click-to-copy, and provides a "Generate New Token" button that rotates the token immediately. Token generation is audit-logged.

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| REDIS_URL | redis://localhost:6379 | Redis for request log, settings, and audit log |
| BYPASS_TOKEN | (none) | Displayed in dashboard for reference |
| VALIDATOR_URL | http://validator:8080 | URL of the validation service (for stats/rules API) |
| LDAP_URI | ldap://ldap.example.com:389 | Active Directory server |
| LDAP_DOMAIN | EXAMPLE | AD domain prefix for bind (DOMAIN\user) |
| LDAP_REQUIRED_GROUP | admins | AD group required for login (legacy, still checked for backward compat) |
| LDAP_ADMIN_GROUP | admins | AD group for admin role (full read/write access) |
| LDAP_USER_GROUP | users | AD group for viewer role (read-only access) |
| LDAP_BASE_DN | DC=example,DC=com | LDAP search base |
| AUTH_ENABLED | true | Set to "false" to disable auth (local dev) |

Requires the `ldap3` Python package for group membership verification. If `ldap3` is not installed, authentication falls back to a simple bind check without group verification.

### Admin Settings API

The dashboard exposes an API for viewing and updating runtime settings without redeploying. Settings are stored in Redis (prefix `settings:`) and read by the validator on each request.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| /api/settings | GET | Required | Get all runtime settings |
| /api/settings | POST | Required | Update one or more settings (JSON body) |
| /api/settings/audit | GET | Required | View audit log of settings changes (last 50) |
| /api/token/generate | POST | Required | Generate a new random bypass token (stored in Redis) |
| /api/rules | GET | No | Proxy to the validator's /rules endpoint |

Available settings:

| Setting | Default | Description |
|---------|---------|-------------|
| cooling_days | 7 | Minimum package age in days |
| bypass_token | (from env) | Current bypass token value |
| log_level | INFO | Logging verbosity |
| cache_ttl_allowed | 86400 | Cache TTL for allowed decisions (seconds) |
| cache_ttl_blocked | 3600 | Cache TTL for blocked decisions (seconds) |
| cache_ttl_error | 300 | Cache TTL for error/fallback decisions (seconds) |
| fail_open | true | Whether to allow requests when validator is unreachable |
| rules_reload_interval | 30 | How often to reload rules.yaml (seconds) |

All changes are audit-logged in Redis (`audit:log`) with the authenticated user, timestamp, and changed values.

## Test & Demo API

The validator includes built-in test endpoints accessible via Swagger UI at `http://localhost:8080/docs`. These let you exercise all proxy scenarios without needing curl, npm, pip, or Maven.

| Endpoint | Method | Description |
|----------|--------|-------------|
| /test/lookup | GET | Look up a package's publish date and whether it would be allowed/blocked |
| /test/simulate | GET | Simulate a full validation request (bypass → rules → cache → upstream) |
| /test/proxy-request | GET | Make a real request through the nginx proxy stack |
| /test/find-new-packages | GET | Find recently published packages across all ecosystems (test candidates) |
| /test/clear-cache | POST | Clear cached decisions from Redis (per-package or all) |

All endpoints accept `ecosystem` (npm/pypi/maven) and `package` query parameters. Available in local dev and disabled in production via environment variable.

## Deployment

```bash
helm install quarry ./helm \
  --set nexus.upstream=http://nexus:8081 \
  --set redis.enabled=true \
  --set ingress.host=artifacts.example.com
```

### Redis Persistence

Redis is deployed as a StatefulSet with AOF persistence enabled by default. This means cached publish-date lookups, the request log, and quarantine data survive pod restarts.

| Helm Value | Default | Description |
|------------|---------|-------------|
| redis.maxmemory | 128mb | Redis maxmemory setting (eviction via allkeys-lru) |
| redis.persistence.enabled | true | Enable PVC-backed AOF persistence |
| redis.persistence.storageClass | gp2 | StorageClass for the PVC |
| redis.persistence.size | 1Gi | PVC size |

To disable persistence (ephemeral cache only):

```bash
helm install quarry ./helm \
  --set redis.persistence.enabled=false
```
