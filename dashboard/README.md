# Quarry Dashboard

Security dashboard for monitoring and managing the Quarry supply chain proxy.

## Architecture

Single-file app — Python backend + HTML/CSS/JS all in `app.py`. No frameworks, no build step, no npm.

### Backend (Python/FastAPI)

- FastAPI serves the HTML as a raw string (`DASHBOARD_HTML`)
- REST API endpoints return JSON
- Each endpoint reads from Redis or queries other services (validator, quarantine)
- Session-based auth with tokens stored in Redis (8-hour TTL)
- Two roles: admin (full access) and viewer (read-only)

### Frontend (vanilla JS)

- Single HTML page with inline `<style>` and `<script>`
- No React, no Vue, no build tools — just DOM manipulation
- Auto-refreshes every 5 seconds via `setInterval(refresh, 5000)`
- Sorting/filtering is client-side (full dataset in memory)

## Panels & Data Flow

| Panel | API Endpoint | Data Source | Refresh |
|-------|-------------|-------------|---------|
| Metrics row (top) | `/api/validator/stats` + `/api/quarantine/stats` | Redis key counts | Every 5s |
| Package table | `/api/packages` | Redis `cooling:*` + `age:*` + `requester:*` | Every 5s |
| Data Sources | `/api/sources` | Redis `source:*:last_pull` timestamps | Every 5s |
| Quarantine Log | `/api/quarantine/log` | Redis `quarantine:log` list | Every 5s |
| Admin Settings | `/api/settings` | Redis `settings:*` keys | On login |
| Administration | `/api/admin/config` | Quarantine `/health` + env vars | On login |

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/` | No | Serve dashboard HTML |
| POST | `/api/auth/login` | No | Authenticate, returns bearer token |
| POST | `/api/auth/logout` | Bearer | Destroy session |
| GET | `/api/auth/status` | Bearer | Check session validity |
| GET | `/api/packages` | No | All tracked packages with status |
| POST | `/api/packages/override` | Admin | Allow/deny/clear a package (24h TTL) |
| GET | `/api/quarantine/log` | No | Recent quarantine actions |
| GET | `/api/quarantine/stats` | No | Aggregate quarantine stats |
| GET | `/api/sources` | No | Data source last-pull timestamps |
| GET | `/api/validator/stats` | No | Cached decision counts |
| GET | `/api/requests` | No | Recent request log |
| GET | `/api/settings` | Admin | Runtime settings |
| POST | `/api/settings` | Admin | Update runtime settings |
| GET | `/api/settings/audit` | Admin | Audit log of changes |
| GET | `/api/admin/config` | Admin | Read-only infrastructure config |
| GET | `/api/rules` | No | Proxy to validator's rules |
| GET | `/api/rules/mr-url` | No | Generate MR URL for rules.yaml change |
| POST | `/api/token/generate` | Admin | Generate new bypass token |
| GET | `/api/nexus-url` | No | Nexus base URL for package links |

## Authentication Flow

1. Page loads, dashboard renders (data visible)
2. Login overlay appears immediately — blocks interaction
3. User submits credentials → POST `/api/auth/login`
4. Backend validates against LDAP (or local admin password)
5. Returns a bearer token (stored in localStorage)
6. All subsequent API calls include `Authorization: Bearer <token>`
7. Token expires after 8 hours (configurable via `SESSION_TTL`)

## Override Flow (Hybrid GitOps)

1. Admin clicks Allow/Deny → 24-hour override in Redis
2. Modal shows YAML snippet + "Open Editor & Create MR" button
3. Clicking copies snippet to clipboard and opens GitLab/GitHub editor
4. User creates MR to make the change permanent in `rules.yaml`
5. If MR not merged, override auto-expires in 24h

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| REDIS_URL | redis://localhost:6379 | Redis connection |
| VALIDATOR_URL | http://validator:8080 | Validator service URL |
| QUARANTINE_URL | http://quarantine:8090 | Quarantine service URL |
| RULES_REPO_URL | (none) | GitLab/GitHub repo for MR creation |
| LDAP_URI | ldap://ldap.example.com:389 | LDAP server |
| LDAP_DOMAIN | EXAMPLE | AD domain prefix |
| LDAP_ADMIN_GROUP | admins | Group for admin role |
| LDAP_USER_GROUP | users | Group for viewer role |
| LDAP_BASE_DN | DC=example,DC=com | LDAP search base |
| AUTH_ENABLED | true | Set false to disable auth (local dev) |
| LOCAL_ADMIN_PASSWORD | (none) | Fallback password when LDAP unavailable |
| SESSION_TTL | 28800 | Session duration in seconds (8h) |
| OVERRIDE_TTL | 86400 | Override expiry in seconds (24h) |

## Why This Approach

- Zero dependencies beyond FastAPI and Redis
- No build step, no webpack, no node_modules
- Single container, single file to deploy
- Fast enough for an internal tool with <1000 packages
- Cache-Control headers prevent browser caching issues
