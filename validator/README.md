# Quarry Validator

The core validation engine. Called by nginx via `auth_request` to decide whether a package download should be allowed or blocked.

## Architecture

Single Python/FastAPI service. Stateless except for Redis cache reads. Can be scaled horizontally.

### Request Flow

```
Client → nginx → auth_request → Validator → 200 (allow) or 403 (block)
                                    ↓
                              Priority order:
                              1. Bypass token (header)
                              2. rules.yaml (file)
                              3. Redis override (dashboard/CLI)
                              4. Redis cache (previous decision)
                              5. Upstream registry lookup (age check)
```

### Two Validation Modes

| Endpoint | Used For | Behavior |
|----------|----------|----------|
| `/validate` | Proxy repos (external packages) | Full check: hold period + block list |
| `/validate-internal` | Hosted repos (internal packages) | Block list only, no hold period |

## How It Works

1. nginx sends the original request URI via `X-Original-URI` header
2. Validator parses the path to extract ecosystem + package + version
3. Checks decision sources in priority order (see above)
4. If no cached decision, looks up publish date from upstream registry
5. Compares age against `COOLING_DAYS` threshold
6. Caches the decision in Redis for future requests

## URL Parsing

The validator identifies packages from Nexus proxy paths:

| Ecosystem | Pattern | Example |
|-----------|---------|---------|
| npm | `/repository/npm-*/package/-/tarball` | `/repository/npm-central/express/-/express-4.21.2.tgz` |
| PyPI | `/repository/*pypi*/simple/package/` | `/repository/pypi-proxy/simple/requests/` |
| Maven | `/repository/maven-*/group/artifact/version/file` | `/repository/maven-central/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar` |

## Rules Engine

Loads `rules.yaml` from a mounted volume. Hot-reloads every 30 seconds (watches file mtime). No restart needed when rules change.

Rules take precedence over the hold period — a package in the allow list passes immediately regardless of age.

## Upstream Registry Lookups

| Registry | API Used | What It Returns |
|----------|----------|-----------------|
| npm | `https://registry.npmjs.org/{package}` | `time.created` field |
| PyPI | `https://pypi.org/pypi/{package}/json` | Earliest `upload_time` across all releases |
| Maven Central | `https://search.maven.org/solrsearch/select` | `timestamp` field |

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/validate` | nginx auth_request (full validation) |
| GET | `/validate-internal` | nginx auth_request (block-list only) |
| GET | `/health` | Health check, returns cooling_days |
| GET | `/stats` | Cache stats and rule counts |
| GET | `/requests` | Recent request log from Redis |
| GET | `/rules` | Current active rules |
| GET | `/test/lookup` | Look up a package's publish date |
| GET | `/test/simulate` | Simulate full validation flow |
| GET | `/test/proxy-request` | Test through actual nginx proxy |
| GET | `/test/find-new-packages` | Find recently published packages |
| POST | `/test/clear-cache` | Clear all cached decisions |

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| COOLING_DAYS | 7 | Minimum package age in days |
| REDIS_URL | redis://localhost:6379 | Redis connection |
| BYPASS_HEADER | X-Cooling-Bypass | Header name for bypass token |
| BYPASS_TOKEN | (none) | Token value for emergency bypass |
| RULES_FILE | /app/rules.yaml | Path to rules override file |
| LOG_LEVEL | INFO | Logging verbosity |

## Scaling

Fully stateless — scale to as many replicas as needed. All state is in Redis (shared) and rules.yaml (mounted ConfigMap). The rules file watcher thread is per-instance but idempotent.

## Redis Keys Used

| Pattern | Purpose | TTL |
|---------|---------|-----|
| `cooling:{eco}:{pkg}` | Cached allow/block decision | 24h (allow) / 1h (block) |
| `version:{eco}:{pkg}` | Last seen version | None |
| `age:{eco}:{pkg}` | Package age in days | None |
| `requester:{eco}:{pkg}` | Last requester info (IP, UA) | None |
| `request:log` | Recent request log (list, max 500) | None |
| `settings:cooling_days` | Runtime override of COOLING_DAYS | None |
| `settings:bypass_token` | Runtime override of bypass token | None |
