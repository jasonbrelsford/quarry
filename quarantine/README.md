# Quarry Quarantine Service

Automatic malware removal. Polls advisory databases, finds cached malware in Nexus, deletes it, and blocks re-download.

## Architecture

Single Python/FastAPI service with a background polling loop. Should run as a single replica (to avoid duplicate API calls to GitHub/OSV).

### Flow When Malware Is Detected

```
Advisory Source (GitHub/OSV) → Quarantine Service
    ↓
1. Search Nexus for cached copies (GET /service/rest/v1/search)
2. Delete each found component (DELETE /service/rest/v1/components/{id})
3. Add regex matcher to block_malware routing rule (PUT /service/rest/v1/routing-rules)
4. Auto-assign routing rule to all proxy repos
5. Mark as blocked in Redis (cooling:{eco}:{pkg} = "block")
6. Log action to Redis (quarantine:log list)
```

### Three Ways Malware Gets Quarantined

| Trigger | How | Latency |
|---------|-----|---------|
| Background poll | Checks GitHub Advisory DB + OSV.dev every hour | Up to 1 hour |
| Webhook | GitHub sends POST to `/webhook/github` on new advisory | Seconds |
| Manual | Admin calls POST `/quarantine` with package details | Immediate |

## Advisory Sources

| Source | What It Provides | Auth | Rate Limit |
|--------|-----------------|------|------------|
| GitHub Advisory DB | Malware-type advisories per ecosystem | GITHUB_TOKEN (PAT) | 5000/hr with token, 60/hr without |
| OSV.dev | MAL-* entries (sequential IDs) | None (public) | Generous |

### GitHub Advisory Polling

- Paginates through all `type=malware` advisories (100 per page)
- Checks npm, pip, and maven ecosystems
- Skips packages already marked as blocked in Redis
- First sync can take several minutes (30k+ npm malware entries)
- Subsequent polls are fast (most already cached)

### OSV.dev Polling

- Checks sequential MAL-20XX-NNNN IDs after the last known
- Stores high-water mark in Redis (`osv:last_mal_id`)
- Covers npm, PyPI, and Maven

## Nexus Integration

### Search
```
GET /service/rest/v1/search?repository={repo}&name={package}
```
Returns component IDs for deletion.

### Delete
```
DELETE /service/rest/v1/components/{component_id}
```
Removes the cached artifact. Returns 204 on success.

### Routing Rules
```
GET/PUT /service/rest/v1/routing-rules/block_malware
```
Maintains a single routing rule with regex matchers for all known malware. Auto-assigns to all proxy repos.

### Required Nexus Privileges

The service account needs:
- `nx-search-read` — search for components
- `nx-component-upload` — delete components (yes, same privilege)
- `nx-repository-admin-*-*-edit` — modify routing rules and repo config

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/webhook/github` | GitHub Advisory webhook receiver |
| POST | `/webhook/osv` | OSV.dev webhook / manual trigger |
| POST | `/quarantine` | Manual quarantine (package + ecosystem + reason) |
| GET | `/quarantine/log` | Recent quarantine actions |
| GET | `/quarantine/stats` | Aggregate stats |
| GET | `/health` | Health check with config info |
| POST | `/poll` | Manually trigger advisory poll |

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| NEXUS_URL | https://nexus.example.com | Nexus instance to quarantine from |
| NEXUS_USER | (none) | Nexus admin credentials |
| NEXUS_PASSWORD | (none) | Nexus admin credentials |
| REDIS_URL | redis://localhost:6379 | Redis for logging and state |
| GITHUB_TOKEN | (none) | GitHub PAT (increases rate limit 60→5000/hr) |
| GITHUB_WEBHOOK_SECRET | (none) | HMAC secret for webhook verification |
| POLL_INTERVAL_SECONDS | 3600 | Seconds between advisory polls |
| LOG_LEVEL | INFO | Logging verbosity |

## Redis Keys Used

| Pattern | Purpose | TTL |
|---------|---------|-----|
| `cooling:{eco}:{pkg}` | Block marker for quarantined packages | 30 days |
| `quarantine:log` | List of quarantine actions (max 5000) | None |
| `source:github:last_pull` | Last GitHub poll timestamp | None |
| `source:osv:{eco}:last_pull` | Last OSV poll timestamp | None |
| `osv:last_mal_id` | High-water mark for OSV MAL IDs | None |

## Scaling

Run as a **single replica**. Multiple instances would:
- Duplicate GitHub API calls (wasting rate limit)
- Create duplicate quarantine log entries
- Race on routing rule updates

If HA is needed, implement a Redis-based distributed lock so only one instance polls at a time.

## Ecosystem → Repo Mapping

```python
ECOSYSTEM_REPOS = {
    "npm": ["npm-central"],
    "pip": ["pypi-proxy"],
    "maven": ["maven-public-central", "maven-public-sonatype"],
}
```

Update this mapping to match your actual Nexus repository names.
