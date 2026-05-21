# Quarry — Demo Walkthrough

Full end-to-end test of all features. Run locally with podman-compose.

## Prerequisites

```bash
# From the quarry directory
cd quarry

# Make sure podman/docker is running
podman machine start  # or Docker Desktop
```

## 1. Start the Stack

```bash
podman-compose up --build
```

Wait for all services to show "Started" / "Uvicorn running":
- nginx on :8888
- validator on :8080 (internal)
- redis on :6379
- dashboard on :9000
- quarantine on :8090

## 2. Health Checks

```bash
# Nginx health
curl http://localhost:8888/health
# Expected: ok

# Validator health (through nginx won't work directly, but stats endpoint does)
curl http://localhost:8888/repository/npm-central/ 2>/dev/null | head -5
# Expected: Nexus HTML response (proves proxy is forwarding)
```

## 3. Test Hold Period — Allow Old Package

```bash
# express was published in 2010 — well past 7 days
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/repository/npm-central/express
# Expected: 200

# requests (PyPI) was published in 2011
curl -s -o /dev/null -w "%{http_code}" "http://localhost:8888/repository/pypi-proxy/simple/requests/"
# Expected: 200
```

## 4. Test Hold Period — Block New Package

Find a package published in the last 7 days (check https://www.npmjs.com/search?ranking=maintenance&q=published-today or use a known-new one):

```bash
# Replace with an actually-new package if needed
# This will likely be blocked if published < 7 days ago:
curl -s -w "\nHTTP_CODE: %{http_code}\n" http://localhost:8888/repository/npm-central/some-brand-new-package-2026
# Expected: 403 with message about hold period
```

If you can't find a new package, temporarily set COOLING_DAYS=99999 to force everything to be "too new":

```bash
# Stop the stack, edit docker-compose.yml: COOLING_DAYS: "99999"
# Restart, then:
curl -s -w "\nHTTP_CODE: %{http_code}\n" http://localhost:8888/repository/npm-central/express
# Expected: 403 (even express is "too new" with 99999 day hold)
# Don't forget to set it back to 7!
```

## 5. Test Rules File — Permanent Block

The `rules.yaml` has `event-stream` (npm) permanently blocked:

```bash
curl -s -w "\nHTTP_CODE: %{http_code}\n" http://localhost:8888/repository/npm-central/event-stream
# Expected: 403 "permanently blocked by policy rule"
```

Test `ctx` (PyPI) — also in the block list:

```bash
curl -s -w "\nHTTP_CODE: %{http_code}\n" "http://localhost:8888/repository/pypi-proxy/simple/ctx/"
# Expected: 403
```

## 6. Test Rules File — Hot Reload

Edit `rules.yaml` while the stack is running. Add express to the block list:

```yaml
  block:
    - package: "express"
      ecosystem: npm
      reason: "Testing hot reload"
      added_by: demo
      added_on: "2026-05-14"
```

Wait 30 seconds (or watch validator logs for "Loaded rules"), then:

```bash
curl -s -w "\nHTTP_CODE: %{http_code}\n" http://localhost:8888/repository/npm-central/express
# Expected: 403 (was 200 before the rule change)
```

Remove the test rule and wait 30s — express should be allowed again.

## 7. Test Bypass Token

The bypass token in docker-compose is `dev-bypass-token`:

```bash
# Block a package first (event-stream is permanently blocked)
curl -s -w "\nHTTP_CODE: %{http_code}\n" http://localhost:8888/repository/npm-central/event-stream
# Expected: 403

# Now bypass it
curl -s -w "\nHTTP_CODE: %{http_code}\n" -H "X-Cooling-Bypass: dev-bypass-token" http://localhost:8888/repository/npm-central/event-stream
# Expected: 200 (bypass overrides everything)
```

## 8. Test Fail-Open Behavior

Stop the validator container while nginx is still running:

```bash
podman-compose stop validator
```

Now try a request:

```bash
curl -s -w "\nHTTP_CODE: %{http_code}\n" http://localhost:8888/repository/npm-central/express
# Expected: 200 (nginx fails open — forwards directly to Nexus)
```

Restart the validator:

```bash
podman-compose start validator
```

## 9. Test Hosted Repo Bypass

Hosted repos (internal packages) skip validation entirely:

```bash
# This path matches the "hosted-*" pattern — no validation
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/repository/hosted-npm/some-internal-pkg
# Expected: 200 (or 404 from Nexus if package doesn't exist, but NOT 403)
```

## 10. Check the Dashboard

Open in browser: http://localhost:9000

You'll be prompted for LDAP credentials (HTTP Basic Auth). To skip auth for local dev, set `AUTH_ENABLED=false` in `docker-compose.yml` and restart.

You should see:
- Real-time request log showing all the requests you just made
- Allow/block decisions with timestamps
- Package names, ecosystems, source IPs
- Rule-based blocks show as "block_rule" vs hold-based "block"

When logged in, an **Admin Settings** panel appears below the request log. From there you can adjust hold period, bypass token, log level, fail-open behavior, and cache TTLs — all without redeploying. Changes take effect immediately and are recorded in the audit log shown at the bottom of the panel. (See also §15 for the equivalent API.)

## 11. Check Stats & Rules API

```bash
# Stats endpoint
curl -s http://localhost:8888/repository/npm-central/express > /dev/null
curl -s localhost:8080/stats 2>/dev/null || true

# If validator port isn't exposed, use the internal network:
podman-compose exec validator curl -s http://localhost:8080/stats | python3 -m json.tool

# Rules endpoint
podman-compose exec validator curl -s http://localhost:8080/rules | python3 -m json.tool
# Expected: JSON with allow[] and block[] arrays matching rules.yaml
```

## 12. Test with Real Package Managers

### npm

```bash
# Configure npm to use the proxy
npm config set registry http://localhost:8888/repository/npm-central/

# Install an old package (should work)
npm install express
# Expected: installs normally

# Try to install a blocked package
npm install event-stream
# Expected: fails with 403

# Reset npm registry
npm config delete registry
```

### pip

```bash
# Install through the proxy
pip install --index-url http://localhost:8888/repository/pypi-proxy/simple/ requests
# Expected: installs normally

# Try blocked package
pip install --index-url http://localhost:8888/repository/pypi-proxy/simple/ ctx
# Expected: fails with 403
```

### Maven

Add to your `~/.m2/settings.xml` or project `pom.xml`:

```xml
<repositories>
  <repository>
    <id>quarry</id>
    <url>http://localhost:8888/repository/maven-central/</url>
  </repository>
</repositories>
```

```bash
# Then build a project — old dependencies should resolve fine
mvn dependency:resolve
```

## 13. Test Quarantine Webhook

```bash
# Manually quarantine a package
curl -s -X POST http://localhost:8090/quarantine \
  -H "Content-Type: application/json" \
  -d '{"package": "malicious-pkg", "ecosystem": "npm", "reason": "Demo quarantine"}' | python3 -m json.tool
# Expected: success response

# Check quarantine log
curl -s http://localhost:8090/quarantine/log | python3 -m json.tool

# Check quarantine stats
curl -s http://localhost:8090/quarantine/stats | python3 -m json.tool
```

## 14. Redis Persistence Test

```bash
# Make some requests to populate the cache
curl -s http://localhost:8888/repository/npm-central/express > /dev/null
curl -s http://localhost:8888/repository/npm-central/lodash > /dev/null

# Restart Redis
podman-compose restart redis

# Wait a few seconds for Redis to reload AOF
sleep 3

# Check that cached decisions survived
podman-compose exec redis redis-cli keys "cooling:*"
# Expected: cooling:npm:express, cooling:npm:lodash (persisted via AOF)

# Dashboard request log should also survive
# Open http://localhost:9000 — previous requests should still be visible
```

## 15. Test Admin Settings API

```bash
# Get current settings (requires LDAP auth by default)
# To skip auth for local dev, set AUTH_ENABLED=false in docker-compose.yml
curl -s -u youruser:yourpass http://localhost:9000/api/settings | python3 -m json.tool
# Expected: JSON with cooling_days, bypass_token, log_level, cache TTLs, etc.

# Update cooling_days at runtime (no redeploy needed)
curl -s -X POST http://localhost:9000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"cooling_days": "14"}' | python3 -m json.tool
# Expected: {"status": "ok", "updated": {"cooling_days": "14"}}

# Verify the change took effect
curl -s http://localhost:9000/api/settings | python3 -m json.tool
# Expected: cooling_days = "14"

# View audit log of settings changes
curl -s http://localhost:9000/api/settings/audit | python3 -m json.tool
# Expected: log entries showing who changed what and when

# Get active rules (proxied from validator)
curl -s http://localhost:9000/api/rules | python3 -m json.tool
# Expected: allow[] and block[] arrays matching rules.yaml

# Reset cooling_days back to default
curl -s -X POST http://localhost:9000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"cooling_days": "7"}' | python3 -m json.tool
```

## 16. Test Token Generation API

You can generate tokens from the dashboard UI (Admin Settings → "🔑 Generate New Token" button) or via the API:

```bash
# Generate a new bypass token (requires LDAP auth — enabled by default)
curl -s -X POST http://localhost:9000/api/token/generate | python3 -m json.tool
# Expected: {"token": "<new-random-token>"}

# Use the newly generated token to bypass a block
NEW_TOKEN=$(curl -s -X POST http://localhost:9000/api/token/generate | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
curl -s -w "\nHTTP_CODE: %{http_code}\n" -H "X-Cooling-Bypass: $NEW_TOKEN" http://localhost:8888/repository/npm-central/event-stream
# Expected: 200 (new token works as bypass)

# Verify it shows up in the audit log
curl -s http://localhost:9000/api/settings/audit | python3 -m json.tool
# Expected: entry with "action": "token_generated"
```

Token generation is logged in the audit trail. The full token is visible to admins in the Admin Settings panel (click to copy). Non-admin developers should contact DevOps for bypass access.

## 17. Swagger UI — Interactive Test API

The validator has built-in test endpoints accessible at: http://localhost:8080/docs

Open in a browser and try:

- **GET /test/lookup** — Check a package's publish date and whether it would be blocked
- **GET /test/simulate** — Run the full validation flow (bypass → rules → cache → upstream) without going through nginx
- **GET /test/proxy-request** — Make a real request through the full nginx proxy stack
- **GET /test/find-new-packages** — Discover recently published packages across npm/PyPI/Maven (great for finding test candidates)
- **POST /test/clear-cache** — Clear Redis cache for a package (useful when re-testing after rule/settings changes)

These are especially handy for demos — no curl or package manager setup needed.

## 18. Cleanup

```bash
podman-compose down -v  # -v removes the redis volume too
```

---

## Appendix: Find Recently Published Packages (for testing blocks)

Use these commands to find packages published in the last 7 days that the Quarry WOULD block.

### Maven — Find new artifacts

```bash
curl -s "https://search.maven.org/solrsearch/select?q=g:org.apache*&rows=10&wt=json&sort=timestamp+desc" | python3 -c "
import sys, json
from datetime import datetime, timezone
data = json.load(sys.stdin)
now = datetime.now(timezone.utc)
print('Package | Age | Status')
print('--------|-----|-------')
for doc in data.get('response', {}).get('docs', []):
    ts = doc.get('timestamp', 0)
    dt = datetime.fromtimestamp(ts/1000, tz=timezone.utc)
    age = (now - dt).days
    status = 'BLOCK' if age < 7 else 'allow'
    gav = f\"{doc.get('g')}:{doc.get('a')}:{doc.get('latestVersion')}\"
    print(f'{gav} | {age}d | {status}')
"
```

Then add the blocked artifact to `quarry-maven-app/pom.xml`:

```xml
<dependency>
    <groupId>org.apache.cxf.build-utils</groupId>
    <artifactId>cxf-buildtools</artifactId>
    <version>4.1.4</version>  <!-- Published 2026-05-09, < 7 days -->
</dependency>
```

Test it:

```bash
# Clear local cache so Maven must fetch through proxy
rm -rf ~/.m2/repository/org/apache/cxf

# Build — should FAIL with 403 from Quarry
mvn clean package -f quarry-maven-app/pom.xml \
  -s quarry-maven-app/.mvn/settings.xml

# Expected error: "Could not resolve dependencies... status code: 403"
```

### PyPI — Find new packages (published today)

```bash
curl -s "https://pypi.org/rss/updates.xml" | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
root = tree.getroot()
items = root.findall('./channel/item')[:10]
for item in items:
    title = item.find('title').text
    pub = item.find('pubDate').text
    print(f'{title} -- {pub}')
"
```

Test it:

```bash
# Try to install a brand-new PyPI package through the proxy
pip install --index-url http://localhost:8888/repository/pypi-proxy/simple/ <new-package-name>
# Expected: 403 blocked by hold period
```

### npm — Find new packages

```bash
# Check the npm "recently published" search:
curl -s "https://registry.npmjs.org/-/v1/search?text=not:unstable&size=5&quality=0.0&popularity=0.0&maintenance=0.0" | python3 -c "
import sys, json
from datetime import datetime, timezone
data = json.load(sys.stdin)
now = datetime.now(timezone.utc)
for obj in data.get('objects', []):
    pkg = obj.get('package', {})
    name = pkg.get('name')
    date = pkg.get('date', '')
    print(f'{name} -- published {date}')
" 2>/dev/null || echo "Browse: https://www.npmjs.com/search?ranking=maintenance to find new packages"
```

Test it:

```bash
# Configure npm to use proxy and try a new package
npm --registry http://localhost:8888/repository/npm-central/ install <new-package-name>
# Expected: 403 blocked by hold period
```

### All-in-one: Find blockable packages across all ecosystems

```bash
echo "=== Maven (published < 7 days) ===" && \
curl -s "https://search.maven.org/solrsearch/select?q=g:org.apache*&rows=5&wt=json&sort=timestamp+desc" | \
python3 -c "
import sys, json
from datetime import datetime, timezone
data = json.load(sys.stdin)
now = datetime.now(timezone.utc)
for doc in data.get('response', {}).get('docs', [])[:5]:
    ts = doc.get('timestamp', 0)
    dt = datetime.fromtimestamp(ts/1000, tz=timezone.utc)
    age = (now - dt).days
    if age < 7:
        print(f'  {doc.get(\"g\")}:{doc.get(\"a\")}:{doc.get(\"latestVersion\")} ({age}d old)')
" && \
echo "" && echo "=== PyPI (published today) ===" && \
curl -s "https://pypi.org/rss/updates.xml" | python3 -c "
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.stdin)
items = tree.getroot().findall('./channel/item')[:5]
for item in items:
    print(f'  {item.find(\"title\").text}')
"
```

### Maven pom.xml snippet for testing

Once you find a package published < 7 days ago, add it to the pom:

```xml
<!-- Add inside <dependencies> in quarry-maven-app/pom.xml -->
<!-- Replace with whatever the "all-in-one" script found -->
<dependency>
    <groupId>org.apache.cxf.build-utils</groupId>
    <artifactId>cxf-buildtools</artifactId>
    <version>4.1.4</version>
</dependency>
```

Then run:

```bash
# IMPORTANT: clear local Maven cache for this artifact first
rm -rf ~/.m2/repository/org/apache/cxf

# Build through the Quarry
mvn clean package -f quarry-maven-app/pom.xml \
  -s quarry-maven-app/.mvn/settings.xml

# Should fail with 403. Then test bypass (use the bypass settings file):
mvn clean package -f quarry-maven-app/pom.xml \
  -s quarry-maven-app/.mvn/settings-bypass.xml
```

---

## Quick Demo Script (5 minutes)

For a fast team demo, run these in sequence:

```bash
# Start
podman-compose up --build -d
sleep 10

echo "=== Health Check ==="
curl -s http://localhost:8888/health

echo -e "\n=== Old package (express) — ALLOW ==="
curl -s -w "HTTP %{http_code}\n" -o /dev/null http://localhost:8888/repository/npm-central/express

echo -e "\n=== Blocked by rule (event-stream) — BLOCK ==="
curl -s -w "HTTP %{http_code}\n" http://localhost:8888/repository/npm-central/event-stream

echo -e "\n=== Bypass token overrides block ==="
curl -s -w "HTTP %{http_code}\n" -o /dev/null -H "X-Cooling-Bypass: dev-bypass-token" http://localhost:8888/repository/npm-central/event-stream

echo -e "\n=== Hosted repo (no validation) ==="
curl -s -w "HTTP %{http_code}\n" -o /dev/null http://localhost:8888/repository/hosted-npm/anything

echo -e "\n=== Active rules ==="
podman-compose exec validator curl -s http://localhost:8080/rules | python3 -m json.tool

echo -e "\n=== Dashboard at http://localhost:9000 ==="
echo "Open in browser to see request log"

# Cleanup when done
# podman-compose down
```
