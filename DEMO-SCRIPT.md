# Quarry Demo Script

Live demo walkthrough. Copy-paste each command.

## Prerequisites

```bash
# Containers running
podman-compose -f nexus-cooling-proxy/docker-compose.yml up -d

# Verify everything is up
podman ps --format "{{.Names}} {{.Status}}" | grep nexus-cooling
```

Dashboard: http://localhost:9000
Proxy: http://localhost:8888
Validator API: http://localhost:8080/docs

---

## 1. Show Current Status (CLI)

```bash
python3 nexus-cooling-proxy/cli/quarry status
```

Expected output shows hold period (14 days), cache connected, sealed packages count.

---

## 2. Scout for Blockable Packages

Find recently published Maven packages that would be blocked:

```bash
python3 nexus-cooling-proxy/cli/quarry scout maven --query org.apache --limit 10
```

This queries Maven Central for the newest packages. Anything under 14 days old shows as "⛔ HELD".

Pick one from the output for the next step.

---

## 3. Show the Rules (Edicts)

```bash
python3 nexus-cooling-proxy/cli/quarry edicts
```

Shows permanently blocked packages (event-stream, colors, faker, ctx, peacenotwar).

---

## 4. Inspect a Specific Package

```bash
# Known malware — should be HELD
python3 nexus-cooling-proxy/cli/quarry inspect npm event-stream

# Old safe package — should be RELEASED
python3 nexus-cooling-proxy/cli/quarry inspect maven org.apache.commons:commons-lang3 3.14.0
```

---

## 5. Maven Build — Allowed Packages

Clear the Maven cache and build. All dependencies in the pom are old enough to pass:

```bash
rm -rf ~/.m2/repository
mvn clean package -f maven-cooling-app/pom.xml -DskipTests
```

Expected: BUILD SUCCESS (all packages are past the hold period).

Check the dashboard at http://localhost:9000 — you'll see the packages appear with their age.

---

## 6. Maven Build — Blocked Package

The pom already has `org.apache.cxf.build-utils:cxf-buildtools:4.1.4` which was published ~9 days ago. With a 14-day hold period, it should be blocked.

```bash
# Clear just the cxf cache so it re-fetches
rm -rf ~/.m2/repository/org/apache/cxf

# Build — should FAIL with 403
mvn clean package -f maven-cooling-app/pom.xml -DskipTests
```

Expected: BUILD FAILURE with "403" in the error (blocked by hold period).

Check the dashboard — the package shows as "Blocked" with its age.

---

## 7. Override from Dashboard

1. Open http://localhost:9000
2. Find `org.apache.cxf.build-utils:cxf-buildtools` in the table
3. Click "✓ Allow"
4. Note the modal: "Override Applied (expires in 24h)" with MR creation option
5. Click "Skip" for now

---

## 8. Maven Build — After Override

```bash
# Clear cache again
rm -rf ~/.m2/repository/org/apache/cxf

# Build — should SUCCEED now
mvn clean package -f maven-cooling-app/pom.xml -DskipTests
```

Expected: BUILD SUCCESS (override allows it through).

---

## 9. Override from CLI

```bash
# Seal a package (block it)
python3 nexus-cooling-proxy/cli/quarry seal npm event-stream

# Check it
python3 nexus-cooling-proxy/cli/quarry inspect npm event-stream

# Unseal it
python3 nexus-cooling-proxy/cli/quarry unseal npm event-stream
```

---

## 10. Show the Dashboard Features

Open http://localhost:9000 and walk through:

- **Metrics row** — allowed/blocked/quarantined counts
- **Package table** — click column headers to sort (by age, status, ecosystem)
- **Filter bar** — filter by name, status, or ecosystem
- **Age column** — color-coded (red < 7d, orange < 14d, green = safe)
- **Data Sources panel** — shows GitHub Advisory DB polling status
- **Admin Settings** — hold period, bypass token, cache TTLs
- **Administration panel** — LDAP config, data sources, Nexus integration

---

## 11. Quarantine Demo (Malware Removal)

Show that the quarantine service can delete packages from Nexus:

```bash
# First, cache a package in Nexus
curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:8888/repository/npm-central/lodash/-/lodash-4.17.21.tgz"
# Expected: 200

# Now quarantine it (simulates malware detection)
curl -s -X POST http://localhost:8090/quarantine \
  -H "Content-Type: application/json" \
  -d '{"package":"lodash","ecosystem":"npm","reason":"Demo - testing quarantine flow"}' | python3 -m json.tool
```

Expected: shows "deleted" array with the package removed from Nexus.

```bash
# Clean up — remove lodash from block list
podman exec nexus-cooling-proxy_redis_1 redis-cli DEL cooling:npm:lodash
```

---

## 12. Load Test (Optional)

```bash
# Validator throughput — cached decisions
hey -n 500 -c 20 -H "X-Original-URI: /repository/maven-central/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar" http://localhost:8080/validate

# Expected: ~2000 req/sec on laptop, <10ms average latency
```

---

## Key Talking Points

- **Hold period is configurable** — 7, 14, 30 days, whatever the team wants
- **No developer workflow change** — Maven/npm/pip just work, blocked packages get a clear 403 message
- **Emergency bypass** — admins can override in seconds from dashboard or CLI
- **Auto-expires** — overrides last 24h, forces teams to formalize via MR
- **Malware auto-removal** — polls GitHub Advisory DB hourly, deletes cached malware from Nexus
- **Scales** — 2000 req/sec on a laptop, stateless validator scales horizontally
- **GitOps** — permanent policy lives in `rules.yaml` in git, auditable via PR
- **No vendor lock-in** — works with any Nexus instance, open source (Apache 2.0)
