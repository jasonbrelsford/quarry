# Quarry CLI

Command-line tool for managing the Quarry supply chain security proxy.

## Installation

```bash
pip install -e .
# or just run directly:
python3 quarry --help
```

## Commands

Themed commands with boring aliases that also work:

| Command | Alias | What It Does |
|---------|-------|-------------|
| `quarry status` | — | Show proxy health, hold period, stats |
| `quarry ledger` | `log` | View recent package requests with decisions |
| `quarry release <eco> <pkg>` | `allow` | Free a package from the hold (24h override) |
| `quarry seal <eco> <pkg>` | `block` | Permanently lock a package away (24h override) |
| `quarry unseal <eco> <pkg>` | `clear` | Remove override, return to auto policy |
| `quarry edicts` | `rules` | Show active block/allow rules |
| `quarry scout [eco]` | — | Scan registries for recently published packages |
| `quarry inspect <eco> <pkg> [ver]` | `simulate` | Test what would happen for a package |
| `quarry config show` | — | Show CLI configuration |
| `quarry config set <key> <val>` | — | Update CLI or server settings |

## How It Works

The CLI talks to the validator service's REST API (default: `http://localhost:8080`). It doesn't connect to Redis directly — all state management goes through the API.

### Configuration

Stored in `~/.quarry.json`:
```json
{
  "url": "http://localhost:8080",
  "token": ""
}
```

Override with environment variables:
- `QUARRY_URL` — validator base URL
- `QUARRY_TOKEN` — auth token for protected endpoints

### Config Keys

| Key | Type | What It Does |
|-----|------|-------------|
| `url` | CLI | Validator service URL |
| `token` | CLI | Auth token |
| `hold-days` | Server | Change the hold period (pushes to Redis via dashboard API) |
| `bypass-token` | Server | Change the bypass token |
| `log-level` | Server | Change validator log level |
| `fail-open` | Server | Whether to allow packages when validator is down |

## Scout Command

Scans public registries for recently published packages and shows which would be held:

```bash
quarry scout maven --query org.apache --limit 10
quarry scout npm --query express
quarry scout all  # scan all registries
```

Returns a table with package name, age, and hold/pass status. For Maven packages that would be held, it outputs a ready-to-paste `<dependency>` block for testing.

## Ecosystems

The CLI accepts any ecosystem string. The validator currently supports npm, pypi, and maven. Other values (gitlab, artifactory, nuget, etc.) are passed through — the server will return an error if unsupported.

## Examples

```bash
# Check if the proxy is running
quarry status

# See what's been blocked recently
quarry ledger --limit 10

# Test a specific package
quarry inspect npm event-stream
quarry inspect maven org.apache.commons:commons-lang3 3.14.0

# Emergency: allow a blocked package for 24h
quarry release maven org.apache.cxf:cxf-core

# Find packages to test with
quarry scout maven --query org.apache

# Change the hold period
quarry config set hold-days 14
```
