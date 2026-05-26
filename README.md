# Argus Security Monitor

A Python agent that monitors an [Argus](https://github.com/release-argus/Argus) instance for outdated services, analyzes release notes for security vulnerabilities using an LLM, enriches CVEs via the NVD API, and sends prioritized alerts to Microsoft Teams.

## How it works

```
┌─────────────┐     ┌──────────────┐     ┌───────────┐     ┌─────┐     ┌───────┐
│ Argus REST + │────>│ GitHub API   │────>│ OpenRouter │────>│ NVD │────>│ Teams │
│ WebSocket    │     │ Release Notes│     │ LLM        │     │ API │     │       │
└─────────────┘     └──────────────┘     └───────────┘     └─────┘     └───────┘
```

1. **Startup scan** — Fetches all services from Argus via REST API, identifies outdated ones (deployed version != latest version)
2. **For each outdated service:**
   - Fetches release notes from GitHub Releases API
   - Sends notes to an LLM (via OpenRouter) to identify security content and extract CVE IDs
   - Queries the NVD API for CVSS scores and severity on any CVEs found
   - Sends all context back to the LLM for a risk assessment with priority rating
   - If security updates are found, sends an Adaptive Card alert to Teams via Power Automate
3. **Continuous monitoring** — Connects to Argus WebSocket for real-time version change notifications, triggering the same pipeline for new updates

## Prerequisites

- Python 3.11+
- A running [Argus](https://github.com/release-argus/Argus) instance with basic auth enabled
- An [OpenRouter](https://openrouter.ai) API key (free tier models work)
- A Microsoft Teams channel with a Power Automate webhook configured (see [Teams setup](#teams-webhook-setup))
- (Optional) A GitHub personal access token for higher API rate limits

## Quick start

```bash
# Clone the repo
cd argus-agent

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your values (see Configuration below)

# Run
python argus_monitor.py
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

| Variable | Required | Description |
|----------|----------|-------------|
| `ARGUS_URL` | Yes | Argus instance URL (e.g., `http://argus.local:8080`) |
| `ARGUS_USERNAME` | Yes | Argus basic auth username |
| `ARGUS_PASSWORD` | Yes | Argus basic auth password |
| `OPENROUTER_KEY` | Yes | OpenRouter API key (`sk-or-v1-...`) |
| `OPENROUTER_MODEL` | No | OpenRouter model ID (default: `openrouter/free`) |
| `TEAMS_WEBHOOK_URL` | Yes | Power Automate flow trigger URL |
| `GITHUB_TOKEN` | No | GitHub PAT for higher rate limits (60 req/hr without, 5000 with) |
| `LOG_FILE` | No | Log file path (default: `argus_monitor.log`) |
| `SCAN_INTERVAL` | No | Seconds between periodic full re-scans (default: `3600` = 1 hour) |

### Custom service mappings

Some services in Argus may not point directly to their GitHub repo, or may use non-standard tag formats. These are configured via two dicts in `argus_monitor.py`:

```python
# Override the GitHub repo URL for a service
GITHUB_OVERRIDES = {
    "jenkins": "https://github.com/jenkinsci/jenkins",
    "kubernetes": "https://github.com/k3s-io/k3s",
}

# Override the release tag format for a service
TAG_OVERRIDES = {
    "jenkins": lambda v: [f"jenkins-{v}"],        # jenkins-2.541.3
    "kubernetes": lambda v: [f"v{v}", v],          # v1.35.2+k3s1
}
```

Add entries here if you have services that use non-standard GitHub repos or tag naming conventions.

## Teams webhook setup

This tool sends alerts to Teams via a Power Automate flow:

1. In Power Automate, create a new **Instant cloud flow** with trigger **When an HTTP request is received**
2. Set the HTTP method to **POST**
3. Add the action **Post card in a chat or channel** (Microsoft Teams)
   - **Post as**: Flow bot
   - **Post in**: Channel
   - **Team** and **Channel**: Select your target
   - **Adaptive Card**: Use the expression `triggerBody()?['attachments'][0]['content']` (or paste the body from the HTTP trigger)
4. Save the flow and copy the **HTTP POST URL** — this is your `TEAMS_WEBHOOK_URL`

The script sends a fully-formed Adaptive Card with priority, version info, risk assessment, CVE details, and a link to the source repo.

## Deploying on a server

### Option 1: systemd service (Linux)

An automated setup script is included:

```bash
# Copy the project to the server
scp -r argus-agent/ user@server:~/argus-agent/

# On the server
cd ~/argus-agent
sudo ./setup-service.sh
```

The script:
- Creates a `argus` system user (no login shell)
- Installs to `/opt/argus-agent` with a Python venv
- Creates a hardened systemd unit (read-only filesystem, no privilege escalation)
- Locks down `.env` permissions (readable only by root and the service user)
- Enables the service to start on boot

> **Note:** The `.env` is loaded by python-dotenv inside the script, **not** by systemd's `EnvironmentFile` (which can't handle passwords with spaces or special characters).

After setup:
```bash
# Edit config if needed
sudo nano /opt/argus-agent/.env

# Manage the service
sudo systemctl start   argus-monitor
sudo systemctl stop    argus-monitor
sudo systemctl status  argus-monitor
sudo journalctl -u argus-monitor -f

# Application log (full timestamps for review)
tail -f /opt/argus-agent/argus_monitor.log
```

### Option 2: Docker

```dockerfile
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY argus_monitor.py .
CMD ["python", "argus_monitor.py"]
```

```bash
docker build -t argus-monitor .
docker run -d --name argus-monitor --restart unless-stopped --env-file .env argus-monitor
```

### Option 3: Run directly (Windows/macOS/Linux)

```bash
# In a terminal or tmux/screen session
python argus_monitor.py

# Or with nohup on Linux
nohup python argus_monitor.py > argus_monitor.log 2>&1 &
```

## How it runs as a service

The monitor uses three layers to make sure nothing is missed:

1. **Startup scan** — processes all currently outdated services immediately
2. **WebSocket listener** — reacts to real-time VERSION and SERVICE events from Argus (reconnects with exponential backoff if disconnected)
3. **Periodic re-scan** — full re-scan every `SCAN_INTERVAL` seconds (default: 1 hour) to catch anything the WebSocket missed during reconnect gaps or network blips

All three run concurrently. The `_alerted` set (keyed on service + version) prevents duplicate alerts, so re-scans are cheap — only truly new outdated services get processed.

## How alerts work

- Alerts are only sent for services where the LLM identifies **security-related updates** in the release notes
- Each (service, version) pair is only alerted once per session to prevent duplicates
- If the Teams webhook fails, the alert is retried on the next scan cycle
- If the configured LLM model is unavailable, a Teams alert is sent and the service exits

## Project structure

```
argus-agent/
├── argus_monitor.py    # Main monitor script
├── setup-service.sh    # Automated systemd service installer
├── requirements.txt    # Python dependencies
├── .env.example        # Template for environment variables
├── .env                # Your actual config (gitignored)
├── .gitignore
└── README.md
```

## License

MIT
