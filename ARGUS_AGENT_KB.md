# Argus Agent Operation on the Update Server

## Description / Overview

Argus Agent is a Python monitor that runs on the LSIT update server, `update.ls.byu.edu`, from `/opt/argus-agent`. It checks Argus for outdated services, analyzes GitHub release notes for security-related changes using OpenRouter, enriches CVE findings through the NVD API, and posts security update alerts to Microsoft Teams through the configured webhook.

## Prerequisites

- Root access on the update server:

```bash
sudo su
```

- Access to the deployed directory:

```text
/opt/argus-agent
```

- Python virtual environment already present at:

```text
/opt/argus-agent/venv
```

- Python dependencies installed in the virtual environment:

```text
websockets>=13.0
python-dotenv>=1.0
```

- Required credentials and secrets from LastPass:
  - Argus credentials
  - OpenRouter API key
  - Teams webhook URL

- Network access from `update.ls.byu.edu` to:
  - The Argus service
  - OpenRouter
  - GitHub release data
  - NVD CVE API
  - The Teams webhook URL

## Scope / When to Use This

Use this article to understand, operate, and make small changes to Argus Agent on `update.ls.byu.edu`.

This article applies to the deployed service files under `/opt/argus-agent`. It does not document how to create the Teams webhook or Power Automate flow. Those values already exist and should be retrieved from LastPass when needed.

## Procedure / Resolution

### 1. Connect to the Update Server

SSH to the update server and become root:

```bash
sudo su
```

Go to the Argus Agent directory:

```bash
cd /opt/argus-agent
```

The deployed directory should contain:

```text
argus_monitor.log
argus_monitor.py
requirements.txt
venv
```

### 2. Confirm the Python Virtual Environment

Argus Agent runs from a Python virtual environment under `/opt/argus-agent/venv`.

Confirm the virtual environment structure:

```bash
cd /opt/argus-agent/venv
ls
```

Expected entries:

```text
bin
include
lib
lib64
pyvenv.cfg
```

Confirm the virtual environment binaries:

```bash
cd /opt/argus-agent/venv/bin
ls
```

Expected entries include:

```text
activate
activate.csh
activate.fish
Activate.ps1
dotenv
pip
pip3
pip3.13
python
python3
python3.13
websockets
```

### 3. Confirm Installed Requirements

From `/opt/argus-agent`, check the requirements file:

```bash
cat requirements.txt
```

Expected contents:

```text
websockets>=13.0
python-dotenv>=1.0
```

### 4. Understand Required Configuration

Argus Agent reads its configuration from environment variables loaded by `python-dotenv`.

The required values are:

| Variable | Required | Purpose |
|---|---:|---|
| `ARGUS_URL` | Yes | Argus base URL. |
| `ARGUS_USERNAME` | Yes | Argus basic authentication username. |
| `ARGUS_PASSWORD` | Yes | Argus basic authentication password. |
| `OPENROUTER_KEY` | Yes | OpenRouter API key. |
| `TEAMS_WEBHOOK_URL` | Yes | Existing Teams webhook URL. |

Optional values:

| Variable | Required | Purpose |
|---|---:|---|
| `OPENROUTER_MODEL` | No | OpenRouter model ID. |
| `LOG_FILE` | No | Log file path. Defaults to `argus_monitor.log`. |
| `SCAN_INTERVAL` | No | Seconds between periodic full re-scans. Defaults to `3600`. |

Important: Argus credentials, the OpenRouter API key, and the Teams webhook URL are stored in LastPass.

### 5. Recommended OpenRouter Model

The default and recommended model is:

```text
openrouter/auto
```

This routes each request to a free model through OpenRouter.

Important: Because `openrouter/auto` can route to different free models, analysis quality may vary. Some routed models may be less capable and may produce weaker security summaries or risk assessments.

Future improvement options:

- Pin Argus Agent to a more stable free OpenRouter model.
- Connect Argus Agent to the local model endpoint on the Mac mini:

```text
http://lsen-macmini.byu.edu:1234
```

The Mac mini currently runs LM Studio and exposes an OpenAI-compatible API. However, the available context window may be too small for reliable Argus Agent analysis, depending on release note length and CVE context.

### 6. How Argus Agent Works

Argus Agent uses the following flow:

1. Loads environment configuration.
2. Validates required environment variables.
3. Validates that the configured OpenRouter model can be used.
4. Calls Argus to retrieve the service order from:

```text
/api/v1/service/order
```

5. Calls Argus for each service summary using:

```text
/api/v1/service/summary?service_id=<service_id>
```

6. Compares each service's deployed version against its latest version.
7. For outdated services, attempts to fetch GitHub release notes.
8. Sends release notes to OpenRouter to determine whether the update contains security-relevant changes.
9. Extracts CVE IDs when available.
10. Queries NVD for CVE details and CVSS data.
11. Sends the security findings and CVE details back to OpenRouter for a risk assessment.
12. Sends a Teams alert when security updates are identified.

The monitor also connects to the Argus WebSocket endpoint:

```text
/ws
```

It listens for Argus `VERSION` and `SERVICE` messages so it can react to changes without waiting for the next scheduled scan.

### 7. Scan Behavior

Argus Agent uses three scan paths:

1. Startup scan
   - Runs once when the script starts.
   - Processes all currently outdated services.

2. WebSocket listener
   - Watches Argus for version and service change messages.
   - Reconnects automatically if disconnected.

3. Periodic full re-scan
   - Runs every `SCAN_INTERVAL` seconds.
   - Defaults to `3600` seconds, or 1 hour.
   - Catches updates missed during WebSocket disconnects or network issues.

The script tracks alerted service/version pairs in memory. This prevents repeat alerts for the same service and latest version during a single process session.

Important: Restarting the script clears the in-memory alert tracking.

### 8. Make Small Code Changes

Simple functionality changes can be made with Codex or GitHub Copilot.

Typical workflow:

1. Edit and test the change locally.
2. Copy the updated file to the update server with `scp`.

Example:

```bash
scp argus_monitor.py smsmart@update.ls.byu.edu:/tmp/argus_monitor.py
```

3. SSH to the server.
4. Become root:

```bash
sudo su
```

5. Move the updated file into place:

```bash
mv /tmp/argus_monitor.py /opt/argus-agent/argus_monitor.py
```

6. Confirm ownership and permissions match the deployed service expectations.

TBD: The current production ownership and permission values for `/opt/argus-agent/argus_monitor.py` were not provided in the source notes.

Warning: Do not overwrite configuration or log files when redeploying code. Only copy the files that intentionally changed.

### 9. Review Logs

The application log is:

```text
/opt/argus-agent/argus_monitor.log
```

View the log:

```bash
tail -f /opt/argus-agent/argus_monitor.log
```

Successful startup entries should include:

```text
ARGUS SECURITY MONITOR starting
OpenRouter model validated
Running initial scan
Found <number> outdated service(s) out of <number> total
```

Successful Teams alert entries look like:

```text
Teams alert sent for <service_id> (HTTP <status_code>)
```

## Validation / Verification

After starting or updating Argus Agent, verify:

1. The process starts without missing environment variable errors.
2. The configured OpenRouter model validates successfully.
3. The initial scan runs.
4. The log shows the number of outdated services found.
5. WebSocket monitoring starts.
6. Teams alerts are sent when the agent identifies security-related updates.

Expected log examples:

```text
ARGUS SECURITY MONITOR starting
OpenRouter model validated
Running initial scan
Found <number> outdated service(s) out of <number> total
Initial scan complete, starting WebSocket listener + periodic re-scan
```

## Troubleshooting

### Missing Required Environment Variables

Log message:

```text
Missing required environment variables: <variable_list>
```

Likely causes:

- The environment file is missing.
- Required values are blank.
- The script is not running from the expected working directory.

Fix:

1. Retrieve the required values from LastPass.
2. Confirm the runtime environment includes all required variables.
3. Restart Argus Agent.

### OpenRouter Model Validation Fails

Log messages may include:

```text
Model '<model>' not found on OpenRouter
OpenRouter model validation failed
Exiting — fix the model configuration and restart
```

Likely causes:

- `OPENROUTER_MODEL` is invalid.
- `OPENROUTER_KEY` is invalid.
- OpenRouter is unavailable.

Fix:

1. Confirm the OpenRouter API key in LastPass.
2. Confirm the configured model value.
3. Use `openrouter/auto` unless there is a specific reason to pin another model.
4. Restart Argus Agent.

### Weak or Inconsistent AI Analysis

Likely cause:

- `openrouter/auto` may route to different free models with different quality levels.

Fix:

1. Review the alert manually before acting on it.
2. Consider pinning a more stable free OpenRouter model.
3. Consider testing the local LM Studio endpoint on the Mac mini:

```text
http://lsen-macmini.byu.edu:1234
```

Important: The Mac mini model context window may not be large enough for release notes with substantial content.

### No Release Notes Found

Log message:

```text
No GitHub release found for <owner>/<repo> version <version>
No release notes available for <service_id>, skipping analysis
```

Likely causes:

- The project does not publish GitHub Releases.
- The release tag does not match the expected version format.
- The Argus service URL does not resolve to the correct GitHub repository.

Fix:

1. Confirm the service source URL in Argus.
2. Add or update repository mappings in `GITHUB_OVERRIDES` inside `argus_monitor.py`.
3. Add or update tag mappings in `TAG_OVERRIDES` inside `argus_monitor.py`.
4. Redeploy the updated script to `/opt/argus-agent/argus_monitor.py`.

### Teams Alert Fails

Log message:

```text
Failed to send Teams alert for <service_id>: HTTP <status> <body>
```

or:

```text
Failed to send Teams alert for <service_id>: <error>
```

Likely causes:

- The Teams webhook URL is incorrect.
- The webhook changed.
- Network access to the webhook is blocked.

Fix:

1. Retrieve the webhook URL from LastPass.
2. Confirm the runtime configuration uses the correct value.
3. Restart Argus Agent.

### WebSocket Disconnects

Log message:

```text
WebSocket disconnected: <error>
Reconnecting in <seconds>s...
```

Expected behavior:

- Argus Agent reconnects automatically.
- Reconnect backoff increases up to 300 seconds.

Fix only if reconnects continue indefinitely:

1. Confirm Argus is reachable from `update.ls.byu.edu`.
2. Confirm Argus credentials are correct.
3. Confirm the Argus WebSocket endpoint is available.

### NVD Lookup Fails

Log message:

```text
NVD lookup failed for <CVE-ID>: <error>
```

Likely causes:

- NVD is temporarily unavailable.
- Network access to NVD is blocked.
- The CVE ID is not available in NVD.

Expected behavior:

- Argus Agent continues processing.
- Risk analysis uses whatever CVE details are available.

## Rollback / Backout

If a code change causes issues:

1. Restore the previous known-good `argus_monitor.py`.
2. Copy it back to:

```text
/opt/argus-agent/argus_monitor.py
```

3. Restart Argus Agent.
4. Watch the log:

```bash
tail -f /opt/argus-agent/argus_monitor.log
```

TBD: The exact command used to restart the production process was not provided in the source notes. If the agent is managed by systemd, use the appropriate `systemctl restart` command for the service name.

## References / Related Links

- Deployed directory:

```text
/opt/argus-agent
```

- Main script:

```text
/opt/argus-agent/argus_monitor.py
```

- Application log:

```text
/opt/argus-agent/argus_monitor.log
```

- Python virtual environment:

```text
/opt/argus-agent/venv
```

- Mac mini LM Studio endpoint:

```text
http://lsen-macmini.byu.edu:1234
```

## Notes / Maintenance

- Manage the deployed files as root on `update.ls.byu.edu`.
- Credentials and secrets are stored in LastPass.
- The OpenRouter default should be `openrouter/auto` unless a more stable model is selected later.
- Because `openrouter/auto` may choose lower-quality free models, important alerts should still be reviewed by an engineer.
- Simple changes can be made with Codex or GitHub Copilot and redeployed with `scp`.
- Do not overwrite secrets or logs during redeployment.

## Questions / Missing Info

- Exact production restart command or service manager name: TBD.
- Current production file ownership and permissions under `/opt/argus-agent`: TBD.
- Whether Argus Agent currently has a `.env` file on the update server or receives environment variables another way: TBD.
- Long-term decision on OpenRouter model versus local Mac mini LM Studio endpoint: TBD.
