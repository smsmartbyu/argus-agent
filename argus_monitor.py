"""Argus continuous monitor — security-aware update alerting."""

import asyncio
import base64
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

import websockets
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ARGUS_URL = os.getenv("ARGUS_URL")
ARGUS_USERNAME = os.getenv("ARGUS_USERNAME")
ARGUS_PASSWORD = os.getenv("ARGUS_PASSWORD")
OPENROUTER_KEY = os.getenv("OPENROUTER_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "step-3.5-flash:free")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # optional
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "3600"))  # seconds between periodic re-scans

# Manual GitHub repo overrides for services whose Argus URL is not a GitHub repo
GITHUB_OVERRIDES: dict[str, str] = {
    "jenkins": "https://github.com/jenkinsci/jenkins",
    "kubernetes": "https://github.com/k3s-io/k3s",
    "openappsec-reverseproxy": "https://github.com/openappsec/openappsec",
    "openappsec-localproxy": "https://github.com/openappsec/openappsec",
}

# Custom tag format overrides: service_id -> function(version) -> list of tag candidates
TAG_OVERRIDES: dict[str, callable] = {
    "jenkins": lambda v: [f"jenkins-{v}"],
    "kubernetes": lambda v: [f"v{v}", v],
}

REQUIRED_VARS = {
    "ARGUS_URL": ARGUS_URL,
    "ARGUS_USERNAME": ARGUS_USERNAME,
    "ARGUS_PASSWORD": ARGUS_PASSWORD,
    "OPENROUTER_KEY": OPENROUTER_KEY,
    "TEAMS_WEBHOOK_URL": TEAMS_WEBHOOK_URL,
}

LOG_FILE = os.getenv("LOG_FILE", "argus_monitor.log")

log = logging.getLogger("argus_monitor")
log.setLevel(logging.INFO)

# Console handler — concise timestamp
_console = logging.StreamHandler()
_console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
log.addHandler(_console)

# File handler — full timestamp for review
_file = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
log.addHandler(_file)

# Session-level duplicate prevention: (service_id, latest_version)
_alerted: set[tuple[str, str]] = set()

# NVD rate-limit tracking (5 requests per 30 seconds)
_nvd_timestamps: list[float] = []


# ===================================================================
# Group A — Argus core
# ===================================================================

def auth_header() -> str:
    token = base64.b64encode(f"{ARGUS_USERNAME}:{ARGUS_PASSWORD}".encode()).decode()
    return f"Basic {token}"


def api_get(path: str) -> dict:
    req = urllib.request.Request(
        f"{ARGUS_URL.rstrip('/')}{path}",
        headers={"Authorization": auth_header()},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def build_ws_url(http_url: str) -> str:
    parsed = urlparse(http_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.hostname}:{parsed.port}/ws"


def fetch_all_services() -> list[dict]:
    order = api_get("/api/v1/service/order")
    services = []
    for svc_id in order["order"]:
        try:
            services.append(api_get(f"/api/v1/service/summary?service_id={svc_id}"))
        except Exception as e:
            log.warning("Failed to fetch summary for %s: %s", svc_id, e)
    return services


def build_outdated_records(services: list[dict]) -> list[dict]:
    outdated = []
    for svc in services:
        status = svc.get("status", {})
        deployed = status.get("deployed_version")
        latest = status.get("latest_version")
        if not deployed or not latest or deployed == latest:
            continue
        record = {
            "service_id": svc["id"],
            "current_version": deployed,
            "latest_version": latest,
            "source_url": svc.get("url"),
            "service_type": svc.get("type"),
        }
        approved = status.get("approved_version")
        if approved:
            record["approved_version"] = approved
        outdated.append(record)
    return outdated


# ===================================================================
# Group B — GitHub release notes
# ===================================================================

def parse_github_repo(source_url: str | None, service_id: str = "") -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL. Falls back to GITHUB_OVERRIDES."""
    url = source_url
    if service_id in GITHUB_OVERRIDES:
        url = GITHUB_OVERRIDES[service_id]
    if not url:
        return None
    parsed = urlparse(url)
    if "github.com" not in (parsed.hostname or ""):
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None


def fetch_release_notes(
    owner: str, repo: str, version: str, service_id: str = ""
) -> str | None:
    """Fetch release notes body from GitHub for a given version tag."""
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    # Use custom tag candidates if configured, otherwise default pattern
    if service_id in TAG_OVERRIDES:
        tag_candidates = TAG_OVERRIDES[service_id](version)
    else:
        tag_candidates = [f"v{version}", version]

    for tag in tag_candidates:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                return data.get("body") or None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            if e.code == 403:
                log.warning("GitHub rate-limited fetching %s/%s tag %s", owner, repo, tag)
                return None
            log.warning("GitHub API error %d for %s/%s tag %s", e.code, owner, repo, tag)
            return None
        except Exception as e:
            log.warning("Failed to fetch GitHub release %s/%s tag %s: %s", owner, repo, tag, e)
            return None

    log.info("No GitHub release found for %s/%s version %s", owner, repo, version)
    return None


# ===================================================================
# Group C — LLM analysis (OpenRouter)
# ===================================================================

def validate_openrouter_model() -> bool:
    """Check that the configured model exists on OpenRouter. Sends Teams alert if not."""
    payload = json.dumps({
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
    }).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            json.loads(resp.read())
        log.info("OpenRouter model validated: %s", OPENROUTER_MODEL)
        return True
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:300]
        except Exception:
            pass
        if e.code == 400 and "not a valid model" in body:
            log.error("Model '%s' not found on OpenRouter", OPENROUTER_MODEL)
            send_teams_notification(
                "Argus Monitor: Model Not Found",
                f"The configured OpenRouter model **{OPENROUTER_MODEL}** is not available. "
                f"The monitor cannot perform security analysis until a valid model is set "
                f"in the OPENROUTER_MODEL environment variable and the service is restarted.",
            )
            return False
        log.error("OpenRouter model validation failed: HTTP %d — %s", e.code, body)
        send_teams_notification(
            "Argus Monitor: LLM Error",
            f"Failed to validate OpenRouter model **{OPENROUTER_MODEL}**: HTTP {e.code}. "
            f"Check the OPENROUTER_KEY and OPENROUTER_MODEL environment variables.",
        )
        return False
    except Exception as e:
        log.error("OpenRouter model validation failed: %s", e)
        return False


def call_openrouter(messages: list[dict]) -> str:
    """Call OpenRouter chat completions API and return the assistant message."""
    payload = json.dumps({
        "model": OPENROUTER_MODEL,
        "messages": messages,
    }).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _parse_llm_json(text: str) -> dict | None:
    """Try to parse JSON from LLM response, stripping markdown fences if present."""
    # Strip code fences
    stripped = re.sub(r"```(?:json)?\s*", "", text)
    stripped = stripped.replace("```", "").strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def analyze_security_content(release_notes: str) -> dict:
    """LLM call 1: identify security content and extract CVE IDs."""
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security analyst. Analyze software release notes and "
                "identify security-related changes. Respond ONLY with valid JSON, "
                "no markdown fencing."
            ),
        },
        {
            "role": "user",
            "content": (
                "Analyze these release notes for security content. Identify:\n"
                "1. Whether it contains security updates (boolean)\n"
                "2. Any CVE IDs mentioned (list of strings)\n"
                "3. A brief summary of security-relevant changes\n"
                "4. A brief summary of non-security changes\n\n"
                f"Release notes:\n{release_notes}\n\n"
                "Respond with this exact JSON structure:\n"
                '{\n'
                '  "has_security_updates": true/false,\n'
                '  "cve_ids": ["CVE-XXXX-YYYY"],\n'
                '  "security_summary": "...",\n'
                '  "non_security_summary": "..."\n'
                '}'
            ),
        },
    ]
    try:
        raw = call_openrouter(messages)
        parsed = _parse_llm_json(raw)
        if parsed and "has_security_updates" in parsed:
            return parsed
        log.warning("LLM returned unparseable security analysis, using fallback")
    except Exception as e:
        log.warning("OpenRouter call failed for security analysis: %s", e)

    return {
        "has_security_updates": False,
        "cve_ids": [],
        "security_summary": "Automated analysis unavailable",
        "non_security_summary": "Automated analysis unavailable",
    }


def analyze_risk(
    record: dict,
    security_analysis: dict,
    cve_details: list[dict],
) -> dict:
    """LLM call 2: risk assessment with NVD-enriched CVE data."""
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security risk analyst for infrastructure services. "
                "Assess update priority based on security findings. "
                "Respond ONLY with valid JSON, no markdown fencing."
            ),
        },
        {
            "role": "user",
            "content": (
                "Assess the update priority for this service:\n\n"
                f"Service: {record['service_id']}\n"
                f"Current version: {record['current_version']}\n"
                f"Latest version: {record['latest_version']}\n\n"
                f"Security analysis of release notes:\n{json.dumps(security_analysis, indent=2)}\n\n"
                f"CVE details from NVD:\n{json.dumps(cve_details, indent=2)}\n\n"
                "Provide a risk assessment with this JSON structure:\n"
                '{\n'
                '  "priority": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
                '  "risk_summary": "2-3 sentence risk assessment",\n'
                '  "recommendation": "Specific action recommendation",\n'
                '  "requires_immediate_attention": true/false\n'
                '}'
            ),
        },
    ]
    try:
        raw = call_openrouter(messages)
        parsed = _parse_llm_json(raw)
        if parsed and "priority" in parsed:
            return parsed
        log.warning("LLM returned unparseable risk analysis, using fallback")
    except Exception as e:
        log.warning("OpenRouter call failed for risk analysis: %s", e)

    return {
        "priority": "UNKNOWN",
        "risk_summary": "Automated risk analysis unavailable",
        "recommendation": "Manual review recommended",
        "requires_immediate_attention": False,
    }


# ===================================================================
# Group D — NVD CVE enrichment
# ===================================================================

def _nvd_rate_limit():
    """Block until we're within the NVD rate limit (5 req / 30s)."""
    global _nvd_timestamps
    now = time.time()
    _nvd_timestamps = [t for t in _nvd_timestamps if now - t < 30]
    if len(_nvd_timestamps) >= 5:
        wait = 30 - (now - _nvd_timestamps[0]) + 0.5
        if wait > 0:
            log.info("NVD rate limit: waiting %.1fs", wait)
            time.sleep(wait)
    _nvd_timestamps.append(time.time())


def fetch_cve_details(cve_id: str) -> dict | None:
    """Fetch a single CVE from NVD and extract key fields."""
    _nvd_rate_limit()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.warning("NVD lookup failed for %s: %s", cve_id, e)
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})
    desc_list = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in desc_list if d.get("lang") == "en"),
        "No description available",
    )

    metrics = cve.get("metrics", {})
    base_score = None
    severity = None
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss = metric_list[0].get("cvssData", {})
            base_score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
            break

    return {
        "cve_id": cve_id,
        "description": description,
        "base_score": base_score,
        "severity": severity,
    }


def enrich_cves(cve_ids: list[str]) -> list[dict]:
    """Fetch NVD details for all CVE IDs, respecting rate limits."""
    results = []
    for cve_id in cve_ids:
        detail = fetch_cve_details(cve_id)
        if detail:
            results.append(detail)
    return results


# ===================================================================
# Group E — Teams webhook (Power Automate)
# ===================================================================

def send_teams_notification(title: str, message: str) -> bool:
    """Send a simple text notification to Teams (for system alerts, not service alerts)."""
    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title},
            {"type": "TextBlock", "text": message, "wrap": True},
        ],
    }
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            log.info("Teams notification sent: %s (HTTP %d)", title, resp.status)
            return True
    except Exception as e:
        log.error("Failed to send Teams notification '%s': %s", title, e)
        return False


def _build_adaptive_card(
    record: dict,
    security_analysis: dict,
    cve_details: list[dict],
    risk_analysis: dict,
) -> dict:
    """Build an Adaptive Card payload for Power Automate / Teams."""
    priority = risk_analysis.get("priority", "UNKNOWN")
    priority_colors = {
        "CRITICAL": "attention",
        "HIGH": "attention",
        "MEDIUM": "warning",
        "LOW": "good",
    }
    color = priority_colors.get(priority, "default")

    body: list[dict] = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": f"Security Update Alert: {record['service_id']}",
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "Service", "value": record["service_id"]},
                {"title": "Current Version", "value": record["current_version"]},
                {"title": "Latest Version", "value": record["latest_version"]},
                {"title": "Priority", "value": priority},
            ],
        },
        {
            "type": "TextBlock",
            "text": f"**Risk Assessment:** {risk_analysis.get('risk_summary', 'N/A')}",
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": f"**Recommendation:** {risk_analysis.get('recommendation', 'N/A')}",
            "wrap": True,
        },
    ]

    # Add CVE details if present
    if cve_details:
        cve_lines = []
        for cve in cve_details:
            score = cve.get("base_score", "N/A")
            sev = cve.get("severity", "N/A")
            cve_lines.append(f"- **{cve['cve_id']}** (CVSS: {score}, {sev}): {cve.get('description', 'N/A')[:150]}")
        body.append({
            "type": "TextBlock",
            "text": "**CVE Details:**\n" + "\n".join(cve_lines),
            "wrap": True,
        })

    # Security summary
    sec_summary = security_analysis.get("security_summary", "")
    if sec_summary:
        body.append({
            "type": "TextBlock",
            "text": f"**Security Summary:** {sec_summary}",
            "wrap": True,
        })

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body,
    }

    # Add action button if source URL available
    source_url = record.get("source_url")
    if source_url:
        card["actions"] = [
            {"type": "Action.OpenUrl", "title": "View Source", "url": source_url}
        ]

    return card


def send_teams_alert(
    record: dict,
    security_analysis: dict,
    cve_details: list[dict],
    risk_analysis: dict,
) -> bool:
    """POST an Adaptive Card to the Power Automate Teams webhook."""
    card = _build_adaptive_card(record, security_analysis, cve_details, risk_analysis)
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": card,
            }
        ],
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        TEAMS_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            log.info(
                "Teams alert sent for %s (HTTP %d)", record["service_id"], resp.status
            )
            return True
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:300]
        except Exception:
            pass
        log.error("Failed to send Teams alert for %s: HTTP %d %s", record["service_id"], e.code, body)
        return False
    except Exception as e:
        log.error("Failed to send Teams alert for %s: %s", record["service_id"], e)
        return False


# ===================================================================
# Group F — Orchestration
# ===================================================================

def process_outdated_service(record: dict) -> None:
    """Full pipeline: GitHub → LLM1 → NVD → LLM2 → Teams."""
    svc = record["service_id"]
    latest = record["latest_version"]

    if (svc, latest) in _alerted:
        log.info("Already alerted for %s %s, skipping", svc, latest)
        return

    log.info("Processing %s: %s → %s", svc, record["current_version"], latest)

    # Step 1: Fetch GitHub release notes
    repo_info = parse_github_repo(record.get("source_url"), service_id=svc)
    release_notes = None
    if repo_info:
        owner, repo = repo_info
        log.info("Fetching release notes for %s/%s tag %s", owner, repo, latest)
        release_notes = fetch_release_notes(owner, repo, latest, service_id=svc)

    if not release_notes:
        log.info("No release notes available for %s, skipping analysis", svc)
        return

    log.info("Analyzing security content for %s...", svc)

    # Step 2: LLM call 1 — security identification
    security_analysis = analyze_security_content(release_notes)
    log.info(
        "%s security_updates=%s, cves=%s",
        svc,
        security_analysis.get("has_security_updates"),
        security_analysis.get("cve_ids", []),
    )

    # Step 3: NVD enrichment
    cve_details = []
    cve_ids = security_analysis.get("cve_ids", [])
    if cve_ids:
        log.info("Enriching %d CVE(s) from NVD for %s", len(cve_ids), svc)
        cve_details = enrich_cves(cve_ids)

    # Step 4: LLM call 2 — risk analysis
    log.info("Running risk analysis for %s...", svc)
    risk_analysis = analyze_risk(record, security_analysis, cve_details)
    log.info("%s priority=%s", svc, risk_analysis.get("priority"))

    # Step 5: Teams alert (always send for now)
    if security_analysis.get("has_security_updates"):
        success = send_teams_alert(record, security_analysis, cve_details, risk_analysis)
        if success:
            _alerted.add((svc, latest))
    else:
        log.info("%s has no security updates, skipping Teams alert", svc)
        _alerted.add((svc, latest))


def _check_repo_coverage(services: list[dict]) -> None:
    """Warn about services that track GitHub releases but have no resolvable repo URL."""
    missing = []
    for svc in services:
        svc_id = svc["id"]
        if svc.get("active") is False:
            continue
        if svc.get("type") != "github" and svc_id not in GITHUB_OVERRIDES:
            if not parse_github_repo(svc.get("url"), service_id=svc_id):
                missing.append(f"{svc_id} (url={svc.get('url', 'none')})")
            continue
        if not parse_github_repo(svc.get("url"), service_id=svc_id):
            missing.append(f"{svc_id} (url={svc.get('url', 'none')})")
    if missing:
        log.warning(
            "These services have no resolvable GitHub repo — release notes "
            "cannot be fetched. Add them to GITHUB_OVERRIDES:\n  %s",
            "\n  ".join(missing),
        )


async def initial_scan() -> None:
    """Fetch all services, identify outdated, process each."""
    log.info("Running initial scan...")
    loop = asyncio.get_event_loop()
    services = await loop.run_in_executor(None, fetch_all_services)
    _check_repo_coverage(services)
    outdated = build_outdated_records(services)
    log.info("Found %d outdated service(s) out of %d total", len(outdated), len(services))

    for record in outdated:
        await loop.run_in_executor(None, process_outdated_service, record)


def _extract_service_id(item: dict) -> str | None:
    """Pull a service ID from a WS message, handling various structures."""
    service_data = item.get("service_data")
    if isinstance(service_data, dict):
        svc_id = service_data.get("id")
        if svc_id:
            return svc_id
    return item.get("id") or item.get("target") or item.get("sub_type")


async def _handle_ws_item(item: dict) -> None:
    """Process a single WS message item."""
    msg_type = item.get("type")

    if msg_type == "SERVICE":
        # A new service was added or modified — re-scan to pick it up
        svc_id = _extract_service_id(item)
        log.info("WS SERVICE change detected%s — triggering re-scan",
                 f" ({svc_id})" if svc_id else "")
        await initial_scan()
        return

    if msg_type != "VERSION":
        return

    svc_id = _extract_service_id(item)
    if not svc_id:
        log.warning("VERSION message with no service ID: %s", json.dumps(item)[:300])
        return

    log.info("WS VERSION update for %s", svc_id)

    loop = asyncio.get_event_loop()
    try:
        summary = await loop.run_in_executor(
            None, api_get, f"/api/v1/service/summary?service_id={svc_id}"
        )
    except Exception as e:
        log.warning("Failed to fetch summary for %s: %s", svc_id, e)
        return

    records = build_outdated_records([summary])
    if records:
        await loop.run_in_executor(None, process_outdated_service, records[0])


async def ws_listener() -> None:
    """Connect to Argus WebSocket and process VERSION updates."""
    ws_url = build_ws_url(ARGUS_URL)
    auth = auth_header()
    backoff = 5

    while True:
        try:
            log.info("Connecting to WebSocket %s", ws_url)
            async with websockets.connect(
                ws_url,
                additional_headers={"Authorization": auth},
            ) as ws:
                log.info("WebSocket connected, listening for updates...")
                backoff = 5  # reset on successful connect

                async for raw_msg in ws:
                    try:
                        msg = json.loads(raw_msg)
                    except json.JSONDecodeError:
                        log.warning("Non-JSON WS message: %s", raw_msg[:200])
                        continue

                    # Handle both single messages and batches
                    items = msg if isinstance(msg, list) else [msg]
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        await _handle_ws_item(item)

        except websockets.exceptions.InvalidStatus as e:
            log.error("WebSocket rejected (HTTP %d)", e.response.status_code)
        except (OSError, websockets.exceptions.ConnectionClosed) as e:
            log.warning("WebSocket disconnected: %s", e)
        except Exception as e:
            log.error("WebSocket unexpected error: %s", e)

        log.info("Reconnecting in %ds...", backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 300)


async def periodic_scan() -> None:
    """Re-scan all services on a fixed interval to catch anything the WS missed."""
    while True:
        await asyncio.sleep(SCAN_INTERVAL)
        log.info("Periodic re-scan triggered (every %ds)", SCAN_INTERVAL)
        await initial_scan()


async def main() -> None:
    # Validate required env vars
    missing = [k for k, v in REQUIRED_VARS.items() if not v]
    if missing:
        log.error("Missing required environment variables: %s", ", ".join(missing))
        return

    log.info("=" * 50)
    log.info("ARGUS SECURITY MONITOR starting")
    log.info("Server:         %s", ARGUS_URL)
    log.info("Model:          %s", OPENROUTER_MODEL)
    log.info("Log:            %s", LOG_FILE)
    log.info("Re-scan every:  %ds", SCAN_INTERVAL)
    log.info("=" * 50)

    # Validate model before doing any work
    model_ok = await asyncio.get_event_loop().run_in_executor(None, validate_openrouter_model)
    if not model_ok:
        log.error("Exiting — fix the model configuration and restart")
        return

    await initial_scan()

    log.info("Initial scan complete, starting WebSocket listener + periodic re-scan...")
    await asyncio.gather(
        ws_listener(),
        periodic_scan(),
    )


if __name__ == "__main__":
    asyncio.run(main())
