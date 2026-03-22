"""
Remediation Agent — Intelligence Layer
Uses Vertex AI SDK (Gemini 2.5 Flash) with IAM auth.
No API keys — Cloud Run service account handles auth automatically.
Locally: uses Application Default Credentials (gcloud auth application-default login).
"""

import os
import re
import json
import logging
import asyncio
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger("remediation-agent")

GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
GCP_LOCATION   = os.getenv("GCP_LOCATION", "us-central1")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

_vertex_model = None

def _get_model():
    """
    Lazy-init Vertex AI model.
    - On Cloud Run: authenticates via the attached service account (no key needed).
    - Locally: uses `gcloud auth application-default login` credentials.
    """
    global _vertex_model
    if _vertex_model is not None:
        return _vertex_model

    if not GCP_PROJECT_ID:
        log.warning("GCP_PROJECT_ID not set — will use mock responses")
        return None

    try:
        import vertexai
        from vertexai.generative_models import GenerativeModel, GenerationConfig

        vertexai.init(project=GCP_PROJECT_ID, location=GCP_LOCATION)
        _vertex_model = GenerativeModel(
            GEMINI_MODEL,
            generation_config=GenerationConfig(
                temperature=0.2,
                max_output_tokens=1024,
                response_mime_type="application/json",
            ),
        )
        log.info(f"Vertex AI ready | project={GCP_PROJECT_ID} | model={GEMINI_MODEL}")
        return _vertex_model

    except Exception as e:
        log.warning(f"Vertex AI init failed ({e}) — using mock responses")
        return None


# ── Failure Detection ─────────────────────────────────────────────────────────

FAILURE_PATTERNS = {
    "port_conflict":     [r"bind.*address already in use", r"port.*in use", r"\[emerg\].*bind"],
    "disk_full":         [r"no space left on device", r"disk full", r"enospc"],
    "permission_denied": [r"permission denied", r"access denied", r"eacces", r"operation not permitted"],
    "oom_kill":          [r"out of memory", r"oom.kill", r"killed process"],
    "service_crash":     [r"segmentation fault", r"core dumped", r"exited with code [^0]", r"failed to start"],
    "connection_refused":[r"connection refused", r"econnrefused", r"failed to connect"],
    "ssl_error":         [r"ssl_error", r"certificate.*expired", r"ssl handshake failed"],
    "timeout":           [r"timed out", r"timeout", r"operation timed out"],
}

ERROR_KEYWORDS = ["error", "failed", "failure", "crash", "critical", "fatal",
                  "exception", "panic", "abort", "killed"]


def detect_failure(log_text: str) -> dict:
    lower = log_text.lower()

    for category, patterns in FAILURE_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, lower)
            if match:
                return {
                    "detected":  True,
                    "category":  category,
                    "pattern":   pattern,
                    "evidence":  match.group(0),
                    "exit_code": _extract_exit_code(lower),
                }

    for kw in ERROR_KEYWORDS:
        if kw in lower:
            return {
                "detected": True,
                "category": "generic_error",
                "pattern":  kw,
                "evidence": kw,
                "exit_code": _extract_exit_code(lower),
            }

    return {"detected": False, "category": None}


def _extract_exit_code(log_lower: str) -> int | None:
    match = re.search(r"exit(?:ed)?\s+(?:with\s+)?(?:code\s+)?(\d+)", log_lower)
    return int(match.group(1)) if match else None


# ── Prompt ────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an elite autonomous IT remediation agent embedded in a critical production system.

PERMISSION RULES (STRICTLY ENFORCED):
- permission_level = "user"  → Return explanation and SUGGESTED steps ONLY. NO bash commands. Set command to null.
- permission_level = "admin" → Return explanation AND executable bash commands.

You MUST acknowledge permission level in your reasoning field.

Return ONLY valid JSON with this exact schema:
{
  "issue": "<concise issue title>",
  "service": "<affected service/component>",
  "root_cause": "<specific technical root cause>",
  "reasoning": "<diagnostic reasoning — must state permission level>",
  "confidence": <integer 0-100>,
  "suggested_fix": "<human-readable fix steps>",
  "command": "<bash command if admin, else null>",
  "rollback": "<rollback command or procedure>",
  "severity": "<critical|high|medium|low>",
  "estimated_downtime": "<e.g. 2-5 minutes>"
}"""


def _build_prompt(log_text: str, failure: dict, permission_level: str) -> str:
    return f"""{SYSTEM_PROMPT}

SYSTEM LOG:
---
{log_text}
---

DETECTED FAILURE CATEGORY: {failure.get('category', 'unknown')}
EVIDENCE: {failure.get('evidence', 'n/a')}
EXIT CODE: {failure.get('exit_code', 'n/a')}
PERMISSION LEVEL: {permission_level}

Analyze this log and return remediation JSON."""


# ── Core AI Tool ──────────────────────────────────────────────────────────────

async def generate_remediation_script(
    log_text: str,
    permission_level: str,
    failure: dict,
) -> dict:
    """
    Calls Vertex AI Gemini 2.5 Flash with a role-gated prompt.
    Automatically falls back to mock responses in local dev.
    """
    model = _get_model()

    if model is None:
        return _mock_response(log_text, permission_level, failure)

    prompt = _build_prompt(log_text, failure, permission_level)

    try:
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: model.generate_content(prompt)
        )

        result = json.loads(response.text.strip())

        # Hard enforce: never return commands to non-admin roles
        if permission_level != "admin":
            result["command"] = None

        log.info(f"Vertex AI success | model={GEMINI_MODEL} | confidence={result.get('confidence')}%")
        return result

    except Exception as e:
        log.error(f"Vertex AI call failed: {e} — using mock fallback")
        return _mock_response(log_text, permission_level, failure)


# ── Mock Responses (local dev without GCP) ────────────────────────────────────

MOCK_RESPONSES = {
    "port_conflict": {
        "user": {
            "issue": "Nginx failed to start — Port 80 already in use",
            "service": "nginx",
            "root_cause": "A process (Apache or stale nginx) is occupying TCP port 80.",
            "reasoning": "Permission level: user. '[emerg] bind() failed (98)' is a definitive port collision. Explanation and steps only — no commands authorized.",
            "confidence": 92,
            "suggested_fix": "1. Find the process: lsof -i :80\n2. Stop it: sudo systemctl stop apache2\n3. Restart nginx: sudo systemctl start nginx",
            "command": None,
            "rollback": "sudo systemctl stop nginx && sudo systemctl start apache2",
            "severity": "critical",
            "estimated_downtime": "2–5 minutes",
        },
        "admin": {
            "issue": "Nginx failed to start — Port 80 already in use",
            "service": "nginx",
            "root_cause": "A process is occupying TCP port 80, preventing nginx from binding.",
            "reasoning": "Permission level: admin. Port collision confirmed via bind() error. Authorized to generate executable remediation commands.",
            "confidence": 92,
            "suggested_fix": "Kill the conflicting process on port 80 and restart nginx.",
            "command": "fuser -k 80/tcp && sleep 2 && systemctl restart nginx && systemctl status nginx",
            "rollback": "systemctl stop nginx && systemctl start apache2",
            "severity": "critical",
            "estimated_downtime": "< 30 seconds",
        },
    },
    "disk_full": {
        "user": {
            "issue": "Service crashed — Disk partition at 100% capacity",
            "service": "system storage",
            "root_cause": "Root filesystem has no space (ENOSPC) — write operations failing.",
            "reasoning": "Permission level: user. ENOSPC error detected. Investigation steps provided only.",
            "confidence": 97,
            "suggested_fix": "1. Check usage: df -h\n2. Find large files: du -sh /* 2>/dev/null | sort -rh | head -20\n3. Clear logs: sudo journalctl --vacuum-size=500M",
            "command": None,
            "rollback": "Restore from GCP snapshot: Console → Compute Engine → Snapshots",
            "severity": "critical",
            "estimated_downtime": "5–15 minutes",
        },
        "admin": {
            "issue": "Service crashed — Disk partition at 100% capacity",
            "service": "system storage",
            "root_cause": "Root filesystem has no space (ENOSPC).",
            "reasoning": "Permission level: admin. ENOSPC confirmed. Authorized to execute emergency disk cleanup.",
            "confidence": 97,
            "suggested_fix": "Execute automated cleanup of logs and temp files.",
            "command": "journalctl --vacuum-size=500M && find /tmp -mtime +1 -delete && docker system prune -f 2>/dev/null; df -h",
            "rollback": "gcloud compute disks snapshot DISK_NAME --snapshot-name pre-cleanup-$(date +%s)",
            "severity": "critical",
            "estimated_downtime": "1–3 minutes",
        },
    },
    "permission_denied": {
        "user": {
            "issue": "Service startup failed — Insufficient file permissions",
            "service": "application daemon",
            "root_cause": "Service account lacks permissions on a required file or directory.",
            "reasoning": "Permission level: user. 'Permission denied' on file path detected. Steps provided only.",
            "confidence": 88,
            "suggested_fix": "1. Check ownership: ls -la /path/to/file\n2. Check service user: systemctl show SERVICE --property=User\n3. Fix: sudo chown service_user /path/to/file",
            "command": None,
            "rollback": "sudo chown root:root /path/to/file",
            "severity": "high",
            "estimated_downtime": "3–8 minutes",
        },
        "admin": {
            "issue": "Service startup failed — Insufficient file permissions",
            "service": "application daemon",
            "root_cause": "Service account lacks permissions on a required resource.",
            "reasoning": "Permission level: admin. Permission denied confirmed. Authorized to execute chown/chmod and restart.",
            "confidence": 88,
            "suggested_fix": "Fix ownership and restart the service.",
            "command": "SERVICE_USER=$(systemctl show $SERVICE --property=User --value); chown $SERVICE_USER /var/log/app /var/run/app 2>/dev/null; chmod 755 /var/log/app /var/run/app 2>/dev/null; systemctl restart $SERVICE",
            "rollback": "systemctl stop $SERVICE && chown root:root /var/log/app /var/run/app",
            "severity": "high",
            "estimated_downtime": "< 2 minutes",
        },
    },
}


def _mock_response(log_text: str, permission_level: str, failure: dict) -> dict:
    category = failure.get("category", "generic_error")
    mock = MOCK_RESPONSES.get(category, {}).get(permission_level)
    if mock:
        return mock
    return {
        "issue": f"System failure — {category.replace('_', ' ').title()}",
        "service": "unknown",
        "root_cause": f"Pattern '{failure.get('evidence', 'n/a')}' matched category '{category}'.",
        "reasoning": f"Permission level: {permission_level}. {'Commands authorized.' if permission_level == 'admin' else 'Explanation only per user role.'}",
        "confidence": 70,
        "suggested_fix": "Review logs and consult the runbook for this service.",
        "command": "journalctl -xe --no-pager | tail -50" if permission_level == "admin" else None,
        "rollback": "Restore from last known good GCP snapshot.",
        "severity": "high",
        "estimated_downtime": "Unknown",
    }