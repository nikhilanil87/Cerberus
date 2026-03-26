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

SYSTEM_PROMPT = """You are Cerberus, a Zero-Trust Autonomous IT Remediation Agent.
Your mission is to diagnose system failures and generate precise remediations while enforcing a strict Human-in-the-Loop security protocol.

═══ IDENTITY-BASED PERMISSION RULES (NON-NEGOTIABLE) ═══

permission_level = "user" (Junior Dev):
  - Provide READ-ONLY diagnostic commands ONLY (df -h, ls -la, tail, ps, lsof, journalctl)
  - You are STRICTLY PROHIBITED from suggesting destructive commands (rm, kill, systemctl stop, truncate)
  - command field MUST be null
  - safe_alternatives must contain 3 safe read-only commands

permission_level = "admin" (Senior Dev):
  - You MAY suggest high-impact remediations if they are the only logical solution
  - ALWAYS prefer truncate or echo "" over rm for log files (preserves file descriptors)
  - NEVER use recursive force deletes (rm -rf /) on system directories
  - If severity=critical → set requires_mfa=true (triggers Auth0 Step-Up MFA)
  - Explain the blast_radius: what data/services are affected, is there a backup?

═══ ANTI-RAMPAGE PROTOCOL ═══
- Always prefer the LEAST destructive command that solves the problem
- If you suggest a restart, explain which dependency failed and the ripple effect
- Prefer truncate over rm for log files
- Prefer systemctl restart over kill -9
- Never suggest commands that affect /etc, /boot, /sys, /proc

═══ MANDATORY OUTPUT SCHEMA ═══
Return ONLY valid JSON. No markdown. No extra text.

{
  "issue": "<concise title — what broke>",
  "service": "<affected service/component>",
  "root_cause": "<specific technical root cause — not generic>",
  "reasoning": "<step-by-step diagnosis — MUST explicitly state permission level>",
  "confidence": <integer 0-100>,
  "severity": "<critical|high|medium|low>",
  "requires_mfa": <true if severity=critical and permission=admin, else false>,
  "security_verdict": "<2-3 sentences: WHY this specific command, what is the blast radius, what could go wrong>",
  "blast_radius": "<what data/services are affected if this command runs — be specific>",
  "risk_assessment": <integer 1-100 — potential for data loss or downtime>,
  "command": "<single bash command if admin, else null — prefer truncate/restart over rm/kill>",
  "safe_alternatives": ["<read-only diagnostic cmd 1>", "<read-only diagnostic cmd 2>", "<read-only diagnostic cmd 3>"],
  "suggested_fix": "<human-readable step-by-step fix>",
  "rollback": "<exact rollback command or procedure>",
  "estimated_downtime": "<e.g. 2-5 minutes>"
}"""


def _build_prompt(log_text: str, failure: dict, permission_level: str) -> str:
    role_label = "Senior Dev / Admin" if permission_level == "admin" else "Junior Dev / User"
    return f"""{SYSTEM_PROMPT}

═══ CURRENT REQUEST ═══
SYSTEM LOG:
---
{log_text}
---

DETECTED FAILURE CATEGORY: {failure.get('category', 'unknown')}
EVIDENCE: {failure.get('evidence', 'n/a')}
EXIT CODE: {failure.get('exit_code', 'n/a')}
PERMISSION LEVEL: {permission_level} ({role_label})

{"IMPORTANT: This is a USER request. command MUST be null. Provide read-only diagnostics only." if permission_level == "user" else "IMPORTANT: This is an ADMIN request. Provide the most targeted fix. Set requires_mfa=true if severity=critical."}

Analyze this log and return ONLY the JSON object."""


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
            "root_cause": "A process (Apache or stale nginx) is occupying TCP port 80, preventing binding.",
            "reasoning": "Permission level: user (Junior Dev). '[emerg] bind() failed (98)' is a definitive port collision signature. Read-only diagnostics only — no commands authorized.",
            "confidence": 92,
            "severity": "high",
            "requires_mfa": False,
            "security_verdict": "Read-only diagnostic only. No data will be modified. These commands safely identify the conflicting process with zero risk of service disruption.",
            "blast_radius": "None — diagnostics only. No changes to running processes or filesystem.",
            "risk_assessment": 5,
            "command": None,
            "safe_alternatives": ["lsof -i :80", "ss -tlnp | grep :80", "ps aux | grep nginx"],
            "suggested_fix": "1. Identify the process: lsof -i :80\n2. If safe to stop: sudo systemctl stop apache2\n3. Restart nginx: sudo systemctl start nginx",
            "rollback": "No changes made — nothing to roll back.",
            "estimated_downtime": "2–5 minutes",
        },
        "admin": {
            "issue": "Nginx failed to start — Port 80 already in use",
            "service": "nginx",
            "root_cause": "A process is occupying TCP port 80. fuser targets only that port — surgical precision.",
            "reasoning": "Permission level: admin (Senior Dev). Port collision confirmed via bind() error. Preferring fuser over kill -9 to target only the port-holding process. Authorized to generate executable remediation.",
            "confidence": 92,
            "severity": "high",
            "requires_mfa": False,
            "security_verdict": "fuser -k 80/tcp kills only the process holding port 80 — not a broad kill. Blast radius is limited to one process. If the conflicting service serves other traffic, those requests will drop. Run safe_alternatives first to verify.",
            "blast_radius": "One process killed. If that process is Apache serving other traffic on port 80, those connections will drop. Verify with safe_alternatives before running.",
            "risk_assessment": 30,
            "command": "fuser -k 80/tcp && sleep 2 && systemctl restart nginx && systemctl status nginx",
            "safe_alternatives": ["lsof -i :80", "ss -tlnp | grep :80", "systemctl status nginx"],
            "suggested_fix": "Kill the process holding port 80, then restart nginx.",
            "rollback": "systemctl stop nginx && systemctl start apache2",
            "estimated_downtime": "< 30 seconds",
        },
    },
    "disk_full": {
        "user": {
            "issue": "Disk at 100% — Service write failures (ENOSPC)",
            "service": "system storage",
            "root_cause": "Root filesystem has no free space. ENOSPC causes all write operations to fail, cascading into service crashes.",
            "reasoning": "Permission level: user (Junior Dev). ENOSPC kernel error confirmed. Providing read-only diagnostics to locate the largest consumers — no deletion authorized.",
            "confidence": 97,
            "severity": "critical",
            "requires_mfa": False,
            "security_verdict": "Read-only diagnostics only. No data will be deleted. These commands safely identify disk consumption without any risk.",
            "blast_radius": "None — diagnostics only. No filesystem changes.",
            "risk_assessment": 2,
            "command": None,
            "safe_alternatives": ["df -h", "du -sh /* 2>/dev/null | sort -rh | head -20", "journalctl --disk-usage"],
            "suggested_fix": "1. Check usage: df -h\n2. Find large files: du -sh /* 2>/dev/null | sort -rh | head -20\n3. Check journal: journalctl --disk-usage\n4. Report findings to an admin.",
            "rollback": "No changes made — nothing to roll back.",
            "estimated_downtime": "5–15 minutes",
        },
        "admin": {
            "issue": "Disk at 100% — Emergency cleanup required",
            "service": "system storage",
            "root_cause": "Root filesystem is full (ENOSPC). Journal logs and /tmp are safest targets for immediate reclamation.",
            "reasoning": "Permission level: admin (Senior Dev). ENOSPC confirmed. Using journalctl --vacuum (safe — trims old logs, preserves file descriptors) over rm. Severity=critical triggers MFA.",
            "confidence": 97,
            "severity": "critical",
            "requires_mfa": True,
            "security_verdict": "journalctl --vacuum-size=500M is preferred over rm because it maintains file descriptor integrity for running processes. Blast radius: ~500MB-2GB of log data removed. Verify journal size with safe_alternatives before running.",
            "blast_radius": "Up to 500MB of systemd journal logs removed. Files in /tmp older than 1 day deleted. Running services will NOT be interrupted. Docker layer cache cleared if Docker is installed.",
            "risk_assessment": 45,
            "command": "journalctl --vacuum-size=500M && find /tmp -mtime +1 -delete && docker system prune -f 2>/dev/null; df -h",
            "safe_alternatives": ["df -h", "journalctl --disk-usage", "du -sh /tmp"],
            "suggested_fix": "Vacuum journal logs, clean /tmp, prune Docker. Then verify with df -h.",
            "rollback": "gcloud compute disks snapshot DISK_NAME --snapshot-name pre-cleanup-$(date +%s)",
            "estimated_downtime": "1–3 minutes",
        },
    },
    "permission_denied": {
        "user": {
            "issue": "Service startup failed — File permission denied",
            "service": "application daemon",
            "root_cause": "The service account lacks read/write/execute permission on a required path.",
            "reasoning": "Permission level: user (Junior Dev). 'Permission denied' on socket/file path. Read-only diagnostics to identify ownership — no changes authorized.",
            "confidence": 88,
            "severity": "high",
            "requires_mfa": False,
            "security_verdict": "Read-only inspection of file ownership and service configuration. No filesystem changes. Zero risk.",
            "blast_radius": "None — diagnostics only.",
            "risk_assessment": 2,
            "command": None,
            "safe_alternatives": ["ls -la /var/run/app/", "systemctl show app-daemon --property=User", "id app-user"],
            "suggested_fix": "1. Check ownership: ls -la /var/run/app/\n2. Get service user: systemctl show SERVICE --property=User\n3. Report to admin with findings.",
            "rollback": "No changes made.",
            "estimated_downtime": "3–8 minutes",
        },
        "admin": {
            "issue": "Service startup failed — Ownership mismatch on socket directory",
            "service": "application daemon",
            "root_cause": "Service user does not own the socket directory. chown transfers ownership to the correct account.",
            "reasoning": "Permission level: admin (Senior Dev). Permission denied confirmed. Using chown (targeted) over chmod 777 (security risk). Blast radius limited to specific paths.",
            "confidence": 88,
            "severity": "high",
            "requires_mfa": False,
            "security_verdict": "chown on a specific non-system directory is low risk. Verify the correct service user with safe_alternatives before running to avoid chowning to the wrong account.",
            "blast_radius": "Ownership of /var/log/app and /var/run/app transferred to service user. No data deleted. If SERVICE variable is not set, the restart step fails harmlessly.",
            "risk_assessment": 20,
            "command": "SERVICE_USER=$(systemctl show $SERVICE --property=User --value); chown $SERVICE_USER /var/log/app /var/run/app 2>/dev/null; chmod 755 /var/log/app /var/run/app 2>/dev/null; systemctl restart $SERVICE",
            "safe_alternatives": ["ls -la /var/run/app/", "systemctl show $SERVICE --property=User", "id $(systemctl show $SERVICE --property=User --value)"],
            "suggested_fix": "Fix ownership of socket directory and restart the daemon.",
            "rollback": "systemctl stop $SERVICE && chown root:root /var/log/app /var/run/app",
            "estimated_downtime": "< 2 minutes",
        },
    },
}


def _mock_response(log_text: str, permission_level: str, failure: dict) -> dict:
    category = failure.get("category", "generic_error")
    mock = MOCK_RESPONSES.get(category, {}).get(permission_level)
    if mock:
        return mock
    is_admin = permission_level == "admin"
    return {
        "issue": f"System failure — {category.replace('_', ' ').title()}",
        "service": "unknown",
        "root_cause": f"Pattern '{failure.get('evidence', 'n/a')}' matched category '{category}'.",
        "reasoning": f"Permission level: {permission_level}. {'Authorized for commands.' if is_admin else 'Read-only diagnostics only per user role.'}",
        "confidence": 70,
        "severity": "high",
        "requires_mfa": False,
        "security_verdict": "Generic fallback response. Run safe_alternatives to gather more information before any remediation.",
        "blast_radius": "Unknown — insufficient log data to assess impact.",
        "risk_assessment": 50,
        "command": "journalctl -xe --no-pager | tail -50" if is_admin else None,
        "safe_alternatives": ["journalctl -xe | tail -100", "df -h", "ps aux | head -20"],
        "suggested_fix": "Review logs and consult the runbook for this service.",
        "rollback": "Restore from last known good GCP snapshot.",
        "estimated_downtime": "Unknown",
    }