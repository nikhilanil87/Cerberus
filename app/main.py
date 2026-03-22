"""
Secure Autonomous IT Remediation Agent — FastAPI Backend
Auth0 JWT + RBAC + Vertex AI (Gemini 2.5 Flash) + GitHub Issue creation via vault.py
"""

import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from auth_middleware import require_auth
from agent import detect_failure, generate_remediation_script
from security import scrubber
from vault import vault

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("remediation-agent")

app = FastAPI(
    title="Secure Autonomous IT Remediation Agent",
    description=(
        "Auth0 RBAC-gated AI agent for intelligent log analysis, "
        "auto-remediation, and autonomous GitHub Issue creation."
    ),
    version="1.0.0",
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("APP_SECRET_KEY", "dev-secret-change-in-prod"),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ────────────────────────────────────────────────────────────────────

class LogAnalysisRequest(BaseModel):
    log_text: str
    service_name: Optional[str] = "unknown"
    environment: Optional[str] = "production"
    # Optional: if provided AND user has a GitHub identity in Auth0,
    # the agent will automatically open a GitHub Issue with the full incident report.
    github_repo: Optional[str] = None   # format: "owner/repo-name"


class RemediationResponse(BaseModel):
    timestamp: str
    request_id: str
    actor: dict
    service_name: str
    environment: str
    failure_detected: bool
    failure_category: Optional[str]
    permission_level: str
    remediation: Optional[dict]
    github_issue: Optional[dict]    # populated if issue was created
    audit_trail: dict


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def health():
    return {
        "status":  "operational",
        "service": "Secure Autonomous IT Remediation Agent",
        "version": "1.0.0",
        "docs":    "/docs",
    }


@app.get("/me", tags=["Auth"])
async def me(actor: dict = Depends(require_auth)):
    """Returns authenticated user info and roles."""
    return {
        "sub":      actor["sub"],
        "email":    actor["email"],
        "name":     actor["name"],
        "roles":    actor["roles"],
        "is_admin": actor["is_admin"],
    }


@app.post("/logs/analyze", response_model=RemediationResponse, tags=["Agent"])
async def analyze_logs(
    request: LogAnalysisRequest,
    req: Request,
    actor: dict = Depends(require_auth),
):
    """
    Core agent endpoint — full autonomous pipeline:
    1. Scrub PII from log (security.py)
    2. Validate JWT + extract role (auth_middleware.py)
    3. Detect failure category (agent.py)
    4. Generate role-gated remediation via Vertex AI (agent.py)
    5. Optionally open a GitHub Issue via Auth0 identity token (vault.py)
    """
    request_id       = str(uuid.uuid4())[:8]
    permission_level = "admin" if actor["is_admin"] else "user"

    log.info(
        f"AUDIT | req={request_id} | actor={actor['email']} | "
        f"role={permission_level} | service={request.service_name}"
    )

    # ── Step 1: Scrub PII before anything touches the log ──
    clean_log = scrubber.scrub(request.log_text)
    log.info(f"PRIVACY | req={request_id} | log scrubbed")

    # ── Step 2: Detect failure ──
    failure = detect_failure(clean_log)

    if not failure["detected"]:
        return RemediationResponse(
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            actor={"sub": actor["sub"], "name": actor["name"], "roles": actor["roles"]},
            service_name=request.service_name,
            environment=request.environment,
            failure_detected=False,
            failure_category=None,
            permission_level=permission_level,
            remediation=None,
            github_issue=None,
            audit_trail={
                "action":    "no_action_required",
                "reason":    "No failure patterns detected in log",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    log.warning(
        f"FAILURE DETECTED | req={request_id} | "
        f"category={failure['category']} | evidence={failure['evidence']}"
    )

    # ── Step 3: Generate role-gated remediation via Vertex AI ──
    remediation = await generate_remediation_script(
        log_text=clean_log,
        permission_level=permission_level,
        failure=failure,
    )

    log.info(
        f"REMEDIATION | req={request_id} | issue={remediation.get('issue')} | "
        f"confidence={remediation.get('confidence')}% | "
        f"command={'yes' if remediation.get('command') else 'no'}"
    )

    # ── Step 4: Autonomous GitHub Issue creation via vault.py ──
    github_issue = None

    if request.github_repo:
        log.info(
            f"GITHUB | req={request_id} | fetching token for user {actor['sub']}"
        )
        github_token = await vault.get_github_token(actor["sub"])

        if github_token:
            github_issue = await vault.create_incident_issue(
                github_token=github_token,
                repo=request.github_repo,
                remediation=remediation,
                failure=failure,
                service_name=request.service_name,
                environment=request.environment,
                request_id=request_id,
                actor_name=actor["name"],
                permission_level=permission_level,
            )
            if github_issue:
                log.info(
                    f"GITHUB | req={request_id} | issue created: "
                    f"#{github_issue['number']} → {github_issue['url']}"
                )
            else:
                log.warning(f"GITHUB | req={request_id} | issue creation failed")
        else:
            log.warning(
                f"GITHUB | req={request_id} | no GitHub identity found for user — "
                f"user must log in via GitHub social connection in Auth0"
            )

    # ── Audit trail ──
    audit = {
        "action":            "remediation_generated",
        "permission_level":  permission_level,
        "command_authorized": bool(remediation.get("command")),
        "failure_category":  failure["category"],
        "github_issue_created": bool(github_issue),
        "actor_sub":         actor["sub"],
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }

    return RemediationResponse(
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_id=request_id,
        actor={"sub": actor["sub"], "name": actor["name"], "roles": actor["roles"]},
        service_name=request.service_name,
        environment=request.environment,
        failure_detected=True,
        failure_category=failure["category"],
        permission_level=permission_level,
        remediation=remediation,
        github_issue=github_issue,
        audit_trail=audit,
    )


@app.get("/demo/logs", tags=["Demo"])
async def get_demo_logs():
    """Pre-built demo scenarios for hackathon demonstration."""
    return {
        "scenarios": [
            {
                "id":           "nginx_crash",
                "name":         "Nginx Port Conflict",
                "service_name": "nginx",
                "log_text": (
                    "2024-01-15 03:42:17 [emerg] 1234#1234: bind() to 0.0.0.0:80 failed "
                    "(98: Address already in use)\n"
                    "2024-01-15 03:42:17 [emerg] 1234#1234: bind() to [::]:80 failed "
                    "(98: Address already in use)\n"
                    "2024-01-15 03:42:17 [emerg] 1234#1234: still could not bind\n"
                    "nginx: [emerg] bind() to 0.0.0.0:80 failed — exited with code 1"
                ),
            },
            {
                "id":           "disk_full",
                "name":         "Disk Space Exhausted",
                "service_name": "postgresql",
                "log_text": (
                    "2024-01-15 04:15:32 FATAL: could not write to file \"pg_wal/000000010000001\": "
                    "No space left on device\n"
                    "2024-01-15 04:15:32 LOG: database system is shut down\n"
                    "kernel: EXT4-fs error: ENOSPC — no free blocks available\n"
                    "systemd: postgresql.service: Main process exited, code=killed"
                ),
            },
            {
                "id":           "permission_denied",
                "name":         "Permission Denied on Socket",
                "service_name": "app-daemon",
                "log_text": (
                    "2024-01-15 05:01:44 ERROR: Failed to open /var/run/app/app.sock: "
                    "Permission denied\n"
                    "2024-01-15 05:01:44 CRITICAL: Cannot bind Unix socket — Operation not permitted\n"
                    "systemd: app-daemon.service: Control process exited with error code 1\n"
                    "systemd: app-daemon.service: Failed to start Application Daemon Service"
                ),
            },
        ]
    }


# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)