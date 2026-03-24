"""
Cerberus — Secure Autonomous IT Remediation Agent
FastAPI backend + Web Dashboard
Auth0 RBAC + Vertex AI (Gemini 2.5 Flash) + Token Vault (GitHub)
"""

import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from auth_middleware import require_auth, _decode_token, extract_roles
from agent import detect_failure, generate_remediation_script
from security import scrubber
from vault import vault

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("cerberus")

AUTH0_DOMAIN    = os.getenv("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_AUDIENCE  = os.getenv("AUTH0_AUDIENCE")
AUTH0_CALLBACK  = os.getenv("AUTH0_CALLBACK_URL", "http://localhost:8000/callback")

TEMPLATES = Path(__file__).parent / "templates"

app = FastAPI(
    title="Cerberus — Secure Autonomous IT Remediation Agent",
    description="Auth0 RBAC-gated AI agent for intelligent log analysis and auto-remediation",
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


# ── Helper ────────────────────────────────────────────────────────────────────

def read_template(name: str) -> str:
    return (TEMPLATES / name).read_text()


def get_session_user(request: Request) -> dict | None:
    return request.session.get("user")


# ── Web Routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, tags=["Web"])
async def landing(request: Request):
    """Landing page — shows login button."""
    user = get_session_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(read_template("landing.html"))


@app.get("/login", tags=["Web"])
async def login():
    """Redirects directly to GitHub login via Auth0 social connection."""
    from urllib.parse import urlencode
    params = urlencode({
        "response_type": "token",
        "client_id":     AUTH0_CLIENT_ID,
        "redirect_uri":  AUTH0_CALLBACK,
        "audience":      AUTH0_AUDIENCE,
        "scope":         "openid profile email",
        "connection":    "github",   # skip Auth0 login page, go straight to GitHub
    })
    return RedirectResponse(url=f"https://{AUTH0_DOMAIN}/authorize?{params}")


@app.get("/callback", response_class=HTMLResponse, tags=["Web"])
async def callback():
    """Serves callback page — JS extracts token from URL hash and POSTs it."""
    return HTMLResponse(read_template("callback.html"))


@app.post("/auth/store-token", tags=["Web"])
async def store_token(request: Request):
    """
    Receives token from callback JS, validates it, stores user in session.
    This is how we convert the implicit flow token into a server session.
    """
    body = await request.json()
    token = body.get("access_token")
    if not token:
        raise HTTPException(status_code=400, detail="No token provided")

    try:
        payload = _decode_token(token)
        roles   = extract_roles(payload)
        user    = {
            "sub":      payload.get("sub"),
            "email":    payload.get("email", "unknown"),
            "name":     payload.get("name", "unknown"),
            "roles":    roles,
            "is_admin": "admin" in roles,
            "token":    token,
        }
        request.session["user"] = user
        log.info(f"SESSION | user={user['sub']} | role={'admin' if user['is_admin'] else 'user'}")
        return {"ok": True}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/dashboard", response_class=HTMLResponse, tags=["Web"])
async def dashboard(request: Request):
    """Main dashboard — requires login."""
    user = get_session_user(request)
    if not user:
        return RedirectResponse(url="/login")
    return HTMLResponse(read_template("dashboard.html"))


@app.get("/logout", tags=["Web"])
async def logout(request: Request):
    """Clears session and logs out from Auth0."""
    from urllib.parse import urlencode
    request.session.clear()
    params = urlencode({
        "returnTo":  "https://remediation-agent-gzuqcqtiqa-uc.a.run.app",
        "client_id": AUTH0_CLIENT_ID,
    })
    return RedirectResponse(url=f"https://{AUTH0_DOMAIN}/v2/logout?{params}")


# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "operational", "service": "Cerberus", "version": "1.0.0", "docs": "/docs"}


@app.get("/me", tags=["Auth"])
async def me(request: Request):
    """
    Returns current user info.
    Works for both session-based (dashboard) and JWT-based (API) requests.
    """
    # Try session first (dashboard users)
    user = get_session_user(request)
    if user:
        return {
            "sub":      user["sub"],
            "email":    user["email"],
            "name":     user["name"],
            "roles":    user["roles"],
            "is_admin": user["is_admin"],
        }
    # Fall back to JWT header (API users)
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi import Security
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        payload = _decode_token(token)
        roles   = extract_roles(payload)
        return {
            "sub":      payload.get("sub"),
            "email":    payload.get("email", "unknown"),
            "name":     payload.get("name", "unknown"),
            "roles":    roles,
            "is_admin": "admin" in roles,
        }
    raise HTTPException(status_code=401, detail="Not authenticated")


class LogAnalysisRequest(BaseModel):
    log_text:     str
    service_name: Optional[str] = "unknown"
    environment:  Optional[str] = "production"
    github_repo:  Optional[str] = None


class RemediationResponse(BaseModel):
    timestamp:        str
    request_id:       str
    actor:            dict
    service_name:     str
    environment:      str
    failure_detected: bool
    failure_category: Optional[str]
    permission_level: str
    remediation:      Optional[dict]
    github_issue:     Optional[dict]
    audit_trail:      dict


@app.post("/logs/analyze", response_model=RemediationResponse, tags=["Agent"])
async def analyze_logs(request_body: LogAnalysisRequest, request: Request):
    """
    Core agent endpoint.
    Accepts both session-based auth (dashboard) and JWT Bearer tokens (API).
    """
    request_id = str(uuid.uuid4())[:8]

    # Get actor — session or JWT
    actor = get_session_user(request)
    if not actor:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            payload = _decode_token(token)
            roles   = extract_roles(payload)
            actor   = {
                "sub":      payload.get("sub"),
                "email":    payload.get("email", "unknown"),
                "name":     payload.get("name", "unknown"),
                "roles":    roles,
                "is_admin": "admin" in roles,
            }
        else:
            raise HTTPException(status_code=401, detail="Not authenticated")

    permission_level = "admin" if actor["is_admin"] else "user"

    log.info(f"AUDIT | req={request_id} | actor={actor['email']} | role={permission_level} | service={request_body.service_name}")

    # Step 1: Scrub PII
    clean_log = scrubber.scrub(request_body.log_text)
    log.info(f"PRIVACY | req={request_id} | log scrubbed")

    # Step 2: Detect failure
    failure = detect_failure(clean_log)

    if not failure["detected"]:
        return RemediationResponse(
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            actor={"sub": actor["sub"], "name": actor["name"], "roles": actor["roles"]},
            service_name=request_body.service_name,
            environment=request_body.environment,
            failure_detected=False, failure_category=None,
            permission_level=permission_level,
            remediation=None, github_issue=None,
            audit_trail={
                "action": "no_action_required",
                "reason": "No failure patterns detected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    log.warning(f"FAILURE | req={request_id} | category={failure['category']}")

    # Step 3: Vertex AI remediation
    remediation = await generate_remediation_script(
        log_text=clean_log,
        permission_level=permission_level,
        failure=failure,
    )

    # Step 4: GitHub issue via Token Vault
    github_issue = None
    if request_body.github_repo:
        github_token = await vault.get_github_token(actor["sub"])
        if github_token:
            github_issue = await vault.create_incident_issue(
                github_token=github_token,
                repo=request_body.github_repo,
                remediation=remediation,
                failure=failure,
                service_name=request_body.service_name,
                environment=request_body.environment,
                request_id=request_id,
                actor_name=actor["name"],
                permission_level=permission_level,
            )

    audit = {
        "action": "remediation_generated",
        "permission_level": permission_level,
        "command_authorized": bool(remediation.get("command")),
        "failure_category": failure["category"],
        "github_issue_created": bool(github_issue),
        "actor_sub": actor["sub"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return RemediationResponse(
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_id=request_id,
        actor={"sub": actor["sub"], "name": actor["name"], "roles": actor["roles"]},
        service_name=request_body.service_name,
        environment=request_body.environment,
        failure_detected=True,
        failure_category=failure["category"],
        permission_level=permission_level,
        remediation=remediation,
        github_issue=github_issue,
        audit_trail=audit,
    )


@app.get("/demo/logs", tags=["Demo"])
async def get_demo_logs():
    return {"scenarios": [
        {"id": "nginx_crash", "name": "Nginx Port Conflict", "service_name": "nginx",
         "log_text": "2024-01-15 03:42:17 [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)\nnginx: exited with code 1"},
        {"id": "disk_full", "name": "Disk Space Exhausted", "service_name": "postgresql",
         "log_text": "2024-01-15 04:15:32 FATAL: No space left on device\nkernel: ENOSPC\npostgresql.service: exited, code=killed"},
        {"id": "permission_denied", "name": "Permission Denied", "service_name": "app-daemon",
         "log_text": "2024-01-15 05:01:44 ERROR: Failed to open /var/run/app/app.sock: Permission denied\napp-daemon.service: Failed to start"},
    ]}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail, "status_code": exc.status_code})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)