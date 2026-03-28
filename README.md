# Cerberus — Zero-Trust Autonomous IT Remediation Agent

> Built for the Auth0 "Authorized to Act" Hackathon & Google APAC AI Agent Challenge

**Live:** `https://remediation-agent-gzuqcqtiqa-uc.a.run.app` · **Docs:** `/docs` · **Repo:** `github.com/shubhayu-dev/Cerberus`

---

## The Problem

When a server crashes at 3 AM, an engineer wakes up, SSHs in, sifts through thousands of log lines, diagnoses the issue, and carefully types a fix. Every minute of downtime costs companies thousands of dollars.

The obvious solution is to let an AI read the logs and fix it. But here's the problem nobody talks about: **giving an autonomous LLM `sudo` access to your production servers is a security nightmare.** AI hallucinations exist. A confident but wrong bash command can bring down an entire infrastructure in seconds.

We needed a middle ground: an AI smart enough to diagnose production failures — but constrained by the same permission system your human engineers use.

That's Cerberus.

---

## What We Built

Cerberus is a Zero-Trust AI agent that monitors system logs, diagnoses failures using Vertex AI (Gemini 2.5 Flash), and generates role-gated remediation. Every response is filtered through a security pipeline before it reaches the client.

**The core innovation: the AI's behavior is controlled by Auth0 RBAC.**

Send the same failing log as two different roles — you get two completely different responses:

| | User (Junior Dev) | Admin (Senior Dev) |
|---|---|---|
| `command` | `null` — read-only diagnostics only | Executable bash command |
| `security_verdict` | Explains why no command | Explains blast radius |
| `risk_assessment` | 2/100 | 30–85/100 |
| `safe_alternatives` | 3 read-only diagnostic commands | 3 commands to verify before running |
| MFA | Not required | Required for critical severity |
| GitHub Issue | — | Auto-created via Token Vault |

---

## Security Architecture

```
Incoming log + JWT
        │
        ├─ 1. security.py          PII scrubber — emails, phones, API keys → [REDACTED]
        │                          Runs BEFORE AI sees anything
        │
        ├─ 2. auth_middleware.py   Auth0 JWT validation via JWKS (RS256)
        │                          Extracts role → sets is_admin flag
        │
        ├─ 3. agent.py             Vertex AI Gemini 2.5 Flash
        │                          Role-gated prompt → structured JSON response
        │                          Fields: security_verdict, blast_radius,
        │                                  risk_assessment, safe_alternatives
        │
        ├─ 4. zero_trust.py        AntiHallucinationFilter
        │                          Blacklist: 25+ destructive patterns (rm -rf, mkfs, etc.)
        │                          Whitelist: 40+ approved operations
        │                          Risk scoring: 0–100 → block if ≥ 80
        │
        ├─ 5. stepup.py            Auth0 Step-Up MFA
        │                          Critical severity + admin role → pause, demand MFA
        │                          Returns 403 with Auth0 authorize URL
        │
        ├─ 6. signing.py           RSA-PSS (SHA-256) payload signing
        │                          Approved commands signed with private key
        │                          Target server can verify before executing
        │
        └─ 7. vault.py             Auth0 Token Vault
                                   Fetches user's GitHub OAuth token from Auth0 identity
                                   Auto-creates structured GitHub Issue on their behalf
```

---

## The Auth0 Token Vault Integration

Most AI tools store third-party tokens in `.env` files or databases — one breach away from exposure.

Token Vault inverts this. When a user logs in via GitHub, Auth0 stores their OAuth token inside the Auth0 identity. When Cerberus needs to open a GitHub Issue on their behalf, `vault.py` retrieves it at runtime via the Management API. The token never touches our database, never sits in an env var, never gets logged.

```python
async def get_github_token(self, user_id: str) -> str | None:
    mgmt_token = await self.get_mgmt_token()
    url = f"{self.audience}users/{user_id}"
    headers = {"Authorization": f"Bearer {mgmt_token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        identities = response.json().get("identities", [])
        for identity in identities:
            if identity.get("provider") == "github":
                return identity.get("access_token")
    return None
```

**Progressive onboarding**: GitHub access is never requested upfront. The analysis runs first. Only after a failure is detected does Cerberus ask "Would you like me to open a GitHub Issue?" — with an explicit consent modal explaining exactly what `public_repo` scope means and what will never be accessed.

---

## Zero-Trust Execution Layer

### AntiHallucinationFilter (`zero_trust.py`)

Every command Gemini generates passes through this before reaching the client:

**Blacklist (25+ patterns):**
- `rm -rf` — recursive/forced deletion
- `mkfs` — filesystem formatting
- `dd of=` — raw disk writes  
- Reverse shells: `nc -e`, `bash -i`, `/dev/tcp/`
- `iptables -F` — firewall flush
- `chmod 777 /` — world-writable root
- Crypto miners: `xmrig`, `minerd`

**Whitelist (40+ operations):**
- `systemctl restart/start/stop`
- `journalctl --vacuum-size`
- `fuser -k` (port-specific only)
- `docker system prune -f`
- `find /tmp` (temp-dir scoped)

**Risk scoring:** If a command scores ≥ 80, it's nullified even if it passed the blacklist. The response includes `command_blocked: true` and the reason.

### Cryptographic Signing (`signing.py`)

Approved commands are signed with RSA-PSS (SHA-256). The signature covers: `command + request_id + actor_sub + timestamp` — preventing replay attacks. A target server can verify the payload before executing:

```python
signed_payload = {
    "command":    "fuser -k 80/tcp && systemctl restart nginx",
    "signature":  "base64-encoded RSA-PSS signature",
    "public_key": "PEM-encoded public key",
    "metadata":   { "request_id": "a7b3c2d1", "algorithm": "RSA-PSS-SHA256" }
}
```

### Step-Up MFA (`stepup.py`)

When severity is `critical` or the category is `disk_full`/`oom_kill`/`service_crash`, admin requests pause and the backend returns a 403 with a step-up Auth0 authorize URL. The frontend saves the pending request to `sessionStorage`, redirects to Auth0 MFA, then auto-retries after the user completes verification.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python 3.13) |
| AI Model | Google Vertex AI — Gemini 2.5 Flash |
| Auth & RBAC | Auth0 — JWT (RS256), RBAC roles, Token Vault, Step-Up MFA |
| Zero-Trust | Custom AntiHallucinationFilter + RSA-PSS signing |
| Deployment | Google Cloud Run (auto-scale to zero) |
| CI/CD | GitHub Actions + Workload Identity Federation |
| Secrets | GCP Secret Manager |
| PII Scrubbing | SovereignScrubber — emails, phones, API keys |
| Container | Docker (Python 3.13-slim, non-root) |

---

## Project Structure

```
Cerberus/
├── app/
│   ├── main.py              # FastAPI routes + web dashboard
│   ├── agent.py             # Vertex AI + Cerberus system prompt + failure detection
│   ├── auth_middleware.py   # Auth0 JWT validation, JWKS caching, role extraction
│   ├── security.py          # SovereignScrubber — PII redaction
│   ├── vault.py             # Auth0 Token Vault + GitHub Issue creator
│   ├── zero_trust.py        # AntiHallucinationFilter (blacklist + whitelist + risk score)
│   ├── signing.py           # RSA-PSS cryptographic payload signing
│   ├── stepup.py            # Auth0 step-up MFA for critical severity
│   └── templates/
│       ├── landing.html     # Login page
│       ├── dashboard.html   # Full agent UI (role badge, log form, audit trail)
│       └── callback.html    # Auth0 callback — extracts token, stores session
├── .github/workflows/
│   └── deploy.yml           # GitHub Actions → Cloud Run (Workload Identity)
├── Dockerfile               # Python 3.13-slim, non-root appuser
├── requirements.txt
├── deploy.sh                # One-time GCP setup: SA, IAM, secrets, Cloud Build
└── .env.example             # All required variables documented
```

---

## Running Locally

```bash
git clone https://github.com/shubhayu-dev/Cerberus
cd Cerberus

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill in AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET,
# AUTH0_AUDIENCE, MGMT_CLIENT_ID, MGMT_CLIENT_SECRET, APP_SECRET_KEY
# Leave GCP_PROJECT_ID blank to use mock responses (no Vertex AI needed)

cd app
uvicorn main:app --reload --port 8000
# Open http://localhost:8000
```

**No GCP project needed for local testing.** Leave `GCP_PROJECT_ID` blank and the agent uses mock responses — full Auth0 RBAC flow, step-up MFA, and Token Vault all work locally.

---

## Auth0 Setup

1. **Application** — Regular Web App. Callback URL: `http://localhost:8000/callback`
2. **API** — Create with identifier `https://remediation-agent/api`. Enable user and client access.
3. **Roles** — Create two roles named exactly `user` and `admin` (lowercase)
4. **Post Login Action** — adds roles to JWT:
   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const ns = 'https://remediation-agent/roles';
     if (event.authorization) {
       api.idToken.setCustomClaim(ns, event.authorization.roles);
       api.accessToken.setCustomClaim(ns, event.authorization.roles);
     }
   };
   ```
   Deploy it, then drag it into the Login flow under Actions → Flows.
5. **Management API M2M App** — Machine to Machine app, authorize against Auth0 Management API, grant `read:users` scope. Credentials go into `MGMT_CLIENT_ID` and `MGMT_CLIENT_SECRET`.
6. **GitHub Social Connection** — Enable so Auth0 stores GitHub tokens in user identities (required for Token Vault).

---

## Demo Scenarios

Three log strings that trigger the full pipeline:

**Nginx Port Conflict**
```
2024-01-15 03:42:17 [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)
nginx: exited with code 1
```

**PostgreSQL Disk Full** ← triggers MFA for admin
```
2024-01-15 04:15:32 FATAL: No space left on device
kernel: ENOSPC
postgresql.service: exited, code=killed
```

**App Daemon Permission Denied**
```
2024-01-15 05:01:44 ERROR: Failed to open /var/run/app/app.sock: Permission denied
app-daemon.service: Failed to start
```

Submit each log as `user` then `admin` to see the RBAC difference. For disk_full as admin, MFA step-up triggers.

---

## Why This Matters

I'm a student. I built this in about 4 days because the current state of "AI in DevOps" is binary — either useless (just explains the error) or dangerous (has root access to everything).

Cerberus is the middle ground: an AI that knows what broke AND knows its place in your org chart. Auth0 handles the identity layer. Gemini handles the reasoning. The AntiHallucinationFilter handles the paranoia. The result is something you could actually hand to a security team without them having a heart attack.

---

## What's Next

- Slack Token Vault — post incident alerts to the user's Slack using their stored token
- PagerDuty — auto-create incidents for critical severity failures
- Cloud Logging — connect directly to GCP logging instead of manual log submission  
- Rollback execution — admin can trigger the rollback command through a second MFA-gated confirmation

---

*Vertex AI · Auth0 Token Vault · Google Cloud Run · RSA-PSS · Zero-Trust · FastAPI · GitHub Actions*