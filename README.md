# Cerberus — Secure Autonomous IT Remediation Agent

> Built for the Auth0 "Authorized to Act" Hackathon and Google APAC AI Agent Challenge

---

## The Problem

In modern DevOps, the biggest bottleneck isn't detecting an error — it's the human response time.

When a server goes down at 3 AM, an engineer has to wake up, SSH into the machine, sift through thousands of lines of logs, diagnose the issue, and carefully type out a fix. Every minute of downtime costs companies thousands of dollars. The on-call rotation is brutal, burnout is real, and the whole thing scales terribly.

The obvious solution is to let an AI read the logs and fix it automatically. But here's the problem nobody talks about: giving an autonomous LLM `sudo` access to your production servers is a massive security nightmare. AI hallucinations exist. A confident but wrong bash command can bring down an entire infrastructure in seconds. You've just traded one problem for a worse one.

So we thought: what if the AI could act — but only as much as it's *authorized* to?

---

## What We Built

**Cerberus** is an AI agent that monitors system logs, diagnoses failures, and generates remediation — but what it's *allowed to do* is controlled entirely by Auth0 RBAC.

The same log. Two different roles. Two completely different responses.

A **junior dev** sends a failing nginx log → the agent explains the root cause, walks them through manual steps, and explicitly says: *"Permission level: user. No commands authorized."*

A **senior admin** sends the exact same log → the agent returns an executable bash command, ready to run. *"Permission level: admin. Authorized to generate remediation."*

The AI isn't just smart. It knows its place in your org chart.

---

## How It Works

```
Incoming log
    │
    ├─ security.py      → scrubs PII, emails, API keys before AI sees anything
    ├─ auth_middleware   → validates Auth0 JWT, extracts role
    ├─ agent.py         → detects failure category (8 patterns), calls Gemini 2.5 Flash
    └─ vault.py         → fetches user's GitHub token from Auth0 Token Vault
                        → opens a GitHub Issue with full incident report automatically
```

The key piece is **Auth0 Token Vault**. When a failure is detected, Cerberus doesn't just return JSON — it uses the logged-in user's GitHub OAuth token (stored securely inside Auth0, never in our database or env vars) to autonomously open a structured GitHub Issue with the root cause, suggested fix, severity label, and rollback procedure. The agent acts *on behalf of the user*, using *their* credentials, with *their* consent — exactly what Token Vault is designed for.

---

## Tech Stack

| Layer | Tech |
|---|---|
| Backend | FastAPI (Python) |
| AI Model | Vertex AI — Gemini 2.5 Flash |
| Auth & RBAC | Auth0 — JWT validation, RBAC roles, Token Vault |
| Deployment | Google Cloud Run |
| CI/CD | GitHub Actions + Workload Identity Federation |
| Secrets | GCP Secret Manager |
| PII Scrubbing | Custom SovereignScrubber (security.py) |

---

## The Auth0 Token Vault Part

This is the bit I'm most proud of and the reason this project exists as it does.

Most people building AI agents store third-party tokens in a `.env` file or a database table. That means your GitHub token, your Slack token, whatever — sitting somewhere in your infrastructure, one breach away from being exposed.

Token Vault flips this. When a user logs into Cerberus via GitHub social connection, Auth0 stores their GitHub OAuth token inside the Auth0 identity itself. When Cerberus needs to open a GitHub Issue on their behalf, `vault.py` calls the Auth0 Management API to retrieve that token at runtime — it never touches our database, never sits in an env var, never gets logged.

The code is about 50 lines:

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

That's it. Auth0 is the credential store. We're just asking for what belongs to the user, when we need it.

---

## Demo

**Live URL:** `https://remediation-agent-gzuqcqtiqa-uc.a.run.app`

**API Docs:** `https://remediation-agent-gzuqcqtiqa-uc.a.run.app/docs`

Three failure scenarios built in for the demo:
- Nginx port conflict (`bind() to 0.0.0.0:80 failed`)
- PostgreSQL disk full (`ENOSPC — no space left on device`)
- App daemon permission denied (`Permission denied on /var/run/app/app.sock`)

Send any of these as a log to `/logs/analyze` with a user token vs an admin token and watch the `command` field go from `null` to an executable bash command.

---

## Running Locally

```bash
git clone https://github.com/shubhayu-dev/Cerberus
cd Cerberus

# Create venv and install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy env template and fill in your values
cp .env.example .env

# Run
cd app
uvicorn main:app --reload --port 8000
```

If `GCP_PROJECT_ID` is left blank in `.env`, the agent uses mock responses automatically — so you can test the full Auth0 RBAC flow locally without needing a GCP project.

---

## Project Structure

```
Cerberus/
├── app/
│   ├── main.py              # FastAPI routes, request pipeline
│   ├── agent.py             # Vertex AI integration, failure detection
│   ├── auth_middleware.py   # Auth0 JWT validation, role extraction
│   ├── security.py          # PII scrubber — runs before AI sees anything
│   └── vault.py             # Token Vault — GitHub token retrieval + issue creation
├── demo/
│   └── demo.html            # Standalone interactive demo
├── .github/workflows/
│   └── deploy.yml           # Auto-deploy to Cloud Run on push to main
├── Dockerfile
├── requirements.txt
└── deploy.sh                # One-time GCP setup script
```

---

## Auth0 Setup Notes

The roles Action is the part that makes RBAC work. Without it, JWT tokens don't carry role information and everyone gets treated as a regular user. If you're forking this and testing locally, make sure you:

1. Create a Post Login Action in Auth0 that adds roles to both the ID token and access token
2. Create two roles named exactly `user` and `admin` (lowercase)
3. Create a Machine-to-Machine app with `read:users` permission on the Management API — this is what lets `vault.py` call the Management API to fetch tokens
4. Enable GitHub social connection so Auth0 stores the GitHub token in user identities

The `.env.example` file has every variable you need with comments explaining each one.

---

## Why This Matters

I think the current state of **AI in DevOps** is either useless (just explains errors) or dangerous (has root access to everything).

The middle ground is an agent that's smart enough to diagnose production issues and precise enough to generate the right fix — but constrained by the same permission system your human engineers use. Auth0 handles that identity layer. Gemini handles the reasoning. The result is something you could actually deploy in a real company without your security team having a heart attack.

That's what Cerberus is trying to be.

---

## What's Next

- Slack Token Vault integration — post incident alerts to the user's Slack channel using their stored token
- PagerDuty integration — automatically create incidents for critical severity failures  
- Log streaming — connect directly to Cloud Logging instead of manual log submission
- Rollback execution — admin role can trigger the rollback command, not just receive it

---
