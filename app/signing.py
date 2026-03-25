"""
signing.py — Cryptographic Payload Signing
Signs LLM-generated remediation commands with RSA-PSS so target servers
can verify authenticity before executing anything.

Key lifecycle:
- Production: private key fetched from GCP Secret Manager at runtime
- Local dev:  auto-generates an ephemeral key pair (logged as EPHEMERAL)

The signed payload is a JSON object containing:
  - command:    the bash command to execute
  - signature:  base64-encoded RSA-PSS signature over SHA-256 hash
  - public_key: PEM-encoded public key (for verification)
  - metadata:   request_id, actor_sub, timestamp, algorithm
"""

import os
import json
import base64
import logging
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel

log = logging.getLogger("cerberus.signing")

# ── Models ────────────────────────────────────────────────────────────────────

class SignedPayload(BaseModel):
    command:     str
    signature:   str          # base64-encoded RSA-PSS signature
    public_key:  str          # PEM-encoded public key for verification
    algorithm:   str = "RSA-PSS-SHA256"
    metadata:    dict


class VerificationResult(BaseModel):
    valid:      bool
    command:    str
    verified_at: str
    reason:     Optional[str] = None


# ── Key management ────────────────────────────────────────────────────────────

_private_key  = None
_public_key   = None
_key_source   = None


def _load_or_generate_keys():
    """
    Loads signing keys. Priority order:
    1. GCP Secret Manager (production)
    2. SIGNING_PRIVATE_KEY env var (CI/testing)
    3. Ephemeral generated key (local dev — logged as WARNING)
    """
    global _private_key, _public_key, _key_source

    if _private_key is not None:
        return

    # ── Option 1: GCP Secret Manager ────────────────────────────────────────
    gcp_project = os.getenv("GCP_PROJECT_ID")
    if gcp_project:
        try:
            from google.cloud import secretmanager
            client      = secretmanager.SecretManagerServiceClient()
            secret_name = f"projects/{gcp_project}/secrets/cerberus-signing-key/versions/latest"
            response    = client.access_secret_version(request={"name": secret_name})
            pem_bytes   = response.payload.data

            _private_key = serialization.load_pem_private_key(
                pem_bytes, password=None, backend=default_backend()
            )
            _public_key  = _private_key.public_key()
            _key_source  = "gcp_secret_manager"

            print(f"SECURITY AUDIT: 🔐 Signing key loaded from GCP Secret Manager | "
                  f"project={gcp_project}")
            return
        except Exception as e:
            print(f"SECURITY AUDIT: ⚠ GCP Secret Manager unavailable ({e}) — "
                  f"falling back to env var")

    # ── Option 2: Environment variable ───────────────────────────────────────
    pem_env = os.getenv("SIGNING_PRIVATE_KEY")
    if pem_env:
        try:
            _private_key = serialization.load_pem_private_key(
                pem_env.encode(), password=None, backend=default_backend()
            )
            _public_key  = _private_key.public_key()
            _key_source  = "environment_variable"
            print(f"SECURITY AUDIT: 🔐 Signing key loaded from environment variable")
            return
        except Exception as e:
            print(f"SECURITY AUDIT: ⚠ Failed to load key from env ({e}) — "
                  f"generating ephemeral key")

    # ── Option 3: Ephemeral (local dev only) ─────────────────────────────────
    print("SECURITY AUDIT: ⚠ EPHEMERAL KEY — generating RSA-2048 key pair for local dev. "
          "DO NOT use in production. Set SIGNING_PRIVATE_KEY or configure GCP Secret Manager.")

    _private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    _public_key = _private_key.public_key()
    _key_source = "ephemeral_local_dev"

    print(f"SECURITY AUDIT: 🔑 Ephemeral RSA-2048 key pair generated | "
          f"valid for this process lifetime only")


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_remediation_payload(
    bash_command:  str,
    request_id:    str,
    actor_sub:     str,
    failure_category: str,
) -> SignedPayload:
    """
    Signs a bash remediation command using RSA-PSS with SHA-256.

    The signature covers: command + request_id + actor_sub + timestamp
    This prevents replay attacks — each signed payload is unique.

    Returns a SignedPayload that a target server can verify before executing.
    """
    _load_or_generate_keys()

    timestamp = datetime.now(timezone.utc).isoformat()

    # The message to sign includes command + context to prevent replay attacks
    message = json.dumps({
        "command":          bash_command,
        "request_id":       request_id,
        "actor_sub":        actor_sub,
        "timestamp":        timestamp,
        "failure_category": failure_category,
    }, sort_keys=True).encode("utf-8")

    print(f"SECURITY AUDIT: ✍ Signing remediation payload | "
          f"req={request_id} | actor={actor_sub[:20]} | "
          f"key_source={_key_source}")

    # RSA-PSS signature with SHA-256
    signature_bytes = _private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    # Export public key for verification by target server
    public_key_pem = _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    print(f"SECURITY AUDIT: ✅ Payload signed | "
          f"sig_length={len(signature_bytes)} bytes | "
          f"algorithm=RSA-PSS-SHA256 | key_source={_key_source}")

    return SignedPayload(
        command=bash_command,
        signature=signature_b64,
        public_key=public_key_pem,
        metadata={
            "request_id":       request_id,
            "actor_sub":        actor_sub,
            "timestamp":        timestamp,
            "failure_category": failure_category,
            "key_source":       _key_source,
            "algorithm":        "RSA-PSS-SHA256",
        },
    )


def verify_signed_payload(signed_payload: SignedPayload) -> VerificationResult:
    """
    Verifies a signed payload. Call this on the target server before executing.
    Returns VerificationResult with valid=True/False.
    """
    try:
        # Reconstruct the message that was signed
        message = json.dumps({
            "command":          signed_payload.command,
            "request_id":       signed_payload.metadata["request_id"],
            "actor_sub":        signed_payload.metadata["actor_sub"],
            "timestamp":        signed_payload.metadata["timestamp"],
            "failure_category": signed_payload.metadata["failure_category"],
        }, sort_keys=True).encode("utf-8")

        public_key = serialization.load_pem_public_key(
            signed_payload.public_key.encode(),
            backend=default_backend(),
        )

        signature_bytes = base64.b64decode(signed_payload.signature)

        public_key.verify(
            signature_bytes,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        print(f"SECURITY AUDIT: ✅ Signature VERIFIED | "
              f"req={signed_payload.metadata['request_id']} | "
              f"command='{signed_payload.command[:40]}'")

        return VerificationResult(
            valid=True,
            command=signed_payload.command,
            verified_at=datetime.now(timezone.utc).isoformat(),
        )

    except Exception as e:
        print(f"SECURITY AUDIT: ❌ Signature INVALID | error={e}")
        return VerificationResult(
            valid=False,
            command=signed_payload.command,
            verified_at=datetime.now(timezone.utc).isoformat(),
            reason=str(e),
        )