import os
import httpx
from functools import lru_cache
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from dotenv import load_dotenv
load_dotenv()

AUTH0_DOMAIN   = os.getenv("AUTH0_DOMAIN")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
ALGORITHMS     = ["RS256"]
security       = HTTPBearer()

@lru_cache(maxsize=1)
def _get_jwks():
    url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    r = httpx.get(url, timeout=10)
    r.raise_for_status()
    return r.json()

def _decode_token(token: str) -> dict:
    jwks = _get_jwks()
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Bad header: {e}")
    rsa_key = next((
        {"kty":k["kty"],"kid":k["kid"],"use":k["use"],"n":k["n"],"e":k["e"]}
        for k in jwks["keys"] if k["kid"] == header.get("kid")), {})
    if not rsa_key:
        raise HTTPException(status_code=401, detail="Key not found")
    try:
        return jwt.decode(token, rsa_key, algorithms=ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

def extract_roles(payload: dict) -> list[str]:
    ns = os.getenv("AUTH0_ROLES_NAMESPACE", "https://remediation-agent/roles")
    roles = payload.get(ns, [])
    if not roles:
        roles = payload.get("permissions", ["user"])
    return roles if roles else ["user"]

async def require_auth(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> dict:
    token = credentials.credentials
    payload = _decode_token(token)
    roles   = extract_roles(payload)
    return {
        "sub":      payload.get("sub"),
        "email":    payload.get("email", "unknown"),
        "name":     payload.get("name", "unknown"),
        "roles":    roles,
        "is_admin": "admin" in roles,
    }
