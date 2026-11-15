import hashlib
import hmac
import os
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from database import get_user_by_id

_ITERATIONS = 310_000
_TOKEN_MAX_AGE = 60 * 60 * 8
_SECRET = os.getenv("AUTH_SECRET_KEY", "development-only-change-this-secret-before-deployment")
_serializer = URLSafeTimedSerializer(_SECRET, salt="sdlc-vulenser-auth")
_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations)).hex()
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def create_access_token(user: dict) -> str:
    return _serializer.dumps({"sub": user["id"], "role": user["role"]})


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer)):
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Please log in to continue.")
    try:
        payload = _serializer.loads(credentials.credentials, max_age=_TOKEN_MAX_AGE)
        user = get_user_by_id(int(payload.get("sub")))
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session is invalid or expired. Please log in again.")
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This account is unavailable. Contact the administrator.")
    return user


def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access is required.")
    return user
