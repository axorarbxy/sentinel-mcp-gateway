"""
Authentication Utilities - Using direct bcrypt
"""

import hashlib
import secrets
import hmac
import re

import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
import os

AGENT_KEY_PATTERN = re.compile(
    r"^(cye_(?:live|test)_)([a-f0-9]{16})_([A-Za-z0-9_-]{43})$"
)


def create_agent_api_key() -> tuple[str, str, str]:
    """Return a prefixed high-entropy key, its indexed lookup ID, and display prefix."""
    environment = os.getenv("SENTINEL_ENVIRONMENT", "dev").lower()
    key_environment = "live" if environment in {"prod", "production"} else "test"
    lookup_id = secrets.token_hex(8)
    key = f"cye_{key_environment}_{lookup_id}_{secrets.token_urlsafe(32)}"
    return key, lookup_id, f"cye_{key_environment}_{lookup_id}"


def parse_agent_api_key(api_key: str) -> Optional[tuple[str, str]]:
    """Return (lookup_id, secret) for a well-formed key; reject legacy/malformed keys."""
    match = AGENT_KEY_PATTERN.fullmatch(api_key)
    if not match:
        return None
    return match.group(2), api_key

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

def truncate_password(password: str) -> bytes:
    """Truncate password to 72 bytes for bcrypt"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    return password_bytes

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        # Truncate to 72 bytes
        password_bytes = truncate_password(plain_password)
        return bcrypt.checkpw(password_bytes, hashed_password.encode('utf-8'))
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

def get_password_hash(password: str) -> str:
    """Hash a password"""
    try:
        # Truncate to 72 bytes
        password_bytes = truncate_password(password)
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    except Exception as e:
        print(f"Hashing error: {e}")
        raise

def create_access_token(data: Dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: Dict) -> str:
    """Create a JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> Optional[Dict]:
    """Decode and verify a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(token: str):
    """Get current user from token"""
    payload = decode_token(token)
    if payload is None:
        return None
    return {
        "user_id": payload.get("sub"),
        "username": payload.get("username"),
        "is_admin": payload.get("is_admin", False)
    }


def hash_api_key(api_key: str) -> str:
    """Hash an API key with a stable, constant-time-safe method for storage."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Compare a candidate API key against a stored hash using constant-time comparison."""
    if not api_key or not stored_hash:
        return False
    expected = hash_api_key(api_key)
    return hmac.compare_digest(expected, stored_hash)