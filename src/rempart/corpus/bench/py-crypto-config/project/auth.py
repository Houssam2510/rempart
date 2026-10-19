import hashlib
import random
import secrets

import jwt
import requests


def hash_password(password: str) -> str:
    # rempart-expect: CODE-WEAK-PASSWORD-HASH
    return hashlib.md5(password.encode()).hexdigest()


def etag(body: bytes) -> str:
    # rempart-safe: CODE-WEAK-PASSWORD-HASH, CODE-WEAK-HASH
    return hashlib.md5(body, usedforsecurity=False).hexdigest()


def reset_token() -> str:
    # rempart-expect: CODE-WEAK-RANDOM
    reset_code = "".join(random.choice("0123456789") for _ in range(6))
    return reset_code


def session_token() -> str:
    # rempart-safe: CODE-WEAK-RANDOM
    return secrets.token_urlsafe(32)


def jitter() -> float:
    # rempart-safe: CODE-WEAK-RANDOM
    return random.uniform(0.1, 0.5)


def read_claims(token: str) -> dict:
    # rempart-expect: CODE-JWT-UNVERIFIED
    return jwt.decode(token, options={"verify_signature": False})


def verified_claims(token: str, key: str) -> dict:
    # rempart-safe: CODE-JWT-UNVERIFIED
    return jwt.decode(token, key, algorithms=["HS256"])


def partner_status() -> int:
    # rempart-expect: CODE-TLS-VERIFY-DISABLED
    return requests.get("https://partner.example/status", verify=False, timeout=5).status_code
