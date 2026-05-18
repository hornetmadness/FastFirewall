"""
auth.py — HTTP Basic and OAuth2 JWT Bearer authentication.

Both schemes are accepted on every protected route.  Call setup() once at
startup with the AuthConfig loaded from app_config.yaml.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import bcrypt as _bcrypt
import jwt as _jwt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer

if TYPE_CHECKING:
    from app_config import AuthConfig

log = logging.getLogger("auth")

# Security scheme objects — importing them triggers registration in OpenAPI.
http_basic = HTTPBasic(auto_error=False)
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False)


@dataclass
class AuthUser:
    username: str
    roles: list[str] = field(default_factory=list)


@dataclass
class _State:
    enabled: bool = False
    secret_key: str = ""
    algorithm: str = "HS256"
    token_expire_minutes: int = 60
    exempt_paths: set[str] = field(default_factory=lambda: {"/token"})
    users: dict[str, dict[str, Any]] = field(default_factory=dict)


_st = _State()


def setup(cfg: "AuthConfig") -> None:
    """Initialise module state from AppConfig.auth. Call once at startup."""
    _st.enabled = cfg.enabled
    _st.secret_key = cfg.secret_key
    _st.algorithm = cfg.algorithm
    _st.token_expire_minutes = cfg.token_expire_minutes
    _st.exempt_paths = set(cfg.exempt_paths)
    _st.users.clear()
    for u in cfg.users:
        pw = u["password"]
        _st.users[u["username"]] = {
            "hashed": pw if pw.startswith("$2") else _hash(pw),
            "roles": u.get("roles", []),
        }
    if _st.enabled:
        log.info("Auth enabled — %d user(s) loaded", len(_st.users))


# ── internal helpers ──────────────────────────────────────────────────────────

def _hash(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def _verify(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def _check_password(username: str, password: str) -> AuthUser | None:
    rec = _st.users.get(username)
    if rec and _verify(password, rec["hashed"]):
        return AuthUser(username=username, roles=rec["roles"])
    return None


_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def _decode_token(token: str) -> AuthUser | None:
    try:
        payload = _jwt.decode(token, _st.secret_key, algorithms=[_st.algorithm])
        username = payload.get("sub")
        if username:
            rec = _st.users.get(username)
            if rec:
                return AuthUser(username=username, roles=rec["roles"])
    except _jwt.PyJWTError:
        pass
    return None


def _user_from_header(authorization: str) -> AuthUser | None:
    low = authorization.lower()
    if low.startswith("basic "):
        try:
            raw = base64.b64decode(authorization[6:]).decode()
            username, _, password = raw.partition(":")
            return _check_password(username, password)
        except Exception:
            return None
    if low.startswith("bearer "):
        return _decode_token(authorization[7:])
    return None


# ── public API ────────────────────────────────────────────────────────────────

def create_token(username: str, roles: list[str]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=_st.token_expire_minutes)
    return _jwt.encode(
        {"sub": username, "roles": roles, "exp": expire},
        _st.secret_key,
        algorithm=_st.algorithm,
    )


def authenticate_for_token(username: str, password: str) -> AuthUser | None:
    """Verify credentials for the /token endpoint."""
    return _check_password(username, password)


async def get_current_user(
    credentials: HTTPBasicCredentials | None = Depends(http_basic),
    token: str | None = Depends(oauth2_bearer),
) -> AuthUser:
    """FastAPI dependency — resolves caller via Basic or Bearer auth.

    Declaring this dependency on a route causes both security schemes to appear
    in the OpenAPI /docs "Authorize" dialog.
    """
    if not _st.enabled:
        return AuthUser(username="anonymous")
    user: AuthUser | None = None
    if credentials:
        user = _check_password(credentials.username, credentials.password)
    if user is None and token:
        user = _decode_token(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="FastFirewall", Bearer'},
        )
    return user


async def enforce_auth(request: Request, call_next) -> Response:
    """HTTP middleware — protects all routes not in exempt_paths."""
    if not _st.enabled or request.url.path in _st.exempt_paths:
        return await call_next(request)
    user = _user_from_header(request.headers.get("Authorization", ""))
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": 'Basic realm="FastFirewall", Bearer error="invalid_token"'},
            content={"detail": "Authentication required"},
        )
    if request.method in _MUTATING_METHODS and "admin" not in user.roles:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Admin role required for write operations"},
        )
    request.state.user = user
    return await call_next(request)
