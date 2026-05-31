"""
auth.py — HTTP Basic and OAuth2 JWT Bearer authentication.

Both schemes are accepted on every protected route.  Call setup() once at
startup with the AuthConfig loaded from app_config.yaml.
"""
from __future__ import annotations

import base64
import logging
import time
from collections import deque
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
_audit_log = logging.getLogger("auth.audit")

_ISSUER = "fastfirewall"

# Computed once at import time — used by _check_password for timing parity on
# unknown usernames so callers cannot enumerate valid accounts via response time.
_DUMMY_HASH: str = _bcrypt.hashpw(b"__dummy__", _bcrypt.gensalt()).decode()

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
    rl_max_attempts: int = 5
    rl_window_seconds: int = 300
    trusted_proxies: set[str] = field(default_factory=set)


_st = _State()

# Maps client IP → deque of failed-attempt timestamps (monotonic clock)
_rl_attempts: dict[str, deque[float]] = {}


def setup(cfg: "AuthConfig") -> None:
    """Initialise module state from AppConfig.auth. Call once at startup."""
    _st.enabled = cfg.enabled
    _st.secret_key = cfg.secret_key
    _st.algorithm = cfg.algorithm
    _st.token_expire_minutes = cfg.token_expire_minutes
    _st.exempt_paths = set(cfg.exempt_paths)
    _st.rl_max_attempts = cfg.rate_limit.max_attempts
    _st.rl_window_seconds = cfg.rate_limit.window_seconds
    _st.trusted_proxies = set(getattr(cfg, "trusted_proxies", []))
    _st.users.clear()
    for u in cfg.users:
        pw = u["password"]
        _st.users[u["username"]] = {
            "hashed": pw if pw.startswith("$2") else _hash(pw),
            "roles": u.get("roles", []),
        }
    if _st.enabled:
        if _st.secret_key.startswith("CHANGE-ME"):
            raise RuntimeError(
                "auth.secret_key is the default placeholder — "
                "run: fastfirewall-api --makecfg ~/.config/fastfirewall  "
                "then edit the generated app_config.yaml to set users/passwords, "
                "and restart with: FASTFIREWALL_CONFIG=~/.config/fastfirewall/app_config.yaml fastfirewall-api"
            )
        log.info(
            "Auth enabled — %d user(s) loaded, rate limit %d attempts / %ds",
            len(_st.users), _st.rl_max_attempts, _st.rl_window_seconds,
        )


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
    if rec is None:
        _verify(password, _DUMMY_HASH)  # timing parity — prevent username enumeration
        return None
    if _verify(password, rec["hashed"]):
        return AuthUser(username=username, roles=rec["roles"])
    return None


_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def _decode_token(token: str) -> AuthUser | None:
    try:
        payload = _jwt.decode(
            token, _st.secret_key, algorithms=[_st.algorithm],
            issuer=_ISSUER,
            options={"require": ["exp", "iss"]},
        )
        username = payload.get("sub")
        if username:
            rec = _st.users.get(username)
            if rec:
                return AuthUser(username=username, roles=rec["roles"])
    except _jwt.PyJWTError:
        pass
    return None


def get_client_ip(request: Request) -> str:
    """Return the real client IP, honouring X-Forwarded-For from trusted proxies."""
    direct = request.client.host if request.client else "unknown"
    if _st.trusted_proxies and direct in _st.trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return direct


def audit(user: str, action: str, resource: str = "", ip: str = "") -> None:
    """Emit a structured audit record for a privileged action."""
    _audit_log.info(
        "user=%s action=%s resource=%s ip=%s",
        user, action, resource or "-", ip or "-",
    )


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


# ── rate limiting ─────────────────────────────────────────────────────────────

def _rl_purge(bucket: deque[float], now: float) -> None:
    while bucket and now - bucket[0] > _st.rl_window_seconds:
        bucket.popleft()


def is_rate_limited(ip: str) -> bool:
    """Return True if this IP has exhausted its allowed login attempts."""
    bucket = _rl_attempts.get(ip)
    if not bucket:
        return False
    _rl_purge(bucket, time.monotonic())
    return len(bucket) >= _st.rl_max_attempts


def record_login_failure(ip: str, username: str = "") -> None:
    """Record a failed /token attempt for the given IP."""
    now = time.monotonic()
    if ip not in _rl_attempts:
        _rl_attempts[ip] = deque()
    bucket = _rl_attempts[ip]
    _rl_purge(bucket, now)
    bucket.append(now)
    if len(bucket) >= _st.rl_max_attempts:
        log.warning(
            "Rate limit reached for %s — %d failures within %ds window",
            ip, len(bucket), _st.rl_window_seconds,
        )
    else:
        log.warning("Failed login attempt from %s (%d/%d)", ip, len(bucket), _st.rl_max_attempts)
    _audit_log.warning("user=%s action=login_failed ip=%s", username or "-", ip)


def record_login_success(ip: str, username: str = "") -> None:
    """Clear the failure counter for an IP after a successful login."""
    _rl_attempts.pop(ip, None)
    _audit_log.info("user=%s action=login_success ip=%s", username or "-", ip)


# ── public API ────────────────────────────────────────────────────────────────

def create_token(username: str, roles: list[str]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=_st.token_expire_minutes)
    return _jwt.encode(
        {"sub": username, "roles": roles, "exp": expire, "iss": _ISSUER},
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
            headers={"WWW-Authenticate": 'Bearer realm="FastFirewall"'},
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
            headers={"WWW-Authenticate": 'Bearer realm="FastFirewall"'},
            content={"detail": "Authentication required"},
        )
    if request.method in _MUTATING_METHODS and "admin" not in user.roles:
        ip = get_client_ip(request)
        _audit_log.warning(
            "user=%s action=write_denied method=%s path=%s ip=%s",
            user.username, request.method, request.url.path, ip,
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Admin role required for write operations"},
        )
    request.state.user = user
    if request.method in _MUTATING_METHODS:
        ip = get_client_ip(request)
        _audit_log.info(
            "user=%s action=write method=%s path=%s ip=%s",
            user.username, request.method, request.url.path, ip,
        )
    return await call_next(request)
