"""
Tests for the ff_auth package — setup, password verification, JWT round-trip,
middleware enforcement, and the get_current_user FastAPI dependency.
"""
import base64

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app_config import AuthConfig
from ff_auth.auth import (
    AuthUser,
    _decode_token,
    authenticate_for_token,
    create_token,
    enforce_auth,
    get_current_user,
    setup,
    _st,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(**kwargs) -> AuthConfig:
    defaults = dict(
        enabled=True,
        secret_key="test-secret-key",
        algorithm="HS256",
        token_expire_minutes=60,
        exempt_paths=["/token"],
        users=[{"username": "admin", "password": "admin", "roles": ["admin"]}],
    )
    defaults.update(kwargs)
    return AuthConfig(**defaults)  # type: ignore[arg-type]


def _basic_header(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"


def _app_with_middleware(cfg: AuthConfig) -> TestClient:
    """Minimal FastAPI app with auth middleware for integration tests."""
    setup(cfg)
    app = FastAPI()

    @app.middleware("http")
    async def auth_mw(request, call_next):
        return await enforce_auth(request, call_next)

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    @app.post("/mutate")
    async def mutate():
        return {"ok": True}

    @app.get("/token")
    async def token_stub():
        return {"exempted": True}

    @app.get("/me")
    async def me(user: AuthUser = Depends(get_current_user)):
        return {"username": user.username, "roles": user.roles}

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_auth():
    """Reset module singleton to a known disabled state around every test."""
    setup(AuthConfig(enabled=False))
    yield
    setup(AuthConfig(enabled=False))


# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

def test_setup_enabled_flag():
    setup(_cfg(enabled=True))
    assert _st.enabled is True


def test_setup_disabled_flag():
    setup(_cfg(enabled=False))
    assert _st.enabled is False


def test_setup_hashes_plaintext_password():
    setup(_cfg())
    hashed = _st.users["admin"]["hashed"]
    assert hashed.startswith("$2")


def test_setup_accepts_prehashed_password():
    import bcrypt
    hashed = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
    setup(_cfg(users=[{"username": "admin", "password": hashed, "roles": []}]))
    assert _st.users["admin"]["hashed"] == hashed


def test_setup_loads_roles():
    setup(_cfg())
    assert _st.users["admin"]["roles"] == ["admin"]


def test_setup_stores_exempt_paths():
    setup(_cfg(exempt_paths=["/token", "/healthz"]))
    assert "/token" in _st.exempt_paths
    assert "/healthz" in _st.exempt_paths


def test_setup_clears_previous_users():
    setup(_cfg(users=[{"username": "alice", "password": "pw", "roles": []}]))
    setup(_cfg(users=[{"username": "bob", "password": "pw", "roles": []}]))
    assert "alice" not in _st.users
    assert "bob" in _st.users


# ---------------------------------------------------------------------------
# authenticate_for_token()
# ---------------------------------------------------------------------------

def test_authenticate_correct_credentials():
    setup(_cfg())
    user = authenticate_for_token("admin", "admin")
    assert user is not None
    assert user.username == "admin"
    assert user.roles == ["admin"]


def test_authenticate_wrong_password():
    setup(_cfg())
    assert authenticate_for_token("admin", "wrong") is None


def test_authenticate_unknown_user():
    setup(_cfg())
    assert authenticate_for_token("ghost", "admin") is None


# ---------------------------------------------------------------------------
# create_token() / _decode_token()
# ---------------------------------------------------------------------------

def test_token_round_trip():
    setup(_cfg())
    token = create_token("admin", ["admin"])
    user = _decode_token(token)
    assert user is not None
    assert user.username == "admin"
    assert user.roles == ["admin"]


def test_decode_invalid_token_returns_none():
    setup(_cfg())
    assert _decode_token("not.a.token") is None


def test_decode_token_wrong_secret():
    setup(_cfg(secret_key="secret-a"))
    token = create_token("admin", [])
    setup(_cfg(secret_key="secret-b"))
    assert _decode_token(token) is None


# ---------------------------------------------------------------------------
# enforce_auth middleware
# ---------------------------------------------------------------------------

def test_middleware_rejects_unauthenticated():
    client = _app_with_middleware(_cfg())
    r = client.get("/protected")
    assert r.status_code == 401


def test_middleware_accepts_basic_auth():
    client = _app_with_middleware(_cfg())
    r = client.get("/protected", headers={"Authorization": _basic_header("admin", "admin")})
    assert r.status_code == 200


def test_middleware_rejects_wrong_basic_password():
    client = _app_with_middleware(_cfg())
    r = client.get("/protected", headers={"Authorization": _basic_header("admin", "wrong")})
    assert r.status_code == 401


def test_middleware_accepts_bearer_token():
    setup(_cfg())
    token = create_token("admin", ["admin"])
    client = _app_with_middleware(_cfg())
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_middleware_rejects_invalid_bearer_token():
    client = _app_with_middleware(_cfg())
    r = client.get("/protected", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


def test_middleware_exempt_path_skips_auth():
    client = _app_with_middleware(_cfg())
    r = client.get("/token")
    assert r.status_code == 200


def test_middleware_passes_through_when_disabled():
    client = _app_with_middleware(_cfg(enabled=False))
    r = client.get("/protected")
    assert r.status_code == 200


def test_middleware_401_includes_www_authenticate_header():
    client = _app_with_middleware(_cfg())
    r = client.get("/protected")
    assert "WWW-Authenticate" in r.headers


# ---------------------------------------------------------------------------
# get_current_user dependency
# ---------------------------------------------------------------------------

def test_dependency_resolves_via_basic_auth():
    client = _app_with_middleware(_cfg())
    r = client.get("/me", headers={"Authorization": _basic_header("admin", "admin")})
    assert r.status_code == 200
    assert r.json()["username"] == "admin"


def test_dependency_resolves_via_bearer_token():
    setup(_cfg())
    token = create_token("admin", ["admin"])
    client = _app_with_middleware(_cfg())
    r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "admin"


def test_dependency_returns_anonymous_when_disabled():
    client = _app_with_middleware(_cfg(enabled=False))
    r = client.get("/me")
    assert r.status_code == 200
    assert r.json()["username"] == "anonymous"


# ---------------------------------------------------------------------------
# _decode_token — user existence check
# ---------------------------------------------------------------------------

def test_decode_token_unknown_user_returns_none():
    setup(_cfg(users=[{"username": "alice", "password": "pw", "roles": ["admin"]}]))
    token = create_token("ghost", [])
    assert _decode_token(token) is None


def test_decode_token_roles_sourced_from_user_store_not_payload():
    setup(_cfg(users=[{"username": "admin", "password": "admin", "roles": ["admin"]}]))
    token = create_token("admin", [])
    user = _decode_token(token)
    assert user is not None
    assert "admin" in user.roles


# ---------------------------------------------------------------------------
# enforce_auth — RBAC
# ---------------------------------------------------------------------------

def test_middleware_forbids_mutating_request_for_non_admin():
    cfg = _cfg(users=[{"username": "reader", "password": "pw", "roles": ["viewer"]}])
    client = _app_with_middleware(cfg)
    r = client.post("/mutate", headers={"Authorization": _basic_header("reader", "pw")})
    assert r.status_code == 403


def test_middleware_allows_mutating_request_for_admin():
    client = _app_with_middleware(_cfg())
    r = client.post("/mutate", headers={"Authorization": _basic_header("admin", "admin")})
    assert r.status_code == 200


def test_middleware_allows_read_request_for_non_admin():
    cfg = _cfg(users=[{"username": "reader", "password": "pw", "roles": ["viewer"]}])
    client = _app_with_middleware(cfg)
    r = client.get("/protected", headers={"Authorization": _basic_header("reader", "pw")})
    assert r.status_code == 200


def test_middleware_mutate_passes_through_when_auth_disabled():
    client = _app_with_middleware(_cfg(enabled=False))
    r = client.post("/mutate")
    assert r.status_code == 200
