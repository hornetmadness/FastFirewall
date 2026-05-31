"""
fastfirewall_app.py — FastAPI entry point with plugin-supplied routes.

Routes are auto-discovered from plugins that subclass ApiRouterPlugin and mounted
at /v1/<plugin_id>/.  Visit /docs for the interactive OpenAPI UI.

Authentication: every route except those in auth.exempt_paths requires a valid
credential.  Clients may use either HTTP Basic or an OAuth2 Bearer JWT (obtained
from POST /token).  Both schemes are visible in the /docs "Authorize" dialog.
"""
import argparse
import logging
import sys
from typing import Annotated

from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status

from plugin_system import manager_cli
from app_config import AppConfig
from plugin_system.core import PluginLoader, bus, macro_registry
from infra.state_manager import configure as configure_state
from request_context import request_tracing_middleware
from ff_auth import (
    AuthUser,
    audit,
    authenticate_for_token,
    create_token,
    enforce_auth,
    get_client_ip,
    get_current_user,
    is_rate_limited,
    record_login_failure,
    record_login_success,
    setup as auth_setup,
)

log = logging.getLogger("app")

cfg = AppConfig.load()

# Handle --showcfg and --makecfg before auth setup so they work even when
# the secret_key placeholder hasn't been replaced yet.
_early = argparse.ArgumentParser(add_help=False)
_early.add_argument("--showcfg", action="store_true")
_early.add_argument("--makecfg", metavar="PATH", default=None)
_ea, _ = _early.parse_known_args()
if _ea.showcfg:
    from plugin_system import manager_cli as _mcli
    _mcli.print_cfg(cfg)
    sys.exit(0)
if _ea.makecfg:
    from pathlib import Path as _Path
    from plugin_system import manager_cli as _mcli
    _mcli.make_cfg(_Path(_ea.makecfg).expanduser().resolve(), cfg)
    sys.exit(0)

auth_setup(cfg.auth)
configure_state(
    backup_enabled=cfg.state.backup.enabled,
    backup_directory=cfg.state.backup.directory,
)

app = FastAPI(
    title="Fastfirewall",
    description=(
        "Plugin-supplied routes auto-mounted at /v1/<service_name>/.\n\n"
        "**Authentication:** use HTTP Basic *or* an OAuth2 Bearer token. "
        "Obtain a token via `POST /token`, then click **Authorize** above."
    ),
)

if cfg.server.cors.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.server.cors.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.middleware("http")
async def _limit_payload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > cfg.server.max_payload_bytes:
        return JSONResponse({"detail": "Payload too large"}, status_code=413)
    return await call_next(request)


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    return await enforce_auth(request, call_next)


@app.middleware("http")
async def _request_tracing(request: Request, call_next):
    return await request_tracing_middleware(request, call_next)


@app.exception_handler(Exception)
async def _generic_error_handler(request: Request, exc: Exception):
    log.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=True)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


@app.post("/token", tags=["auth"], summary="Obtain a Bearer JWT")
async def login(request: Request, form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    client_ip = get_client_ip(request)
    if is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": "300"},
        )
    user = authenticate_for_token(form.username, form.password)
    if user is None:
        record_login_failure(client_ip, form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    record_login_success(client_ip, user.username)
    return {"access_token": create_token(user.username, user.roles), "token_type": "bearer"}


@app.get("/auth/me", tags=["auth"], summary="Return the authenticated user's identity")
async def whoami(user: Annotated[AuthUser, Depends(get_current_user)]):
    return {"username": user.username, "roles": user.roles}

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
):
    # Write user friendly error messages
    error_messages = []
    for error in exc.errors():
        field = str(error["loc"][-1])
        message = error["msg"]
        error_messages.append(f"{field.capitalize()}: {message}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "message": ".\n".join(error_messages),
            "source_errors": exc.errors(),
        },
    )

loader = PluginLoader(bus=bus, app=app, logger=cfg.logger)
only_plugins, ignore_plugins_states, show_macros = manager_cli.run(loader, cfg.plugins_src_dir(), cfg)
loader.ignore_state_on_boot = ignore_plugins_states
data_dir = cfg.plugins_data_dir()
cfg_dir = cfg.plugins_cfg_dir()

# 1. Dev / cwd plugins directory (highest priority)
plugins_dir = cfg.plugins_src_dir()
if plugins_dir.is_dir():
    loader.load_directory(plugins_dir, only=only_plugins, skip_requirements=show_macros, data_dir=data_dir, cfg_dir=cfg_dir)

# 2. Configured scan dirs: /etc/fastfirewall/plugins, ~/.config/fastfirewall/plugins, …
for scan_dir in cfg.plugins_scan_dirs():
    if scan_dir.is_dir():
        loader.load_directory(scan_dir, only=only_plugins, skip_requirements=show_macros, data_dir=data_dir, cfg_dir=cfg_dir)

# 3. Installed package entry points (fills in anything not found on the filesystem)
loader.load_installed(only=only_plugins, skip_requirements=show_macros, data_dir=data_dir, cfg_dir=cfg_dir)
macro_registry.register_service_port("fastfirewall-api", "tcp", [cfg.server.port])
loader.finished()

if show_macros:
    import sys
    manager_cli.print_macros(loader)
    sys.exit(0)


@app.get("/v1/macros", tags=["macros"], summary="List all macro namespaces and their current values")
def list_macros():
    return manager_cli.get_macros(loader)


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Apply both security schemes globally so Swagger UI sends credentials for
    # plugin routes, which are protected by middleware but have no FastAPI
    # security dependency.
    schema["security"] = [{"OAuth2PasswordBearer": []}, {"HTTPBasic": []}]
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _custom_openapi

def main() -> None:
    manager_cli.print_plugin_table(loader.list_plugins(cfg.plugins_src_dir()))
    print()
    cfg.logger.debug("Starting server with uvicorn kwargs: %s", cfg.uvicorn_kwargs())
    uvicorn.run(app, **cfg.uvicorn_kwargs())


if __name__ == "__main__":
    main()
