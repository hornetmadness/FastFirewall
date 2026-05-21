"""
app.py — FastAPI entry point with plugin-supplied routes.

Routes are auto-discovered from plugins that subclass ApiRouterPlugin and mounted
at /v1/<plugin_id>/.  Visit /docs for the interactive OpenAPI UI.

Authentication: every route except those in auth.exempt_paths requires a valid
credential.  Clients may use either HTTP Basic or an OAuth2 Bearer JWT (obtained
from POST /token).  Both schemes are visible in the /docs "Authorize" dialog.
"""
from typing import Annotated

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status

from plugin_system import manager_cli
from app_config import AppConfig
from plugin_system.core import PluginLoader, bus
from infra.state_manager import configure as configure_state
from ff_auth import (
    AuthUser,
    authenticate_for_token,
    create_token,
    enforce_auth,
    get_current_user,
    setup as auth_setup,
)

cfg = AppConfig.load()
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


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    return await enforce_auth(request, call_next)


@app.post("/token", tags=["auth"], summary="Obtain a Bearer JWT")
async def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_for_token(form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
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
only_plugins, ignore_plugins_states, show_macros = manager_cli.run(loader, cfg.plugins_dir())
loader.ignore_state_on_boot = ignore_plugins_states
loader.load_directory(cfg.plugins_dir(), only=only_plugins, skip_requirements=show_macros)

if show_macros:
    import sys
    manager_cli.print_macros(loader)
    sys.exit(0)


@app.get("/v1/macros", tags=["macros"], summary="List all macro namespaces and their current values")
def list_macros():
    return manager_cli.get_macros(loader)

if __name__ == "__main__":
    manager_cli.print_plugin_table(loader.list_plugins(cfg.plugins_dir()))
    print()
    cfg.logger.debug("Starting server with uvicorn kwargs: %s", cfg.uvicorn_kwargs())
    uvicorn.run(app, **cfg.uvicorn_kwargs())
