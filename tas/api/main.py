"""FastAPI application entry point."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from tas.adapters.auth.local_credentials import (
    CredentialRegistry,
    InvalidCredentialError,
    LocalPrincipal,
)
from tas.observability.logging import configure_json_logging
from tas.observability.trace import TraceMiddleware


class SessionResponse(BaseModel):
    agent_id: str
    owner_id: str
    identity_source: str
    assurance_level: str
    is_test_fixture: bool


def create_app(credentials: CredentialRegistry | None = None) -> FastAPI:
    registry = credentials if credentials is not None else _registry_from_environment()
    application = FastAPI(
        title="Team Agent System",
        version="0.1.0",
        description="F2 technical validation API.",
    )
    application.add_middleware(TraceMiddleware)

    @application.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """Return a stable liveness response without touching infrastructure."""

        return {"status": "ok"}

    @application.get("/session", tags=["system"])
    def session(authorization: str | None = Header(default=None)) -> SessionResponse:
        principal = _authenticate_bearer(registry, authorization)
        return SessionResponse(
            agent_id=principal.agent_id,
            owner_id=principal.owner_id,
            identity_source=principal.identity_source,
            assurance_level=principal.assurance_level,
            is_test_fixture=principal.is_test_fixture,
        )

    return application


def _registry_from_environment() -> CredentialRegistry:
    path = os.environ.get("TAS_CREDENTIAL_BINDINGS_FILE")
    return CredentialRegistry.empty() if path is None else CredentialRegistry.from_file(Path(path))


def _authenticate_bearer(
    registry: CredentialRegistry, authorization: str | None
) -> LocalPrincipal:
    scheme, separator, token = (authorization or "").partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credential",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return registry.authenticate(token)
    except InvalidCredentialError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credential",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error


configure_json_logging()
app = create_app()
