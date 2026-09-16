"""Fail-closed stdio process adapter for a configured local Agent identity."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from tas.adapters.auth.local_credentials import CredentialRegistry
from tas.adapters.persistence.sqlite.identity_repository import SQLiteIdentityRepository
from tas.adapters.a2a.official_gateway import DiscoveringOfficialA2AGateway
from tas.domain.identity import AgentId, OwnerId
from tas.mcp.server import create_mcp_server
from tas.observability.logging import configure_json_logging


DATABASE = "TAS_MCP_DATABASE"
BINDINGS = "TAS_MCP_CREDENTIAL_BINDINGS"
CREDENTIAL = "TAS_MCP_CREDENTIAL"
A2A_BASE_URL = "TAS_A2A_BASE_URL"


class MCPConfigurationError(RuntimeError):
    """The stdio server cannot establish its configured actor boundary."""


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if not isinstance(value, str) or not value.strip():
        raise MCPConfigurationError(f"{name} must be configured")
    return value


def _absolute_file(value: str, name: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise MCPConfigurationError(f"{name} must be an absolute path")
    if not path.is_file():
        raise MCPConfigurationError(f"{name} must reference an existing file")
    return path


def create_server_from_environment(
    environment: Mapping[str, str],
    *,
    server_factory: Callable[..., FastMCP] = create_mcp_server,
) -> FastMCP:
    """Authenticate process configuration and create an actor-bound server."""
    database = _absolute_file(_required(environment, DATABASE), DATABASE)
    bindings = _absolute_file(_required(environment, BINDINGS), BINDINGS)
    credential = _required(environment, CREDENTIAL)

    try:
        principal = CredentialRegistry.from_file(bindings).authenticate(credential)
        actor_id = AgentId(principal.agent_id)
        configured_owner_id = OwnerId(principal.owner_id)
        database_agent = SQLiteIdentityRepository(database).get_agent(actor_id)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        raise MCPConfigurationError(
            "MCP credential or binding configuration is invalid"
        ) from None

    if database_agent is None or database_agent.owner_id != configured_owner_id:
        raise MCPConfigurationError(
            "MCP identity binding does not match the database"
        )

    options: dict[str, object] = {"database": database, "actor_id": actor_id}
    a2a_base_url = environment.get(A2A_BASE_URL)
    if a2a_base_url is not None:
        parsed = urlparse(a2a_base_url)
        if (
            not a2a_base_url.strip()
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise MCPConfigurationError(
                "TAS_A2A_BASE_URL must be an HTTP(S) URL without credentials"
            )
        options["a2a_gateway"] = DiscoveringOfficialA2AGateway(a2a_base_url)

    return server_factory(**options)


def main() -> None:
    """Run the configured MCP server over stdio."""
    configure_json_logging()
    create_server_from_environment(os.environ).run("stdio")


if __name__ == "__main__":
    main()
