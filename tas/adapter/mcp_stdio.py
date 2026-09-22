"""Fail-closed stdio launcher for the remote F3 Adapter."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping

from mcp.server.fastmcp import FastMCP

from tas.adapter.config import AdapterConfigurationError, load_adapter_config
from tas.adapter.actions import AdapterActionError, AdapterActionService
from tas.adapter.evidence import AdapterEvidenceService, AdapterEvidenceError
from tas.adapter.http_client import AdapterClientError, TASRemoteClient
from tas.adapter.mcp_server import create_remote_mcp_server
from tas.adapter.secrets import CredentialStoreError, OSCredentialStore
from tas.adapter.workspaces import LocalWorkspaceError, LocalWorkspaceStore
from tas.observability.logging import configure_json_logging


class RemoteMCPConfigurationError(RuntimeError):
    """The process cannot establish its remote actor and transport boundary."""


def create_server_from_environment(
    environment: Mapping[str, str],
    *,
    store_factory: Callable[[], OSCredentialStore] = OSCredentialStore,
    client_factory: Callable[..., TASRemoteClient] = TASRemoteClient,
    server_factory: Callable[..., FastMCP] = create_remote_mcp_server,
) -> FastMCP:
    client: TASRemoteClient | None = None
    try:
        config = load_adapter_config(environment)
        credential = store_factory().get(config.credential_account)
        client = client_factory(config, credential)
        startup_session = client.smoke()
        if startup_session.agent_id is None:
            raise ValueError("Remote MCP requires an Agent Credential")
        workspace_store = LocalWorkspaceStore(config.state_directory)
        evidence_service = AdapterEvidenceService(
            client=client,
            workspaces=workspace_store,
            actor_id=startup_session.agent_id,
            credential=credential,
            profiles=config.test_commands,
        )
        action_service = AdapterActionService(
            client=client,
            workspaces=workspace_store,
            evidence=evidence_service,
            actor_id=startup_session.agent_id,
        )
        server = server_factory(
            client=client,
            startup_session=startup_session,
            evidence_service=evidence_service,
            action_service=action_service,
        )
    except (
        AdapterConfigurationError,
        CredentialStoreError,
        AdapterClientError,
        AdapterEvidenceError,
        AdapterActionError,
        LocalWorkspaceError,
        TypeError,
        ValueError,
    ):
        if client is not None:
            client.close()
        raise RemoteMCPConfigurationError(
            "Remote MCP Adapter configuration or authentication failed"
        ) from None
    return server


def main() -> None:
    configure_json_logging()
    try:
        server = create_server_from_environment(os.environ)
    except RemoteMCPConfigurationError:
        print("TAS Adapter MCP startup failed", file=sys.stderr)
        raise SystemExit(1) from None
    server.run("stdio")


if __name__ == "__main__":
    main()
