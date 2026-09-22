"""Command-line entry point for local Adapter diagnostics."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

from tas.adapter.config import (
    AdapterConfigurationError,
    load_adapter_config,
    validate_adapter_credential,
)
from tas.adapter.http_client import AdapterClientError, TASRemoteClient
from tas.adapter.secrets import CredentialStoreError, OSCredentialStore
from tas.adapter.workspaces import LocalWorkspaceError, LocalWorkspaceStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tas-adapter")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "smoke",
        help="run a bounded API compatibility and authenticated Session check",
    )
    commands.add_parser(
        "credential-set",
        help="store an interactively entered Credential in the native OS keyring",
    )
    commands.add_parser(
        "credential-delete",
        help="remove the configured Credential from the native OS keyring",
    )
    workspace = commands.add_parser(
        "workspace-register",
        help="register the current Git root and persist its opaque local mapping",
    )
    workspace.add_argument("--task-id", required=True)
    workspace.add_argument("--repository", required=True)
    workspace.add_argument("--idempotency-key", required=True)
    return parser


def run(
    arguments: list[str],
    environment: dict[str, str],
    *,
    store_factory: Callable[[], OSCredentialStore] = OSCredentialStore,
    client_factory: Callable[..., TASRemoteClient] = TASRemoteClient,
    credential_reader: Callable[[str], str] = getpass.getpass,
    interactive: bool | None = None,
) -> int:
    parsed_arguments = _parser().parse_args(arguments)
    command = parsed_arguments.command
    try:
        config = load_adapter_config(environment)
        store = store_factory()
        if command == "credential-set":
            if interactive is False or (interactive is None and not sys.stdin.isatty()):
                raise AdapterConfigurationError(
                    "Credential installation requires an interactive terminal"
                )
            credential = validate_adapter_credential(
                credential_reader("TAS Adapter Credential: ")
            )
            store.set(config.credential_account, credential)
            result = {"status": "stored", "account": config.credential_account}
        elif command == "credential-delete":
            removed = store.delete(config.credential_account)
            result = {
                "status": "deleted" if removed else "not_found",
                "account": config.credential_account,
            }
        elif command == "workspace-register":
            credential = store.get(config.credential_account)
            workspaces = LocalWorkspaceStore(config.state_directory)
            root = workspaces.validate_root(Path.cwd())
            with client_factory(config, credential) as client:
                session = client.smoke()
                if session.agent_id is None:
                    raise AdapterConfigurationError(
                        "Workspace registration requires an Agent Credential"
                    )
                workspace = client.register_workspace(
                    idempotency_key=parsed_arguments.idempotency_key,
                    task_id=parsed_arguments.task_id,
                    repository=parsed_arguments.repository,
                )
            if (
                workspace.task_id != parsed_arguments.task_id
                or workspace.repository != parsed_arguments.repository
                or workspace.actor_agent_id != session.agent_id
            ):
                raise AdapterConfigurationError(
                    "Central Workspace binding differs from the local request"
                )
            workspaces.bind(
                workspace_id=workspace.id,
                task_id=workspace.task_id,
                agent_id=workspace.actor_agent_id,
                repository=workspace.repository,
                workspace_root=root,
            )
            result = {
                "status": "registered",
                "workspace_id": workspace.id,
                "task_id": workspace.task_id,
                "repository": workspace.repository,
                "replayed": workspace.replayed,
                "correlation_id": workspace.correlation_id,
            }
        else:
            credential = store.get(config.credential_account)
            with client_factory(config, credential) as client:
                session = client.smoke()
            result = {
                "status": "ok",
                "owner_id": session.owner_id,
                "agent_id": session.agent_id,
                "credential_id": session.credential_id,
                "expires_at": session.expires_at.isoformat(),
                "correlation_id": session.correlation_id,
            }
    except (
        AdapterConfigurationError,
        CredentialStoreError,
        AdapterClientError,
        LocalWorkspaceError,
    ) as error:
        print(
            json.dumps(
                {"status": "error", "error": type(error).__name__},
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


def main() -> None:
    raise SystemExit(run(sys.argv[1:], dict(os.environ)))


if __name__ == "__main__":
    main()
