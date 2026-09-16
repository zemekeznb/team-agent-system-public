"""F2-only local credential binding adapter.

This adapter proves server-side actor binding for local test fixtures. It is
not a production authentication or authorization implementation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from tas.observability.logging import get_logger


logger = get_logger("auth.local_credentials")


class InvalidCredentialError(ValueError):
    """Raised when a credential cannot be mapped to a configured principal."""


@dataclass(frozen=True, slots=True)
class LocalPrincipal:
    agent_id: str
    owner_id: str
    identity_source: str
    assurance_level: str
    is_test_fixture: bool


class CredentialRegistry:
    """Map token digests to immutable local principal bindings."""

    def __init__(self, bindings: dict[str, LocalPrincipal]) -> None:
        self._bindings = dict(bindings)

    @classmethod
    def empty(cls) -> CredentialRegistry:
        return cls({})

    @classmethod
    def from_bindings(
        cls, bindings: Iterable[tuple[str, str, str]]
    ) -> CredentialRegistry:
        mapped: dict[str, LocalPrincipal] = {}
        for token, agent_id, owner_id in bindings:
            digest = _token_digest(token)
            if digest in mapped:
                raise ValueError("Duplicate credential digest")
            mapped[digest] = LocalPrincipal(
                agent_id, owner_id, "local_fixture", "test_only", True
            )
        return cls(mapped)

    @classmethod
    def from_file(cls, path: str | Path) -> CredentialRegistry:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = raw.get("bindings") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            raise ValueError("Credential binding file must contain a bindings list")

        mapped: dict[str, LocalPrincipal] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Credential binding entries must be objects")
            digest = _required_string(entry, "token_sha256")
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError("token_sha256 must be a lowercase SHA-256 digest")
            if set(entry) != {
                "agent_id", "owner_id", "identity_source", "assurance_level",
                "is_test_fixture", "token_sha256",
            }:
                raise ValueError("Credential binding contains unsupported fields")
            if entry.get("identity_source") != "local_fixture":
                raise ValueError("identity_source must be local_fixture")
            if entry.get("assurance_level") != "test_only":
                raise ValueError("assurance_level must be test_only")
            if entry.get("is_test_fixture") is not True:
                raise ValueError("is_test_fixture must be true")
            if digest in mapped:
                raise ValueError("Duplicate credential digest")
            mapped[digest] = LocalPrincipal(
                agent_id=_required_string(entry, "agent_id"),
                owner_id=_required_string(entry, "owner_id"),
                identity_source="local_fixture",
                assurance_level="test_only",
                is_test_fixture=True,
            )
        return cls(mapped)

    def authenticate(self, token: str) -> LocalPrincipal:
        if not token:
            logger.info("auth.credential.rejected", extra={"error_code": "invalid_credential"})
            raise InvalidCredentialError("Invalid credential")
        principal = self._bindings.get(_token_digest(token))
        if principal is None:
            logger.info("auth.credential.rejected", extra={"error_code": "invalid_credential"})
            raise InvalidCredentialError("Invalid credential")
        logger.info(
            "auth.credential.accepted",
            extra={
                "actor_type": "agent",
                "actor_id": principal.agent_id,
                "owner_id": principal.owner_id,
                "identity_source": principal.identity_source,
                "assurance_level": principal.assurance_level,
                "is_test_fixture": principal.is_test_fixture,
            },
        )
        return principal


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _required_string(value: dict[str, object], key: str) -> str:
    field = value.get(key)
    if not isinstance(field, str) or not field:
        raise ValueError(f"{key} must be a non-empty string")
    return field
