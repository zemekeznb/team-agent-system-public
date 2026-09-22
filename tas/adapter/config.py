"""Strict, non-secret configuration for the local F3 Adapter."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


CONFIG_ENVIRONMENT_VARIABLE = "TAS_ADAPTER_CONFIG"
MAX_CONFIG_BYTES = 64 * 1024
SUPPORTED_API_VERSION = "1.0.0-draft.16"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AdapterConfigurationError(RuntimeError):
    """The Adapter cannot establish a safe local configuration boundary."""


class TestCommandProfile(BaseModel):
    """Owner-controlled fixed argv; the Agent can select but cannot rewrite it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    argv: tuple[str, ...] = Field(min_length=1, max_length=64)
    timeout_seconds: float = Field(default=300, strict=True, gt=0, le=1800)
    max_output_bytes: int = Field(
        default=1024 * 1024, strict=True, ge=1024, le=4 * 1024 * 1024
    )

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not argument
            or len(argument) > 4096
            or "\0" in argument
            for argument in value
        ):
            raise ValueError("test command arguments must be bounded non-empty strings")
        executable_windows = PureWindowsPath(value[0])
        executable_posix = PurePosixPath(value[0])
        if (
            executable_windows.is_absolute()
            or executable_posix.is_absolute()
            or ".." in executable_windows.parts
            or ".." in executable_posix.parts
        ):
            raise ValueError("test executable must be a workspace-relative path")
        for argument in value[1:]:
            windows = PureWindowsPath(argument)
            posix = PurePosixPath(argument)
            if (
                windows.is_absolute()
                or posix.is_absolute()
                or ".." in windows.parts
                or ".." in posix.parts
            ):
                raise ValueError("test command cannot contain an absolute or parent path")
        return value


class AdapterConfig(BaseModel):
    """Configuration contains no Credential or local Workspace path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(strict=True, ge=1, le=1)
    endpoint: str = Field(min_length=1, max_length=2048)
    tls_ca_file: str | None = Field(default=None, min_length=1, max_length=4096)
    credential_store: Literal["os_keyring"]
    credential_account: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    state_directory: str = Field(min_length=1, max_length=4096)
    test_commands: dict[str, TestCommandProfile] = Field(default_factory=dict)
    expected_api_version: str = Field(
        default=SUPPORTED_API_VERSION, min_length=1, max_length=64
    )
    connect_timeout_seconds: float = Field(default=5, strict=True, gt=0, le=30)
    read_timeout_seconds: float = Field(default=30, strict=True, gt=0, le=120)
    write_timeout_seconds: float = Field(default=30, strict=True, gt=0, le=120)
    pool_timeout_seconds: float = Field(default=5, strict=True, gt=0, le=30)
    max_response_bytes: int = Field(
        default=1024 * 1024, strict=True, ge=1024, le=4 * 1024 * 1024
    )

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        parsed = urlparse(value)
        if (
            value != value.strip()
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError(
                "endpoint must be an HTTPS origin without credentials, path, query or fragment"
            )
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("endpoint contains an invalid port") from error
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("endpoint contains an invalid port")
        return value.rstrip("/")

    @field_validator("tls_ca_file")
    @classmethod
    def validate_tls_ca_file(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = Path(value)
        try:
            if (
                value != value.strip()
                or "\0" in value
                or not path.is_absolute()
                or path.is_symlink()
                or (hasattr(path, "is_junction") and path.is_junction())
                or not path.is_file()
                or path.stat().st_size > 1024 * 1024
            ):
                raise ValueError("tls_ca_file must be a safe absolute CA bundle path")
        except OSError as error:
            raise ValueError("tls_ca_file is unavailable") from error
        return str(path)

    @field_validator("state_directory")
    @classmethod
    def validate_state_directory(cls, value: str) -> str:
        if value != value.strip() or "\0" in value or not Path(value).is_absolute():
            raise ValueError("state_directory must be an absolute local path")
        return value

    @field_validator("test_commands")
    @classmethod
    def validate_test_commands(
        cls, value: dict[str, TestCommandProfile]
    ) -> dict[str, TestCommandProfile]:
        if len(value) > 32 or any(_SAFE_NAME.fullmatch(name) is None for name in value):
            raise ValueError("test command profile names are invalid or excessive")
        return value

    @classmethod
    def from_file(cls, path: str | Path) -> AdapterConfig:
        config_path = Path(path)
        if not config_path.is_absolute() or not config_path.is_file():
            raise AdapterConfigurationError(
                "Adapter config must be an absolute path to an existing file"
            )
        try:
            if config_path.stat().st_size > MAX_CONFIG_BYTES:
                raise AdapterConfigurationError("Adapter config exceeds 64 KiB")
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise AdapterConfigurationError("Adapter config must be a JSON object")
            return cls.model_validate(raw)
        except AdapterConfigurationError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise AdapterConfigurationError("Adapter config is invalid") from error


def load_adapter_config(environment: Mapping[str, str]) -> AdapterConfig:
    raw_path = environment.get(CONFIG_ENVIRONMENT_VARIABLE)
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise AdapterConfigurationError(
            f"{CONFIG_ENVIRONMENT_VARIABLE} must be configured"
        )
    return AdapterConfig.from_file(raw_path)


def validate_adapter_credential(credential: str) -> str:
    if (
        not isinstance(credential, str)
        or not credential
        or credential != credential.strip()
        or len(credential) > 4096
        or any(character.isspace() for character in credential)
    ):
        raise AdapterConfigurationError(
            "Adapter Credential must be one non-whitespace value"
        )
    return credential
