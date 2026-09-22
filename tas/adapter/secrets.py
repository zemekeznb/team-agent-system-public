"""OS credential-store boundary for local Adapter secrets."""

from __future__ import annotations

from typing import Protocol

from tas.adapter.config import AdapterConfigurationError, validate_adapter_credential


KEYRING_SERVICE = "team-agent-system-f3-adapter"
SUPPORTED_NATIVE_BACKENDS = (
    "keyring.backends.Windows.",
    "keyring.backends.macOS.",
    "keyring.backends.SecretService.",
    "keyring.backends.kwallet.",
)


class CredentialStoreError(RuntimeError):
    """The local OS credential store is unavailable or missing the token."""


class KeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class OSCredentialStore:
    """Use Python keyring only through its selected native OS backend."""

    def __init__(self, backend: KeyringBackend | None = None) -> None:
        self._backend = backend if backend is not None else self._load_backend()

    @staticmethod
    def _load_backend() -> KeyringBackend:
        try:
            import keyring

            backend = keyring.get_keyring()
            backend_type = type(backend)
            qualified_name = f"{backend_type.__module__}.{backend_type.__qualname__}"
            if (
                float(getattr(backend, "priority", 0)) <= 0
                or not qualified_name.startswith(SUPPORTED_NATIVE_BACKENDS)
            ):
                raise CredentialStoreError(
                    "No supported native OS credential-store backend is available"
                )
            return backend
        except CredentialStoreError:
            raise
        except (ImportError, RuntimeError, TypeError, ValueError) as error:
            raise CredentialStoreError(
                "OS credential-store support is unavailable"
            ) from error

    def get(self, account: str) -> str:
        try:
            credential = self._backend.get_password(KEYRING_SERVICE, account)
        except Exception as error:
            raise CredentialStoreError("OS credential-store read failed") from error
        if credential is None:
            raise CredentialStoreError("Adapter Credential is not installed")
        try:
            return validate_adapter_credential(credential)
        except AdapterConfigurationError as error:
            raise CredentialStoreError("Stored Adapter Credential is invalid") from error

    def set(self, account: str, credential: str) -> None:
        try:
            validate_adapter_credential(credential)
        except AdapterConfigurationError as error:
            raise CredentialStoreError("Adapter Credential is invalid") from error
        try:
            self._backend.set_password(KEYRING_SERVICE, account, credential)
        except Exception as error:
            raise CredentialStoreError("OS credential-store write failed") from error

    def delete(self, account: str) -> bool:
        try:
            if self._backend.get_password(KEYRING_SERVICE, account) is None:
                return False
            self._backend.delete_password(KEYRING_SERVICE, account)
            return True
        except Exception as error:
            raise CredentialStoreError("OS credential-store delete failed") from error
