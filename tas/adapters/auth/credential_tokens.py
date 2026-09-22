"""Opaque Credential token generation and server-peppered digest verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping

from tas.domain.credential import (
    CredentialId,
    CredentialKeyUnavailableError,
    CredentialTokenError,
)
from tas.domain.identity import DomainValidationError


_TOKEN = re.compile(
    r"^tas_f3_([A-Za-z0-9][A-Za-z0-9_-]{0,127})\.([A-Za-z0-9_-]{43,128})$"
)
_TOKEN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


class CredentialTokenCodec:
    def __init__(
        self,
        keys: Mapping[str, bytes],
        primary_key_id: str,
        *,
        secret_factory: Callable[[int], str] = secrets.token_urlsafe,
    ) -> None:
        if (
            not isinstance(keys, Mapping)
            or not 1 <= len(keys) <= 8
            or any(
                not isinstance(key_id, str)
                or not key_id
                or len(key_id) > 64
                or not isinstance(value, bytes)
                or len(value) < 32
                for key_id, value in keys.items()
            )
            or primary_key_id not in keys
        ):
            raise ValueError("Credential keyring requires 1..8 named 256-bit keys")
        if not callable(secret_factory):
            raise TypeError("secret_factory must be callable")
        self._keys = dict(keys)
        self.primary_key_id = primary_key_id
        self._secret_factory = secret_factory

    def issue(self, credential_id: CredentialId) -> tuple[str, str, str]:
        if not isinstance(credential_id, CredentialId):
            raise TypeError("credential_id must be CredentialId")
        if _TOKEN_ID.fullmatch(credential_id.value) is None:
            raise ValueError("Credential ID cannot be represented in a token")
        secret = self._secret_factory(32)
        if not isinstance(secret, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", secret):
            raise RuntimeError("Credential secret generator returned an invalid value")
        try:
            decoded = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
        except (ValueError, binascii.Error) as error:
            raise RuntimeError("Credential secret generator returned an invalid value") from error
        if len(decoded) < 32:
            raise RuntimeError("Credential secret generator returned insufficient entropy")
        token = f"tas_f3_{credential_id.value}.{secret}"
        return token, self._digest(credential_id, secret, self.primary_key_id), self.primary_key_id

    def identify(self, token: str) -> CredentialId:
        if not isinstance(token, str):
            raise CredentialTokenError("Invalid credential")
        match = _TOKEN.fullmatch(token)
        if match is None:
            raise CredentialTokenError("Invalid credential")
        try:
            return CredentialId(match.group(1))
        except DomainValidationError as error:
            raise CredentialTokenError("Invalid credential") from error

    def verify(
        self,
        token: str,
        credential_id: CredentialId,
        key_id: str,
        expected_digest: str,
    ) -> bool:
        identified = self.identify(token)
        if identified != credential_id:
            return False
        match = _TOKEN.fullmatch(token)
        assert match is not None
        actual = self._digest(credential_id, match.group(2), key_id)
        return hmac.compare_digest(actual, expected_digest)

    def _digest(self, credential_id: CredentialId, secret: str, key_id: str) -> str:
        key = self._keys.get(key_id)
        if key is None:
            raise CredentialKeyUnavailableError("Credential digest key is unavailable")
        message = (
            b"tas-credential-v1\0"
            + credential_id.value.encode("utf-8")
            + b"\0"
            + secret.encode("ascii")
        )
        return hmac.new(key, message, hashlib.sha256).hexdigest()
