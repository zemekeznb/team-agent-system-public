"""HMAC-derived, replayable Lease tokens that are never persisted in plaintext."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping

from tas.domain.delivery import InboxItemId, LeaseToken
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


class LeaseTokenKeyUnavailableError(RuntimeError):
    """The key required to reconstruct a prior Lease response is unavailable."""


class HmacLeaseTokenProvider:
    def __init__(self, keys: Mapping[str, bytes], active_key_id: str) -> None:
        if (
            not isinstance(keys, Mapping)
            or not 1 <= len(keys) <= 8
            or any(
                not isinstance(key_id, str)
                or not key_id
                or len(key_id) > 64
                or not isinstance(key, bytes)
                or len(key) < 32
                for key_id, key in keys.items()
            )
            or active_key_id not in keys
        ):
            raise ValueError("Lease keyring requires 1..8 named 256-bit keys")
        self._keys = dict(keys)
        self.active_key_id = active_key_id

    def issue(
        self,
        actor_id: AgentId,
        request_key: IdempotencyKey,
        item_id: InboxItemId,
        attempt: int,
    ) -> tuple[LeaseToken, str]:
        return self.restore(
            actor_id, request_key, item_id, attempt, self.active_key_id
        ), self.active_key_id

    def restore(
        self,
        actor_id: AgentId,
        request_key: IdempotencyKey,
        item_id: InboxItemId,
        attempt: int,
        key_id: str,
    ) -> LeaseToken:
        if not isinstance(actor_id, AgentId):
            raise TypeError("actor_id must be AgentId")
        if not isinstance(request_key, IdempotencyKey):
            raise TypeError("request_key must be IdempotencyKey")
        if not isinstance(item_id, InboxItemId):
            raise TypeError("item_id must be InboxItemId")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValueError("attempt must be a positive integer")
        key = self._keys.get(key_id)
        if key is None:
            raise LeaseTokenKeyUnavailableError("Lease token key is unavailable")
        material = b"tas-lease-v1\0" + json.dumps(
            [actor_id.value, request_key.value, item_id.value, attempt],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        digest = hmac.new(key, material, hashlib.sha256).digest()
        encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return LeaseToken(f"tas_lease_{encoded}")
