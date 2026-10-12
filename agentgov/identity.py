"""Agent and human identities: signed, scoped, expiring tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable

APPROVAL_SCOPE = "approval:grant"
KINDS = ("agent", "human")


class AuthError(Exception):
    """A token is invalid, expired, revoked, or lacks a required scope."""


@dataclass(frozen=True)
class Identity:
    principal_id: str
    kind: str
    scopes: frozenset[str]
    expires_at: float
    token_id: str

    def has(self, scope: str) -> bool:
        return scope in self.scopes


def require(identity: Identity, scope: str) -> None:
    if not identity.has(scope):
        raise AuthError(f"{identity.principal_id} lacks scope {scope!r}")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class IdentityRegistry:
    """Issues and verifies tokens. Agents can never be issued the approval scope."""

    def __init__(self, secret: bytes | None = None, clock: Callable[[], float] = time.time) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._clock = clock
        self._revoked: set[str] = set()

    def issue(self, principal_id: str, kind: str, scopes: Iterable[str], ttl_seconds: float) -> str:
        scope_set = frozenset(scopes)
        if kind not in KINDS:
            raise ValueError(f"unknown principal kind {kind!r}")
        if kind == "agent" and APPROVAL_SCOPE in scope_set:
            raise ValueError("agents can never hold the approval scope")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        claims = {
            "sub": principal_id,
            "kind": kind,
            "scopes": sorted(scope_set),
            "exp": self._clock() + ttl_seconds,
            "jti": secrets.token_hex(8),
        }
        body = _b64e(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str) -> Identity:
        body, sep, signature = token.partition(".")
        if not sep or not hmac.compare_digest(signature, self._sign(body)):
            raise AuthError("invalid token")
        claims = json.loads(_b64d(body))
        if claims["jti"] in self._revoked:
            raise AuthError("token revoked")
        if claims["exp"] <= self._clock():
            raise AuthError("token expired")
        return Identity(
            principal_id=claims["sub"],
            kind=claims["kind"],
            scopes=frozenset(claims["scopes"]),
            expires_at=claims["exp"],
            token_id=claims["jti"],
        )

    def revoke(self, token: str) -> None:
        self._revoked.add(self.verify(token).token_id)

    def _sign(self, body: str) -> str:
        return _b64e(hmac.new(self._secret, body.encode("utf-8"), hashlib.sha256).digest())
