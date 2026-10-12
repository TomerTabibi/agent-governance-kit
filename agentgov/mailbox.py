"""Agent mailbox: scoped send/read/ack, idempotent sends, and one wake per backlog.

Messages are data. Nothing in a message body can grant permission; that is the
approval gate's job.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable

from .audit import AuditLog
from .identity import AuthError, IdentityRegistry, require

# Receipt-only messages ("ack", "received") are deliberately not a type: they cost tokens and add noise.
ALLOWED_TYPES = frozenset({"task", "question", "blocker", "review", "result", "decision"})

WakeFn = Callable[[str, str], None]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    type TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    in_reply_to TEXT,
    idempotency_key TEXT NOT NULL,
    created_at REAL NOT NULL,
    acked_at REAL,
    UNIQUE (sender, idempotency_key)
);
"""


class ConflictError(Exception):
    """An idempotency key was reused with a different payload."""


@dataclass(frozen=True)
class Message:
    id: str
    seq: int
    sender: str
    recipient: str
    type: str
    subject: str
    body: str
    in_reply_to: str | None
    created_at: float


class Mailbox:
    def __init__(
        self,
        registry: IdentityRegistry,
        audit: AuditLog,
        recipients: Iterable[str],
        wake: WakeFn | None = None,
        path: str = ":memory:",
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._wake = wake
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        # A recipient is "armed" when it should be woken by the next message.
        self._armed = {recipient: True for recipient in recipients}

    def send(
        self,
        token: str,
        recipient: str,
        message_type: str,
        subject: str,
        body: str,
        idempotency_key: str,
        in_reply_to: str | None = None,
    ) -> str:
        sender = self._registry.verify(token)
        require(sender, "mailbox:send")
        if recipient not in self._armed:
            raise ValueError(f"unknown recipient {recipient!r}")
        if message_type not in ALLOWED_TYPES:
            raise ValueError(f"message type {message_type!r} is not allowed")
        if not body.strip():
            raise ValueError("message body is empty")
        if not 8 <= len(idempotency_key) <= 128:
            raise ValueError("idempotency_key must be 8-128 characters")

        payload = (recipient, message_type, subject, body, in_reply_to)
        with self._lock:
            existing = self._db.execute(
                "SELECT id, recipient, type, subject, body, in_reply_to FROM messages"
                " WHERE sender = ? AND idempotency_key = ?",
                (sender.principal_id, idempotency_key),
            ).fetchone()
            if existing:
                if tuple(existing[1:]) != payload:
                    raise ConflictError(f"idempotency key {idempotency_key!r} reused with a different payload")
                return existing[0]
            message_id = str(uuid.uuid4())
            self._db.execute(
                "INSERT INTO messages (id, sender, recipient, type, subject, body, in_reply_to,"
                " idempotency_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (message_id, sender.principal_id, *payload, idempotency_key, time.time()),
            )
            self._db.commit()
            should_wake = self._armed[recipient]
            self._armed[recipient] = False

        self._audit.record(
            "message.sent", sender.principal_id, message_id=message_id, recipient=recipient, type=message_type
        )
        if should_wake:
            self._notify(recipient, message_id)
        return message_id

    def inbox(self, token: str) -> list[Message]:
        """Unacknowledged messages for the caller, oldest first."""
        reader = self._registry.verify(token)
        require(reader, "mailbox:read")
        with self._lock:
            rows = self._db.execute(
                "SELECT id, seq, sender, recipient, type, subject, body, in_reply_to, created_at"
                " FROM messages WHERE recipient = ? AND acked_at IS NULL ORDER BY seq",
                (reader.principal_id,),
            ).fetchall()
        return [Message(*row) for row in rows]

    def ack(self, token: str, message_id: str) -> None:
        """Acknowledge a message and everything before it.

        Acknowledging the newest message re-arms the wake. If newer messages
        arrived meanwhile, the recipient is woken again so nothing is missed.
        """
        reader = self._registry.verify(token)
        require(reader, "mailbox:ack")
        recipient = reader.principal_id
        with self._lock:
            row = self._db.execute(
                "SELECT seq FROM messages WHERE id = ? AND recipient = ?", (message_id, recipient)
            ).fetchone()
            if row is None:
                raise AuthError("no such message in your inbox")
            self._db.execute(
                "UPDATE messages SET acked_at = ? WHERE recipient = ? AND seq <= ? AND acked_at IS NULL",
                (time.time(), recipient, row[0]),
            )
            self._db.commit()
            newer = self._db.execute(
                "SELECT id FROM messages WHERE recipient = ? AND seq > ? AND acked_at IS NULL ORDER BY seq LIMIT 1",
                (recipient, row[0]),
            ).fetchone()
            self._armed[recipient] = newer is None

        self._audit.record("message.acked", recipient, message_id=message_id)
        if newer:
            self._notify(recipient, newer[0])

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _notify(self, recipient: str, message_id: str) -> None:
        if self._wake is None:
            return
        try:
            self._wake(recipient, message_id)
        except Exception as error:  # a failed wake must not lose the next one
            with self._lock:
                self._armed[recipient] = True
            self._audit.record("wake.failed", "mailbox", recipient=recipient, error=type(error).__name__)
