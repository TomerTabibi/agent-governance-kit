"""Approval gate: sensitive actions run only after a human approves that exact action, once."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, TypeVar

from .audit import AuditLog
from .identity import APPROVAL_SCOPE, AuthError, IdentityRegistry, require

T = TypeVar("T")


@dataclass(frozen=True)
class Action:
    kind: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        canonical = json.dumps(
            {"kind": self.kind, "target": self.target, "params": self.params},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    requester: str
    action: Action
    fingerprint: str
    status: str  # pending | approved | rejected | used
    created_at: float
    decided_by: str | None = None
    note: str = ""


class ApprovalRequired(Exception):
    def __init__(self, request_id: str) -> None:
        super().__init__(f"human approval required (request {request_id})")
        self.request_id = request_id


class ApprovalError(Exception):
    """The action cannot run under the given request."""


class ApprovalGate:
    def __init__(self, registry: IdentityRegistry, audit: AuditLog, sensitive_kinds: Iterable[str]) -> None:
        self._registry = registry
        self._audit = audit
        self._sensitive = frozenset(sensitive_kinds)
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def execute(self, token: str, action: Action, run: Callable[[], T], request_id: str | None = None) -> T:
        """Run an action. Sensitive actions need an approved request created by the same principal."""
        actor = self._registry.verify(token)
        require(actor, f"action:{action.kind}")
        if action.kind not in self._sensitive:
            self._audit.record("action.executed", actor.principal_id, kind=action.kind, target=action.target)
            return run()

        with self._lock:
            if request_id is None:
                request = ApprovalRequest(
                    id=str(uuid.uuid4()),
                    requester=actor.principal_id,
                    action=action,
                    fingerprint=action.fingerprint(),
                    status="pending",
                    created_at=time.time(),
                )
                self._requests[request.id] = request
            else:
                request = self._requests.get(request_id)
                problem = self._problem(request, actor.principal_id, action)
                if problem is None:
                    self._requests[request_id] = replace(request, status="used")

        if request_id is None:
            self._audit.record(
                "approval.requested", actor.principal_id, request_id=request.id,
                kind=action.kind, target=action.target, fingerprint=request.fingerprint,
            )
            raise ApprovalRequired(request.id)
        if problem is not None:
            self._audit.record("action.blocked", actor.principal_id, request_id=request_id, reason=problem)
            raise ApprovalError(problem)
        self._audit.record(
            "action.executed", actor.principal_id, kind=action.kind, target=action.target, request_id=request_id
        )
        return run()

    def approve(self, human_token: str, request_id: str, fingerprint: str, note: str = "") -> None:
        """Approve exactly the action the human was shown, identified by its fingerprint."""
        self._decide(human_token, request_id, fingerprint, "approved", note)

    def reject(self, human_token: str, request_id: str, note: str = "") -> None:
        with self._lock:
            request = self._requests.get(request_id)
        self._decide(human_token, request_id, request.fingerprint if request else "", "rejected", note)

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return [request for request in self._requests.values() if request.status == "pending"]

    def get(self, request_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._requests.get(request_id)

    def _decide(self, human_token: str, request_id: str, fingerprint: str, status: str, note: str) -> None:
        decider = self._registry.verify(human_token)
        if decider.kind != "human" or not decider.has(APPROVAL_SCOPE):
            self._audit.record("approval.denied", decider.principal_id, request_id=request_id, reason="not a human approver")
            raise AuthError("only a human with the approval scope can decide")
        with self._lock:
            request = self._requests.get(request_id)
            if request is None or request.status != "pending":
                raise ApprovalError("request is not pending")
            if request.fingerprint != fingerprint:
                raise ApprovalError("fingerprint does not match the requested action")
            self._requests[request_id] = replace(request, status=status, decided_by=decider.principal_id, note=note)
        self._audit.record(f"approval.{status}", decider.principal_id, request_id=request_id, note=note)

    @staticmethod
    def _problem(request: ApprovalRequest | None, principal_id: str, action: Action) -> str | None:
        if request is None:
            return "unknown request"
        if request.requester != principal_id:
            return "request belongs to another principal"
        if request.fingerprint != action.fingerprint():
            return "action differs from what was approved"
        if request.status != "approved":
            return f"request is {request.status}"
        return None
