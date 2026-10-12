"""Agent Governance Kit: identities, mailbox, approval gates, audit and event-driven wake for AI agents."""

from .approvals import Action, ApprovalError, ApprovalGate, ApprovalRequired
from .audit import AuditLog, verify_entries
from .identity import APPROVAL_SCOPE, AuthError, Identity, IdentityRegistry
from .mailbox import ConflictError, Mailbox, Message
from .wake import WakeListener, WakeRouter

__all__ = [
    "APPROVAL_SCOPE",
    "Action",
    "ApprovalError",
    "ApprovalGate",
    "ApprovalRequired",
    "AuditLog",
    "AuthError",
    "ConflictError",
    "Identity",
    "IdentityRegistry",
    "Mailbox",
    "Message",
    "WakeListener",
    "WakeRouter",
    "verify_entries",
]
