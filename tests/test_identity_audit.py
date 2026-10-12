import json
import tempfile
import unittest
from pathlib import Path

from agentgov import APPROVAL_SCOPE, AuditLog, AuthError, IdentityRegistry, verify_entries
from agentgov.identity import require


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.registry = IdentityRegistry(clock=lambda: self.now)

    def test_issue_and_verify(self):
        token = self.registry.issue("dev", "agent", {"mailbox:send"}, ttl_seconds=60)
        identity = self.registry.verify(token)
        self.assertEqual(identity.principal_id, "dev")
        self.assertTrue(identity.has("mailbox:send"))
        with self.assertRaises(AuthError):
            require(identity, "mailbox:read")

    def test_expired_token_rejected(self):
        token = self.registry.issue("dev", "agent", set(), ttl_seconds=60)
        self.now += 61
        with self.assertRaises(AuthError):
            self.registry.verify(token)

    def test_tampered_token_rejected(self):
        token = self.registry.issue("dev", "agent", {"mailbox:send"}, ttl_seconds=60)
        forged = self.registry.issue("dev", "agent", {"mailbox:send", "mailbox:read"}, ttl_seconds=60)
        with self.assertRaises(AuthError):
            self.registry.verify(forged.split(".")[0] + "." + token.split(".")[1])

    def test_other_registry_token_rejected(self):
        token = IdentityRegistry().issue("dev", "agent", set(), ttl_seconds=60)
        with self.assertRaises(AuthError):
            self.registry.verify(token)

    def test_revoked_token_rejected(self):
        token = self.registry.issue("dev", "agent", set(), ttl_seconds=60)
        self.registry.revoke(token)
        with self.assertRaises(AuthError):
            self.registry.verify(token)

    def test_agent_cannot_hold_approval_scope(self):
        with self.assertRaises(ValueError):
            self.registry.issue("dev", "agent", {APPROVAL_SCOPE}, ttl_seconds=60)
        self.registry.issue("owner", "human", {APPROVAL_SCOPE}, ttl_seconds=60)


class AuditTests(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        log = AuditLog()
        log.record("a", "x", value=1)
        log.record("b", "y", value=2)
        self.assertTrue(log.verify())
        entries = log.entries()
        entries[0]["data"]["value"] = 99
        self.assertFalse(verify_entries(entries))
        self.assertFalse(verify_entries(log.entries()[1:]))

    def test_persisted_log_reloads_and_detects_file_edit(self):
        path = Path(tempfile.mkdtemp()) / "audit.jsonl"
        log = AuditLog(path)
        log.record("a", "x")
        log.record("b", "y")
        self.assertTrue(AuditLog(path).verify())
        lines = path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["actor"] = "intruder"
        path.write_text("\n".join([json.dumps(first), *lines[1:]]) + "\n", encoding="utf-8")
        self.assertFalse(AuditLog(path).verify())


if __name__ == "__main__":
    unittest.main()
