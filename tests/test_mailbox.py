import unittest

from agentgov import AuditLog, AuthError, ConflictError, IdentityRegistry, Mailbox

SCOPES = {"mailbox:send", "mailbox:read", "mailbox:ack"}


class MailboxTests(unittest.TestCase):
    def setUp(self):
        self.registry = IdentityRegistry()
        self.audit = AuditLog()
        self.wakes = []
        self.mailbox = Mailbox(self.registry, self.audit, ["a", "b"], wake=lambda r, m: self.wakes.append((r, m)))
        self.addCleanup(self.mailbox.close)
        self.a = self.registry.issue("a", "agent", SCOPES, 60)
        self.b = self.registry.issue("b", "agent", SCOPES, 60)

    def send(self, key, body="hello", token=None):
        return self.mailbox.send(token or self.a, "b", "task", "subject", body, idempotency_key=key)

    def test_send_requires_scope(self):
        reader_only = self.registry.issue("a", "agent", {"mailbox:read"}, 60)
        with self.assertRaises(AuthError):
            self.send("key-0001", token=reader_only)

    def test_receipt_only_types_rejected(self):
        with self.assertRaises(ValueError):
            self.mailbox.send(self.a, "b", "ack", "s", "received", idempotency_key="key-0001")

    def test_recipient_isolation(self):
        message_id = self.send("key-0001")
        self.assertEqual([m.id for m in self.mailbox.inbox(self.b)], [message_id])
        self.assertEqual(self.mailbox.inbox(self.a), [])
        with self.assertRaises(AuthError):
            self.mailbox.ack(self.a, message_id)

    def test_idempotent_send(self):
        first = self.send("key-0001")
        self.assertEqual(self.send("key-0001"), first)
        with self.assertRaises(ConflictError):
            self.send("key-0001", body="different")
        self.assertEqual(len(self.mailbox.inbox(self.b)), 1)

    def test_one_wake_until_newest_is_acked(self):
        first = self.send("key-0001")
        self.send("key-0002")
        self.assertEqual(self.wakes, [("b", first)])
        latest = self.mailbox.inbox(self.b)[-1].id
        self.mailbox.ack(self.b, latest)
        self.assertEqual(self.mailbox.inbox(self.b), [])
        third = self.send("key-0003")
        self.assertEqual(self.wakes[-1], ("b", third))

    def test_ack_of_older_message_rewakes_for_newer(self):
        first = self.send("key-0001")
        second = self.send("key-0002")
        self.mailbox.ack(self.b, first)
        self.assertEqual(self.wakes[-1], ("b", second))
        self.assertEqual([m.id for m in self.mailbox.inbox(self.b)], [second])

    def test_failed_wake_rearms(self):
        def failing(recipient, message_id):
            raise ConnectionError("listener down")

        mailbox = Mailbox(self.registry, self.audit, ["b"], wake=failing)
        self.addCleanup(mailbox.close)
        mailbox.send(self.a, "b", "task", "s", "one", idempotency_key="key-0001")
        calls = []
        mailbox._wake = lambda r, m: calls.append(m)
        second = mailbox.send(self.a, "b", "task", "s", "two", idempotency_key="key-0002")
        self.assertEqual(calls, [second])
        self.assertIn("wake.failed", [e["event"] for e in self.audit.entries()])


if __name__ == "__main__":
    unittest.main()
