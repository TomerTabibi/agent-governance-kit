import unittest

from agentgov import APPROVAL_SCOPE, Action, ApprovalError, ApprovalGate, ApprovalRequired, AuditLog, AuthError, IdentityRegistry


class ApprovalGateTests(unittest.TestCase):
    def setUp(self):
        self.registry = IdentityRegistry()
        self.audit = AuditLog()
        self.gate = ApprovalGate(self.registry, self.audit, sensitive_kinds={"git.push"})
        scopes = {"action:git.push", "action:lint"}
        self.dev = self.registry.issue("dev", "agent", scopes, 60)
        self.other = self.registry.issue("other", "agent", scopes, 60)
        self.owner = self.registry.issue("owner", "human", {APPROVAL_SCOPE}, 60)
        self.push = Action("git.push", "origin/feature", {"commit": "abc"})

    def request(self):
        with self.assertRaises(ApprovalRequired) as held:
            self.gate.execute(self.dev, self.push, lambda: "pushed")
        return self.gate.get(held.exception.request_id)

    def test_non_sensitive_action_runs(self):
        self.assertEqual(self.gate.execute(self.dev, Action("lint", "repo"), lambda: "ok"), "ok")

    def test_action_scope_required(self):
        no_scope = self.registry.issue("dev", "agent", set(), 60)
        with self.assertRaises(AuthError):
            self.gate.execute(no_scope, self.push, lambda: None)

    def test_human_approval_runs_exactly_once(self):
        request = self.request()
        with self.assertRaises(ApprovalError):
            self.gate.execute(self.dev, self.push, lambda: "pushed", request_id=request.id)
        self.gate.approve(self.owner, request.id, request.fingerprint)
        self.assertEqual(self.gate.execute(self.dev, self.push, lambda: "pushed", request_id=request.id), "pushed")
        with self.assertRaises(ApprovalError):
            self.gate.execute(self.dev, self.push, lambda: "pushed", request_id=request.id)

    def test_agent_cannot_approve(self):
        request = self.request()
        with self.assertRaises(AuthError):
            self.gate.approve(self.dev, request.id, request.fingerprint)
        self.assertEqual(self.gate.get(request.id).status, "pending")

    def test_human_without_approval_scope_cannot_approve(self):
        request = self.request()
        viewer = self.registry.issue("viewer", "human", set(), 60)
        with self.assertRaises(AuthError):
            self.gate.approve(viewer, request.id, request.fingerprint)

    def test_approval_bound_to_exact_action(self):
        request = self.request()
        with self.assertRaises(ApprovalError):
            self.gate.approve(self.owner, request.id, "0" * 64)
        self.gate.approve(self.owner, request.id, request.fingerprint)
        to_main = Action("git.push", "origin/main", {"commit": "abc"})
        with self.assertRaises(ApprovalError):
            self.gate.execute(self.dev, to_main, lambda: None, request_id=request.id)

    def test_approval_bound_to_requester(self):
        request = self.request()
        self.gate.approve(self.owner, request.id, request.fingerprint)
        with self.assertRaises(ApprovalError):
            self.gate.execute(self.other, self.push, lambda: None, request_id=request.id)

    def test_rejected_request_cannot_run(self):
        request = self.request()
        self.gate.reject(self.owner, request.id)
        with self.assertRaises(ApprovalError):
            self.gate.execute(self.dev, self.push, lambda: None, request_id=request.id)

    def test_decisions_are_audited(self):
        request = self.request()
        self.gate.approve(self.owner, request.id, request.fingerprint)
        self.gate.execute(self.dev, self.push, lambda: None, request_id=request.id)
        events = [e["event"] for e in self.audit.entries()]
        self.assertEqual(events, ["approval.requested", "approval.approved", "action.executed"])
        self.assertTrue(self.audit.verify())


if __name__ == "__main__":
    unittest.main()
