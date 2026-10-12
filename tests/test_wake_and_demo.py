import contextlib
import io
import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from agentgov.demo import run_demo
from agentgov.wake import WakeListener, send_wake, sign

SECRET = b"s" * 32


class WakeListenerTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.received = threading.Event()

        def handler(event):
            self.events.append(event)
            self.received.set()

        self.listener = WakeListener(SECRET, handler).start()
        self.addCleanup(self.listener.stop)

    def post(self, payload, secret=SECRET, timestamp=None):
        body = json.dumps(payload).encode()
        timestamp = timestamp or str(int(time.time()))
        request = urllib.request.Request(self.listener.url, data=body, method="POST", headers={
            "X-Wake-Timestamp": timestamp, "X-Wake-Signature": sign(secret, timestamp, body)})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_valid_wake_delivered(self):
        send_wake(self.listener.url, SECRET, {"event_id": "e1", "message_id": "m1"})
        self.assertTrue(self.received.wait(5))
        self.assertEqual(self.events[0]["message_id"], "m1")

    def test_bad_signature_rejected(self):
        self.assertEqual(self.post({"event_id": "e1"}, secret=b"x" * 32), 401)

    def test_stale_timestamp_rejected(self):
        self.assertEqual(self.post({"event_id": "e1"}, timestamp=str(int(time.time()) - 3600)), 401)

    def test_replay_rejected(self):
        self.assertEqual(self.post({"event_id": "e1"}), 204)
        self.assertEqual(self.post({"event_id": "e1"}), 409)


class DemoTests(unittest.TestCase):
    def run_quietly(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return run_demo(auto_approve=True, **kwargs)

    def test_approved_push_runs(self):
        result = self.run_quietly(approve=True)
        self.assertTrue(result["pushed"])
        self.assertTrue(result["injection_blocked"])
        self.assertTrue(result["self_approval_blocked"])
        self.assertTrue(result["audit_valid"])
        self.assertTrue(result["tamper_detected"])
        self.assertEqual(result["audit_events"]["action.executed"], 1)

    def test_rejected_push_does_not_run(self):
        result = self.run_quietly(approve=False)
        self.assertFalse(result["pushed"])
        self.assertEqual(result["audit_events"]["action.blocked"], 1)
        self.assertNotIn("action.executed", result["audit_events"])


if __name__ == "__main__":
    unittest.main()
