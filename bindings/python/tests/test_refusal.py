import json
import tempfile
import threading
import time
import unittest

import tendril


class Pair:
    """A confirmed host and client pair over loopback, paired on the given wire."""

    def __init__(self, v2: bool, confirm_host: bool = True) -> None:
        self.v2 = v2
        self._dir = tempfile.TemporaryDirectory()
        self.host = tendril.Endpoint(self._dir.name, "refusal-host")
        self.client = tendril.Endpoint(None, "refusal-client")
        self.addr = self.host.serve_direct("127.0.0.1:0")
        code = self.host.issue_code("lan")
        accepted: dict = {}
        accept = self.host.pair_v2_accept if v2 else self.host.pair_accept
        initiate = self.client.pair_v2_initiate if v2 else self.client.pair_initiate

        def run_accept() -> None:
            accepted.update(json.loads(accept(5000)))

        t = threading.Thread(target=run_accept)
        t.start()
        res = json.loads(initiate(self.addr, code))
        t.join(timeout=10)
        self.device_id = accepted["device_id"]
        self.client.confirm_peer("refusal-host", res["sas"])
        self.grant = ""
        if confirm_host:
            self.host.confirm_peer(self.device_id, res["sas"])
            self.grant = self.host.mint_grant(self.device_id, ["fs.read"], 3600)

    def connect(self) -> "tendril.Session":
        if self.v2:
            return self.client.connect_v2(self.addr, "refusal-host", self.grant or None)
        return self.client.connect(self.addr, "refusal-host", self.grant or None)

    def accept(self, results: list) -> threading.Thread:
        """Accepts one session on the host, as the server loop of an app does."""
        accept = self.host.accept_v2 if self.v2 else self.host.accept_session

        def run() -> None:
            try:
                results.append(accept(3000))
            except RuntimeError as err:
                results.append(err)

        t = threading.Thread(target=run)
        t.start()
        return t

    def connect_refused(self) -> RuntimeError:
        accepted: list = []
        t = self.accept(accepted)
        try:
            self.connect()
        except RuntimeError as err:
            return err
        finally:
            t.join(timeout=10)
        raise AssertionError("the connect succeeded")

    def close(self) -> None:
        self.host.close()
        self.client.close()
        self._dir.cleanup()


class RefusalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pairs: list = []

    def tearDown(self) -> None:
        for p in self.pairs:
            p.close()

    def pair(self, v2: bool, confirm_host: bool = True) -> Pair:
        p = Pair(v2, confirm_host)
        self.pairs.append(p)
        return p

    def test_refused_error_is_exported_and_a_runtime_error(self) -> None:
        self.assertTrue(issubclass(tendril.RefusedError, RuntimeError))

    def test_refused_v2_connect_raises_a_typed_error(self) -> None:
        p = self.pair(True)
        p.host.revoke_peer(p.device_id)
        err = p.connect_refused()
        self.assertIsInstance(err, tendril.RefusedError)
        self.assertEqual(err.reason, "revoked")
        self.assertEqual(err.close_code, 4001)
        self.assertEqual(err.code, "refused_revoked")
        self.assertIn("revoked", str(err))

    def test_pending_v2_connect_raises_a_typed_error(self) -> None:
        p = self.pair(True, confirm_host=False)
        err = p.connect_refused()
        self.assertIsInstance(err, tendril.RefusedError)
        self.assertEqual(err.reason, "pending")
        self.assertEqual(err.close_code, 4004)
        self.assertEqual(err.code, "refused_pending")

    def test_v1_refusal_surfaces_after_connect(self) -> None:
        p = self.pair(False)
        p.host.revoke_peer(p.device_id)
        accepted: list = []
        t = p.accept(accepted)
        try:
            sess = p.connect()
            closed = None
            deadline = time.monotonic() + 10
            while closed is None and time.monotonic() < deadline:
                ev = json.loads(sess.poll_event(500))
                if ev.get("event") == "closed":
                    closed = ev
            self.assertIsNotNone(closed, "no closed event")
            self.assertEqual(closed["refusal"], "revoked")
            self.assertEqual(closed["code"], 4001)
            with self.assertRaises(tendril.RefusedError) as ctx:
                sess.send_data(b"x")
            self.assertEqual(ctx.exception.reason, "revoked")
            self.assertEqual(ctx.exception.close_code, 4001)
            with self.assertRaises(tendril.RefusedError):
                sess.rekey()
            with self.assertRaises(tendril.RefusedError):
                sess.close()
        finally:
            t.join(timeout=10)

    def test_plain_close_carries_no_refusal(self) -> None:
        p = self.pair(False)
        accepted: list = []
        t = p.accept(accepted)
        sess = p.connect()
        t.join(timeout=10)
        host_sess = accepted[0]
        host_sess.close(1000, "bye")
        closed = None
        deadline = time.monotonic() + 10
        while closed is None and time.monotonic() < deadline:
            ev = json.loads(sess.poll_event(500))
            if ev.get("event") == "closed":
                closed = ev
        self.assertIsNotNone(closed)
        self.assertIsNone(closed["refusal"])

    def test_silent_revoke_leaves_no_notice(self) -> None:
        p = self.pair(True)
        p.host.revoke_peer(p.device_id, notify=False)
        err = p.connect_refused()
        self.assertNotIsInstance(err, tendril.RefusedError)

    def test_policy_without_notices(self) -> None:
        p = self.pair(True)
        p.host.set_refusal_policy(pending=True, revoked_notice_ttl_secs=0)
        p.host.revoke_peer(p.device_id)
        err = p.connect_refused()
        self.assertNotIsInstance(err, tendril.RefusedError)

    def test_clear_refusal_notice_keeps_the_peer_revoked(self) -> None:
        p = self.pair(True)
        p.host.revoke_peer(p.device_id)
        p.host.clear_refusal_notice(p.device_id)
        err = p.connect_refused()
        self.assertNotIsInstance(err, tendril.RefusedError)
        with self.assertRaises(RuntimeError):
            p.host.clear_refusal_notice("no-such-peer")

    def test_policy_arguments_are_validated(self) -> None:
        p = self.pair(True)
        with self.assertRaises(TypeError):
            p.host.set_refusal_policy(pending="yes")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
