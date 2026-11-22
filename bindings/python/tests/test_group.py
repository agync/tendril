import base64
import json
import socket
import tempfile
import threading
import time
import unittest

import tendril


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def free_addr() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{s.getsockname()[1]}"


def pair(host: "tendril.Endpoint", cli: "tendril.Endpoint") -> None:
    """Enrolls `cli` with `host` over the M2M flow, which pins both signing keys."""
    host_info = json.loads(host.info_json())
    host_addr = host.serve_direct("127.0.0.1:0")
    token = host.mint_enrollment_token(host_info["host_id"], None, 900)
    accepted: dict = {}

    def accept() -> None:
        accepted["res"] = json.loads(host.pair_accept(8000))

    t = threading.Thread(target=accept)
    t.start()
    res = json.loads(
        cli.enroll_initiate(
            host_addr,
            host_info["host_id"],
            b64url_decode(host_info["static_pub"]),
            b64url_decode(host_info["signing_pub"]),
            token,
            name="py-group",
            kind="machine",
        )
    )
    t.join(timeout=10)
    assert res["status"] == "active" and accepted["res"]["status"] == "active"


def next_event(group: "tendril.Group", kind: str, timeout_s: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        raw = group.poll_event(500)
        if raw is None:
            continue
        ev = json.loads(raw)
        if ev["event"] == kind:
            return ev
    raise AssertionError(f"no {kind} event within {timeout_s}s")


class GroupTests(unittest.TestCase):
    def test_group_broadcast_over_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                pair(a, b)
                a_id = json.loads(a.info_json())["device_id"]
                b_id = json.loads(b.info_json())["device_id"]
                addr_a, addr_b = free_addr(), free_addr()

                m1 = json.loads(a.group_create("py-group", 1, [addr_a]))
                gid = m1["group_id"]
                m2_json = a.group_add_member(gid, b_id, None, [addr_b])
                self.assertEqual(json.loads(m2_json)["seq"], m1["seq"] + 1)
                self.assertNotIn("rendezvous", m2_json)

                self.assertEqual(b.group_ingest_manifest(m2_json, a_id), gid)

                with a.group_open(gid, addr_a) as ga, b.group_open(gid, addr_b) as gb:
                    self.assertEqual(ga.group_id, gid)
                    self.assertTrue(ga.authorize_peer(b_id, f"group.send:{gid}"))
                    with self.assertRaises(RuntimeError):
                        ga.authorize_peer(b_id, f"group.admin:{gid}")

                    report = json.loads(ga.broadcast(b"hello group"))
                    self.assertEqual(report["delivered"], [b_id], report)
                    ev = next_event(gb, "app_data")
                    self.assertEqual(ev["sender_device_id"], a_id)
                    self.assertEqual(b64url_decode(ev["payload_b64"]), b"hello group")

                    report = json.loads(gb.broadcast(b"reply", f"group.send:{gid}"))
                    self.assertEqual(report["delivered"], [a_id], report)
                    ev = next_event(ga, "app_data")
                    self.assertEqual(b64url_decode(ev["payload_b64"]), b"reply")

                    with self.assertRaisesRegex(RuntimeError, "denied"):
                        gb.broadcast(b"x", f"group.admin:{gid}")

                    gb.close()
                    gb.close()
                    with self.assertRaisesRegex(RuntimeError, "closed"):
                        gb.broadcast(b"x")
                    with self.assertRaisesRegex(RuntimeError, "closed"):
                        gb.poll_event(10)
                    with self.assertRaisesRegex(RuntimeError, "closed"):
                        gb.authorize_peer(a_id, f"group.send:{gid}")
            finally:
                b.close()
                a.close()

    def test_wire_v2_group_sync_then_broadcast(self) -> None:
        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                pair(a, b)
                a_id = json.loads(a.info_json())["device_id"]
                b_id = json.loads(b.info_json())["device_id"]
                addr_a, addr_b = free_addr(), free_addr()
                gid = json.loads(a.group_create("py-group-v2", 2, [addr_a]))["group_id"]
                m2 = a.group_add_member(gid, b_id, None, [addr_b])
                self.assertEqual(b.group_ingest_manifest(m2, a_id), gid)

                with b.group_open(gid, addr_b) as gb, a.group_open(gid, addr_a) as ga:
                    report = json.loads(ga.sync())
                    self.assertEqual(report["delivered"], [b_id], report)

                    deadline = time.monotonic() + 10
                    while True:
                        report = json.loads(ga.broadcast(b"v2 hello"))
                        if report["delivered"] == [b_id] or time.monotonic() > deadline:
                            break
                        time.sleep(0.2)
                    self.assertEqual(report["delivered"], [b_id], report)
                    ev = next_event(gb, "app_data")
                    self.assertEqual(ev["sender_device_id"], a_id)
                    self.assertEqual(b64url_decode(ev["payload_b64"]), b"v2 hello")

                    report = json.loads(gb.broadcast(b"v2 reply"))
                    self.assertEqual(report["delivered"], [a_id], report)
                    ev = next_event(ga, "app_data")
                    self.assertEqual(b64url_decode(ev["payload_b64"]), b"v2 reply")

                    ga.close()
                    with self.assertRaisesRegex(RuntimeError, "closed"):
                        ga.sync()
            finally:
                b.close()
                a.close()

    def test_remove_member_and_non_root_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                pair(a, b)
                a_id = json.loads(a.info_json())["device_id"]
                b_id = json.loads(b.info_json())["device_id"]
                addr_a, addr_b = free_addr(), free_addr()
                gid = json.loads(a.group_create("py-group", 1, [addr_a]))["group_id"]
                m2 = a.group_add_member(gid, b_id, [], [addr_b])
                b.group_ingest_manifest(m2, a_id)

                with self.assertRaisesRegex(RuntimeError, "authorization denied"):
                    b.group_add_member(gid, a_id, [], [])
                with self.assertRaisesRegex(RuntimeError, "authorization denied"):
                    b.group_remove_member(gid, a_id)

                m3 = json.loads(a.group_remove_member(gid, b_id))
                self.assertIn(b_id, m3["revoked_members"])
                self.assertEqual(m3["seq"], json.loads(m2)["seq"] + 1)
            finally:
                b.close()
                a.close()

    def test_ingest_refuses_non_signer_and_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                pair(a, b)
                a_id = json.loads(a.info_json())["device_id"]
                b_id = json.loads(b.info_json())["device_id"]
                gid = json.loads(a.group_create("py-group", 1, [free_addr()]))["group_id"]
                m2 = a.group_add_member(gid, b_id, [], [free_addr()])

                with self.assertRaisesRegex(RuntimeError, "authorization denied"):
                    b.group_ingest_manifest(m2, b_id)
                with self.assertRaises(RuntimeError):
                    b.group_ingest_manifest("{not json", a_id)
                self.assertEqual(b.group_ingest_manifest(m2, a_id), gid)
            finally:
                b.close()
                a.close()

    def test_session_group_frames_report_runtime_ingest_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                pair(a, b)
                b_id = json.loads(b.info_json())["device_id"]
                addr_a, addr_b = free_addr(), b.serve_direct("127.0.0.1:0")
                gid = json.loads(a.group_create("py-session", 2, [addr_a]))["group_id"]
                a.group_add_member(gid, b_id, None, [addr_b])
                seen: list = []

                def member() -> None:
                    sess = b.accept_session(10000)
                    # The admin counts the push as delivered only after this session
                    # answers its ping, and the answer is produced only while polling:
                    # keep polling until the admin closes it.
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        ev = json.loads(sess.poll_event(100))
                        if ev["status"] == "eof" or (
                            ev["status"] == "event" and ev["event"] == "closed"
                        ):
                            break
                        if ev["status"] == "event" and ev["event"].startswith("group_"):
                            seen.append(ev)

                t = threading.Thread(target=member)
                t.start()
                with a.group_open(gid, addr_a) as ga:
                    report = json.loads(ga.sync())
                    t.join(timeout=20)
                    self.assertEqual(report["delivered"], [b_id], report)
                self.assertEqual(
                    [ev["event"] for ev in seen],
                    ["group_manifest_ingested", "group_rendezvous_ingested"],
                    seen,
                )
                for ev in seen:
                    self.assertEqual(ev["group_id"], gid)
                    self.assertEqual(
                        sorted(ev), ["event", "group_id", "seq", "status"], ev
                    )
                with b.group_open(gid) as gb:
                    self.assertEqual(gb.group_id, gid)
            finally:
                b.close()
                a.close()

    def test_endpoint_close_closes_open_groups(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ep = tendril.Endpoint(d)
            gid = json.loads(ep.group_create("py-close", 1, []))["group_id"]
            addr = free_addr()
            g1 = ep.group_open(gid, addr)
            g2 = ep.group_open(gid, None)
            ep.close()
            for g in (g1, g2):
                with self.assertRaisesRegex(RuntimeError, "group is closed"):
                    g.sync()
                with self.assertRaisesRegex(RuntimeError, "group is closed"):
                    g.broadcast(b"x")
                with self.assertRaisesRegex(RuntimeError, "group is closed"):
                    g.poll_event(10)

    def test_group_open_with_p2p_configured(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            ep = tendril.Endpoint(d)
            try:
                ep.configure_transports_json('{"p2p_relay_mode": "disabled"}')
                gid = json.loads(ep.group_create("py-p2p", 1, []))["group_id"]
                with ep.group_open(gid, None) as g:
                    self.assertEqual(g.group_id, gid)
            finally:
                ep.close()

    def test_group_open_without_relay_mode_adds_no_p2p_dialer(self) -> None:
        settings = [
            '{"p2p_pkarr": true}',
            '{"p2p_allow_private_addrs": true}',
            '{"p2p_advertise_direct_addrs": true}',
            '{"p2p_relay_auth_token": "tok"}',
        ]
        for raw in settings:
            with self.subTest(settings=raw), tempfile.TemporaryDirectory() as d:
                ep = tendril.Endpoint(d)
                try:
                    ep.configure_transports_json(raw)
                    gid = json.loads(ep.group_create("py-nop2p", 1, []))["group_id"]
                    with ep.group_open(gid, None) as g:
                        self.assertEqual(g.group_id, gid)
                finally:
                    ep.close()

    def test_group_requires_state_dir(self) -> None:
        ep = tendril.Endpoint(None)
        try:
            with self.assertRaisesRegex(RuntimeError, "state_dir"):
                ep.group_create("g", 2, [])
        finally:
            ep.close()


if __name__ == "__main__":
    unittest.main()
