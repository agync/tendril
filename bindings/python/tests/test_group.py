import base64
import json
import pathlib
import socket
import subprocess
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


ROOT = pathlib.Path(__file__).resolve().parents[3]
RELAY_BIN = ROOT / "target" / "debug" / "tendril-relay"
RELAY_SECRET = "tendril-group-relay-hmac-secret-32"


class AuthRelay:
    """A `tendril-relay` on loopback requiring HMAC admission with `RELAY_SECRET`.

    `host` is the relay's canonical host and the host of its URLs; it always binds 127.0.0.1.
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host

    def __enter__(self) -> "AuthRelay":
        if not RELAY_BIN.exists():
            subprocess.run(
                ["cargo", "build", "-p", "tendril-relay", "--bin", "tendril-relay"],
                cwd=str(ROOT),
                check=True,
            )
        self._dir = tempfile.TemporaryDirectory()
        secret_file = pathlib.Path(self._dir.name) / "relay.secret"
        secret_file.write_text(RELAY_SECRET, encoding="utf-8")
        secret_file.chmod(0o600)
        port = int(free_addr().rsplit(":", 1)[1])
        self._proc = subprocess.Popen(
            [
                str(RELAY_BIN),
                "--listen",
                f"127.0.0.1:{port}",
                "--host",
                self.host,
                "--auth-secret-file",
                str(secret_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self.__exit__(None, None, None)
            raise RuntimeError("tendril-relay did not listen in time")
        self.v1_url = f"ws://{self.host}:{port}/v1/relay"
        self.v2_url = f"ws://{self.host}:{port}/v2/relay"
        return self

    def __exit__(self, *exc) -> None:
        self._proc.terminate()
        self._proc.wait(timeout=5)
        self._dir.cleanup()


def with_relay_auth(*endpoints: "tendril.Endpoint") -> None:
    for ep in endpoints:
        ep.configure_transports_json(json.dumps({"relay_auth_secret": RELAY_SECRET}))


def broadcast_until(group: "tendril.Group", peer: str, payload: bytes) -> dict:
    deadline = time.monotonic() + 15
    while True:
        report = json.loads(group.broadcast(payload))
        if peer in report["delivered"] or time.monotonic() > deadline:
            return report
        time.sleep(0.2)


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

    def test_v2_relay_sibling_with_relay_auth(self) -> None:
        with AuthRelay() as relay, tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                with_relay_auth(a, b)
                pair(a, b)
                a_id = json.loads(a.info_json())["device_id"]
                b_id = json.loads(b.info_json())["device_id"]
                addr_b = free_addr()
                gid = json.loads(a.group_create("py-relay", 2, [relay.v2_url]))["group_id"]
                m2 = a.group_add_member(gid, b_id, None, [addr_b])
                self.assertEqual(b.group_ingest_manifest(m2, a_id), gid)

                with b.group_open(gid, addr_b) as gb, a.group_open(
                    gid, None, relay_listen=True
                ) as ga:
                    report = json.loads(ga.sync())
                    self.assertEqual(report["delivered"], [b_id], report)
                    report = broadcast_until(gb, a_id, b"over the relay")
                    self.assertEqual(report["delivered"], [a_id], report)
                    ev = next_event(ga, "app_data")
                    self.assertEqual(ev["sender_device_id"], b_id)
                    self.assertEqual(b64url_decode(ev["payload_b64"]), b"over the relay")
            finally:
                b.close()
                a.close()

    def test_relay_listen_leaves_a_served_v1_relay_to_the_endpoint(self) -> None:
        # The control relay is addressed as `localhost`, so its host differs from the served
        # `127.0.0.1` relay. It is not served, so the root's pool registers the identity there,
        # and a dial that the control stops answering `offline` proves the mailbox plan ran.
        with AuthRelay() as served_relay, AuthRelay("localhost") as control, \
                tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                with_relay_auth(a, b)
                pair(a, b)
                a_info = json.loads(a.info_json())
                served = a.serve_relay(served_relay.v1_url)
                gid = json.loads(
                    a.group_create("py-served", 1, [control.v1_url, served_relay.v1_url])
                )["group_id"]
                control_ep = f"{control.v1_url}#{a_info['relay_pub']}"
                with a.group_open(gid, None, relay_listen=True):
                    deadline = time.monotonic() + 15
                    while True:
                        try:
                            b.connect(control_ep, a_info["host_id"], None, None)
                            break
                        except RuntimeError as e:
                            self.assertIn("offline", str(e))
                            self.assertLess(time.monotonic(), deadline, "pool never registered")
                            time.sleep(0.1)

                    accepted: dict = {}

                    def accept() -> None:
                        try:
                            accepted["sess"] = a.accept_session(10000)
                        except RuntimeError as e:
                            accepted["err"] = e

                    t = threading.Thread(target=accept)
                    t.start()
                    try:
                        b.connect(served, a_info["host_id"], None, None)
                    finally:
                        t.join(timeout=20)
                    self.assertIn("sess", accepted, f"served mailbox displaced: {accepted}")
            finally:
                b.close()
                a.close()

    def test_admin_sync_over_ordinary_v2_relay(self) -> None:
        with AuthRelay() as relay, tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as db:
            a = tendril.Endpoint(da)
            b = tendril.Endpoint(db)
            try:
                with_relay_auth(a, b)
                a_info = json.loads(a.info_json())
                a_addr = a.serve_direct("127.0.0.1:0")
                code = a.issue_code("lan")
                accepted: dict = {}
                t = threading.Thread(
                    target=lambda: accepted.__setitem__("res", json.loads(a.pair_v2_accept(8000)))
                )
                t.start()
                init = json.loads(b.pair_v2_initiate(a_addr, code, name="py-member", kind="python"))
                t.join(timeout=10)
                b_id = accepted["res"]["device_id"]
                a.confirm_peer(b_id, init["sas"])
                b.confirm_peer(a_info["host_id"], init["sas"])

                gid = json.loads(a.group_create("py-relay-admin", 2, []))["group_id"]
                a.group_add_member(gid, b_id, None, [relay.v2_url])
                b.serve_relay_v2(relay.v2_url, None, a_info["host_id"])
                seen: list = []

                def member() -> None:
                    sess = b.accept_v2(15000)
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        ev = json.loads(sess.poll_event(100))
                        if ev["status"] == "eof" or (
                            ev["status"] == "event" and ev["event"] == "closed"
                        ):
                            break
                        if ev["status"] == "event" and ev["event"].startswith("group_"):
                            seen.append(ev["event"])

                t = threading.Thread(target=member)
                t.start()
                with a.group_open(gid) as ga:
                    report = json.loads(ga.sync())
                    t.join(timeout=30)
                    self.assertEqual(report["delivered"], [b_id], report)
                self.assertEqual(
                    seen, ["group_manifest_ingested", "group_rendezvous_ingested"], seen
                )
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
