import base64
import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import tendril

ADVERTISED_ROUTE = "direct:192.168.77.5:9"

ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS = ROOT / "spec" / "vectors"
PEER_BIN = ROOT / "target" / "debug" / "tendril-conformance-peer"
RELAY_BIN = ROOT / "target" / "debug" / "tendril-relay"


def load_vec(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def hex_to_b64url(hex_str: str) -> str:
    return base64.urlsafe_b64encode(bytes.fromhex(hex_str)).rstrip(b"=").decode("ascii")


class PeerProc:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [str(PEER_BIN)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def send(self, obj: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def recv(self) -> dict:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("conformance peer EOF")
        return json.loads(line)

    def call(self, obj: dict) -> dict:
        self.send(obj)
        resp = self.recv()
        if not resp.get("ok"):
            raise AssertionError(f"peer call failed: {resp}")
        return resp

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()


class TendrilPythonTests(unittest.TestCase):
    def test_conformance_vectors(self) -> None:
        fp = load_vec("fingerprints.json")
        pub = bytes.fromhex(fp["raw_pubkey_hex"])
        hh = bytes.fromhex(fp["handshake_hash_hex"])
        self.assertEqual(tendril.device_id(pub), fp["raw_device_id"])
        self.assertEqual(tendril.fingerprint_host(pub), fp["raw_host_fingerprint"])
        self.assertEqual(tendril.fingerprint_device(pub), fp["raw_device_fingerprint"])
        self.assertEqual(tendril.pairing_sas(hh), fp["pairing_sas"])

        pm = load_vec("pairing_mac.json")
        pm_hh = bytes.fromhex(pm["handshake_hash_hex"])
        r3 = pm["remote_3group"]
        self.assertEqual(
            tendril.compute_code_mac(r3["code"], pm_hh),
            bytes.fromhex(r3["code_mac_hex"]),
        )

        rot = load_vec("rotation.json")
        records = [entry["record"] for entry in rot["chain"]]
        psig = hex_to_b64url(rot["pinned_signing_pub_hex"])
        pstat = hex_to_b64url(rot["pinned_static_pub_hex"])
        cstat = records[-1]["new_static_pub"]
        csig = records[-1]["new_signing_pub"]
        seq = tendril.verify_rotation_chain_json(
            psig, pstat, 0, json.dumps(records), cstat, csig
        )
        self.assertEqual(seq, 2)
        with self.assertRaises(RuntimeError):
            tendril.verify_rotation_chain_json(
                psig,
                pstat,
                0,
                json.dumps(records + [rot["fork_record"]["record"]]),
                cstat,
                csig,
            )

        gv = load_vec("grants.json")
        keys = json.dumps(
            {
                gv["root_issuer_id"]: hex_to_b64url(gv["root_signing_pub_hex"]),
                gv["delegate_id"]: hex_to_b64url(gv["delegate_signing_pub_hex"]),
            }
        )
        now = 1795564800
        self.assertTrue(
            tendril.verify_grant_json(
                json.dumps(gv["delegated_valid"]),
                keys,
                gv["leaf_id"],
                gv["root_issuer_id"],
                "fs.read:/photos/2026/a.jpg",
                now,
            )
        )
        self.assertFalse(
            tendril.verify_grant_json(
                json.dumps(gv["delegated_widened"]),
                keys,
                gv["leaf_id"],
                gv["root_issuer_id"],
                "fs.read:/photos/2026/a.jpg",
                now,
            )
        )
        self.assertTrue(
            tendril.verify_grant_json(
                json.dumps(gv["delegated_valid"]),
                keys,
                gv["leaf_id"],
                gv["root_issuer_id"],
                "fs.read:/photos/2026/a.jpg",
                now,
                json.dumps(gv["revocation_list"]),
            )
        )
        forged_crl = dict(gv["revocation_list"])
        forged_crl["revoked_devices"] = []
        self.assertFalse(
            tendril.verify_grant_json(
                json.dumps(gv["delegated_valid"]),
                keys,
                gv["leaf_id"],
                gv["root_issuer_id"],
                "fs.read:/photos/2026/a.jpg",
                now,
                json.dumps(forged_crl),
            )
        )

    def test_multithreaded_gil_release_and_interop_with_peer(self) -> None:
        # 1a. Concurrent heartbeat ticks freely while another Python thread runs Argon2 compute_code_mac.
        stop_argon = threading.Event()
        ticks = 0

        def heartbeat() -> None:
            nonlocal ticks
            while not stop_argon.is_set():
                ticks += 1
                time.sleep(0.005)

        def argon_worker() -> None:
            try:
                for i in range(4):
                    mac = tendril.compute_code_mac("4829-1704", bytes([i]) * 32)
                    self.assertEqual(len(mac), 32)
            finally:
                stop_argon.set()

        hb_thr = threading.Thread(target=heartbeat)
        ag_thr = threading.Thread(target=argon_worker)
        hb_thr.start()
        ag_thr.start()
        ag_thr.join(timeout=10)
        hb_thr.join(timeout=5)
        self.assertGreaterEqual(ticks, 5)

        # 1b. Two Python threads running pair_accept / pair_initiate simultaneously prove GIL release.
        host_ep = tendril.Endpoint(None, "py-host")
        cli_ep = tendril.Endpoint(None, "py-cli")
        with self.assertRaises(ValueError):
            host_ep.issue_code("invalid")
        addr = host_ep.serve_direct("127.0.0.1:0")
        code = host_ep.issue_code("lan")
        accepted_holder: dict = {}

        def accept_pair() -> None:
            accepted_holder["res"] = json.loads(host_ep.pair_accept(5000))

        t = threading.Thread(target=accept_pair)
        t.start()
        cli_pair = json.loads(cli_ep.pair_initiate(addr, code))
        t.join(timeout=5)
        self.assertEqual(accepted_holder["res"]["sas"], cli_pair["sas"])
        host_ep.confirm_peer(accepted_holder["res"]["device_id"], cli_pair["sas"])
        cli_ep.confirm_peer("py-host", cli_pair["sas"])
        grant = host_ep.mint_grant(accepted_holder["res"]["device_id"], ["fs.read"], 3600)

        sess_holder: dict = {}

        def accept_sess() -> None:
            sess_holder["sess"] = host_ep.accept_session(5000)

        t2 = threading.Thread(target=accept_sess)
        t2.start()
        cli_sess = cli_ep.connect(addr, "py-host", grant)
        t2.join(timeout=5)
        host_sess = sess_holder["sess"]
        self.assertEqual(cli_sess.peer_id, "py-host")
        self.assertEqual(host_sess.peer_id, accepted_holder["res"]["device_id"])
        self.assertTrue(host_sess.authorize("fs.read"))
        self.assertFalse(host_sess.authorize("shell.exec"))
        cli_sess.send_data(b"hello-gil-free")
        ev = json.loads(host_sess.poll_event(2000))
        self.assertEqual(ev["event"], "data")
        host_ep.revoke_peer(accepted_holder["res"]["device_id"])
        self.assertFalse(host_sess.authorize("fs.read"))
        self.assertEqual(host_sess.peer_id, accepted_holder["res"]["device_id"])
        cli_sess.close()
        host_ep.close()
        cli_ep.close()

        # 2. Live cross-language interop against Rust tendril-conformance-peer subprocess.
        peer = PeerProc()
        try:
            py_cli = tendril.Endpoint(None, "py-interop-cli")
            peer.call({"op": "init", "host_id": "rust-host"})
            srv = peer.call({"op": "serve_direct"})
            ep = srv["endpoint"]
            c = peer.call({"op": "issue_code", "kind": "lan"})["code"]

            peer.send({"op": "pair"})
            p_res = json.loads(py_cli.pair_initiate(ep, c, name="py-dev", kind="python"))
            peer_pair = peer.recv()
            self.assertTrue(peer_pair["ok"])
            self.assertEqual(peer_pair["sas"], p_res["sas"])
            dev_id = peer_pair["device_id"]

            peer.call({"op": "confirm", "peer_id": dev_id, "sas": p_res["sas"]})
            grant_obj = peer.call({"op": "mint", "peer_id": dev_id, "caps": ["fs.read"]})["grant"]

            # Pre-confirm connect on Python client must fail closed before SAS confirm.
            peer.send({"op": "connect"})
            with self.assertRaises(RuntimeError):
                py_cli.connect(ep, "rust-host", json.dumps(grant_obj))
            self.assertFalse(peer.recv()["ok"])
            py_cli.confirm_peer("rust-host", p_res["sas"])

            peer.send({"op": "connect"})
            s = py_cli.connect(ep, "rust-host", json.dumps(grant_obj))
            self.assertTrue(peer.recv()["ok"])
            self.assertEqual(s.peer_id, "rust-host")
            self.assertTrue(peer.call({"op": "authorize", "cap": "fs.read"})["allowed"])
            self.assertFalse(peer.call({"op": "authorize", "cap": "shell.exec"})["allowed"])

            s.send_data(b"from-python")
            ev2 = peer.call({"op": "recv", "timeout_ms": 2000})
            self.assertEqual(ev2["data_utf8"], "from-python")

            s.rekey()
            ev_rk = json.loads(s.poll_event(2000))
            self.assertEqual(ev_rk["event"], "rekeyed")
            peer.call({"op": "send", "data_utf8": "back-to-python"})
            ev_py = json.loads(s.poll_event(2000))
            self.assertEqual(ev_py["event"], "data")
            b64 = ev_py["data_b64"]
            decoded = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            self.assertEqual(decoded, b"back-to-python")

            s.close()
            py_cli.close()
            peer.call({"op": "shutdown"})
        finally:
            peer.close()

        # 3. Direction 2 live interop: Rust peer client -> Python host.
        peer2 = PeerProc()
        py_host = tendril.Endpoint(None, "py-interop-host")
        try:
            host_info = json.loads(py_host.info_json())
            self.assertEqual(host_info["host_id"], "py-interop-host")
            self.assertTrue(host_info["device_id"].startswith("dev_"))

            host_addr = py_host.serve_direct("127.0.0.1:0")
            host_code = py_host.issue_code("lan")
            peer2.call({"op": "init", "host_id": "rust-cli"})

            peer2.send(
                {
                    "op": "pair",
                    "endpoint": host_addr,
                    "code": host_code,
                    "name": "rust-cli",
                }
            )
            acc = json.loads(py_host.pair_accept(5000))
            p2_pair = peer2.recv()
            self.assertEqual(p2_pair["sas"], acc["sas"])

            py_host.confirm_peer(acc["device_id"], acc["sas"])
            peer2.call({"op": "confirm", "peer_id": "py-interop-host", "sas": acc["sas"]})
            grant_str = py_host.mint_grant(acc["device_id"], ["fs.read"], 3600)

            peer2.send(
                {
                    "op": "connect",
                    "endpoint": host_addr,
                    "target_host_id": "py-interop-host",
                    "grant": json.loads(grant_str),
                }
            )
            py_host_sess = py_host.accept_session(5000)
            self.assertTrue(peer2.recv()["ok"])
            self.assertEqual(py_host_sess.peer_id, acc["device_id"])
            self.assertTrue(py_host_sess.authorize("fs.read"))
            self.assertFalse(py_host_sess.authorize("shell.exec"))

            peer2.call({"op": "send", "data_utf8": "hello-to-py-host"})
            ev_h = json.loads(py_host_sess.poll_event(2000))
            self.assertEqual(ev_h["event"], "data")
            b64_h = ev_h["data_b64"]
            self.assertEqual(
                base64.urlsafe_b64decode(b64_h + "=" * (-len(b64_h) % 4)),
                b"hello-to-py-host",
            )

            py_host_sess.rekey()
            ev_rk_local = json.loads(py_host_sess.poll_event(2000))
            self.assertEqual(ev_rk_local["event"], "rekeyed")
            ev_rk_peer = peer2.call({"op": "recv", "timeout_ms": 2000})
            self.assertEqual(ev_rk_peer["event"], "rekeyed")

            py_host_sess.send_data(b"reply-from-py-host")
            ev_p2 = peer2.call({"op": "recv", "timeout_ms": 2000})
            self.assertEqual(ev_p2["data_utf8"], "reply-from-py-host")

            py_host.revoke_peer(acc["device_id"])
            self.assertFalse(py_host_sess.authorize("fs.read"))
            self.assertEqual(py_host_sess.peer_id, acc["device_id"])

            py_host_sess.close()
            peer2.call({"op": "shutdown"})
        finally:
            py_host.close()
            peer2.close()

    def test_p2p_net_options_reach_the_listener(self) -> None:
        ep = tendril.Endpoint(None, "py-p2p-net")
        try:
            ep.configure_transports_json(
                json.dumps(
                    {
                        "p2p_port_mapping": False,
                        "p2p_bind_addrs": ["127.0.0.1:0"],
                    }
                )
            )
            addr = ep.serve_p2p("disabled")
            hints = re.findall(r"[?&]addr=([^&]+)", addr)
            self.assertTrue(hints, addr)
            for hint in hints:
                self.assertTrue(hint.startswith("127.0.0.1:"), addr)
        finally:
            ep.close()

    def test_p2p_net_keys_are_validated_and_name_the_key(self) -> None:
        ep = tendril.Endpoint(None, "py-p2p-net-bad")
        try:
            for bad in (["not-an-addr"], ["127.0.0.1:0", "127.0.0.2:0"]):
                with self.assertRaises(ValueError) as ctx:
                    ep.configure_transports_json(json.dumps({"p2p_bind_addrs": bad}))
                self.assertIn("p2p_bind_addrs", str(ctx.exception))
            with self.assertRaises(ValueError):
                ep.configure_transports_json('{"p2p_port_mapping": "no"}')
            ep.configure_transports_json('{"p2p_relay_mode": "n0", "p2p_port_mapping": true}')
        finally:
            ep.close()

    def test_serve_p2p_disabled_loopback(self) -> None:
        host_ep = tendril.Endpoint(None, "py-p2p-host")
        cli_ep = tendril.Endpoint(None, "py-p2p-cli")
        try:
            p2p_addr = host_ep.serve_p2p("disabled")
            self.assertTrue(p2p_addr.startswith("iroh://"))

            lan_code = host_ep.issue_code("lan")
            rejected: dict = {}

            def reject_lan_pair() -> None:
                try:
                    host_ep.pair_accept(5000)
                except RuntimeError as exc:
                    rejected["err"] = str(exc)

            t_rej = threading.Thread(target=reject_lan_pair)
            t_rej.start()
            with self.assertRaises(RuntimeError):
                cli_ep.pair_initiate(p2p_addr, lan_code, relay_host="disabled")
            t_rej.join(timeout=10)
            self.assertIn("err", rejected)

            code = host_ep.issue_code("remote")
            accepted: dict = {}

            def accept_pair() -> None:
                accepted["res"] = json.loads(host_ep.pair_accept(8000))

            t = threading.Thread(target=accept_pair)
            t.start()
            cli_pair = json.loads(cli_ep.pair_initiate(p2p_addr, code, relay_host="disabled"))
            t.join(timeout=10)
            self.assertEqual(accepted["res"]["sas"], cli_pair["sas"])
            host_ep.confirm_peer(accepted["res"]["device_id"], cli_pair["sas"])
            cli_ep.confirm_peer("py-p2p-host", cli_pair["sas"])
            grant = host_ep.mint_grant(accepted["res"]["device_id"], ["fs.read"], 3600)

            sess_holder: dict = {}

            def accept_sess() -> None:
                sess_holder["sess"] = host_ep.accept_session(8000)

            t2 = threading.Thread(target=accept_sess)
            t2.start()
            cli_sess = cli_ep.connect(p2p_addr, "py-p2p-host", grant, relay_host="disabled")
            t2.join(timeout=10)
            host_sess = sess_holder["sess"]
            cli_sess.send_data(b"py-p2p-ok")
            ev = json.loads(host_sess.poll_event(2000))
            self.assertEqual(ev["event"], "data")
            cli_sess.close()
            ev_close = json.loads(host_sess.poll_event(2000))
            self.assertIn(ev_close.get("event") or ev_close.get("status"), ("closed", "eof"))
        finally:
            host_ep.close()
            cli_ep.close()

    def test_pair_flood_does_not_starve_accept_session(self) -> None:
        host_ep = tendril.Endpoint(None, "py-sec03-host")
        cli_ep = tendril.Endpoint(None, "py-sec03-cli")
        flood_socks: list[socket.socket] = []
        try:
            addr = host_ep.serve_direct("127.0.0.1:0")
            code = host_ep.issue_code("lan")
            t_pair = threading.Thread(target=lambda: host_ep.pair_accept(5000))
            t_pair.start()
            cli_pair = json.loads(cli_ep.pair_initiate(addr, code))
            t_pair.join(timeout=5)
            host_ep.confirm_peer(cli_pair["device_id"], cli_pair["sas"])
            cli_ep.confirm_peer("py-sec03-host", cli_pair["sas"])
            grant = host_ep.mint_grant(cli_pair["device_id"], ["fs.read"], 3600)

            host_port = int(addr.rsplit(":", 1)[1])
            for i in range(32):
                if i == 24:
                    time.sleep(1.5)
                s = socket.create_connection(("127.0.0.1", host_port), timeout=2)
                s.sendall(b"TND\x01\x02\x00")
                flood_socks.append(s)
            time.sleep(0.3)

            sess_holder: dict = {}

            def accept_sess() -> None:
                sess_holder["sess"] = host_ep.accept_session(4000)

            t_acc = threading.Thread(target=accept_sess)
            t_acc.start()
            cli_sess = cli_ep.connect(addr, "py-sec03-host", grant)
            t_acc.join(timeout=5)
            self.assertIn("sess", sess_holder)
            cli_sess.close()
            sess_holder["sess"].close()
        finally:
            for s in flood_socks:
                s.close()
            host_ep.close()
            cli_ep.close()

    def test_full_duplex_poll_does_not_block_send_authorize_and_expiry(self) -> None:
        host_ep = tendril.Endpoint(None, "py-sec17-host")
        cli_ep = tendril.Endpoint(None, "py-sec17-cli")
        try:
            addr = host_ep.serve_direct("127.0.0.1:0")
            code = host_ep.issue_code("lan")
            t_pair = threading.Thread(target=lambda: host_ep.pair_accept(5000))
            t_pair.start()
            cli_pair = json.loads(cli_ep.pair_initiate(addr, code))
            t_pair.join(timeout=5)
            host_ep.confirm_peer(cli_pair["device_id"], cli_pair["sas"])
            cli_ep.confirm_peer("py-sec17-host", cli_pair["sas"])
            grant = host_ep.mint_grant(cli_pair["device_id"], ["fs.read"], 3600)

            sess_holder: dict = {}
            t_acc = threading.Thread(
                target=lambda: sess_holder.__setitem__("sess", host_ep.accept_session(5000))
            )
            t_acc.start()
            cli_sess = cli_ep.connect(addr, "py-sec17-host", grant)
            t_acc.join(timeout=5)
            host_sess = sess_holder["sess"]

            poll_holder: dict = {}
            t_poll = threading.Thread(
                target=lambda: poll_holder.__setitem__("ev", host_sess.poll_event(5000))
            )
            t_poll.start()
            time.sleep(0.06)

            t0 = time.monotonic()
            self.assertTrue(host_sess.authorize("fs.read"))
            self.assertEqual(host_sess.peer_id, cli_pair["device_id"])
            self.assertEqual(cli_sess.peer_id, "py-sec17-host")
            host_sess.send_data(b"py-duplex-reply")
            cli_ev = json.loads(cli_sess.poll_event(2000))
            self.assertEqual(cli_ev["event"], "data")
            cli_sess.send_data(b"py-wake-host")
            t_poll.join(timeout=2)
            self.assertLess(time.monotonic() - t0, 1.5)
            self.assertEqual(json.loads(poll_holder["ev"])["event"], "data")

            # SEC-31: grant expiring while poll_event(6000) is parked must reject incoming rekey.
            short_grant = host_ep.mint_grant(cli_pair["device_id"], ["fs.read"], 3)
            sess2_holder: dict = {}
            t_acc2 = threading.Thread(
                target=lambda: sess2_holder.__setitem__("sess", host_ep.accept_session(5000))
            )
            t_acc2.start()
            cli_sess2 = cli_ep.connect(addr, "py-sec17-host", short_grant)
            t_acc2.join(timeout=5)
            host_sess2 = sess2_holder["sess"]
            poll2_err: dict = {}

            def poll_exp() -> None:
                try:
                    poll2_err["ev"] = host_sess2.poll_event(6000)
                except RuntimeError as exc:
                    poll2_err["err"] = str(exc)

            t_exp = threading.Thread(target=poll_exp)
            t_exp.start()
            time.sleep(3.5)
            cli_sess2.rekey()
            t_exp.join(timeout=3)
            self.assertIn("err", poll2_err)

            cli_sess2.close()
            cli_sess.close()
        finally:
            host_ep.close()
            cli_ep.close()

    def _enroll_into(self, host_ep, cli_ep, cfg=None):
        def b64u_dec(s: str) -> bytes:
            return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

        if cfg is not None:
            cli_ep.configure_transports_json(json.dumps(cfg))
        host_ep.configure_transports_json(
            json.dumps({"advertise": "explicit", "advertised_endpoints": [ADVERTISED_ROUTE]})
        )
        host_info = json.loads(host_ep.info_json())
        cli_info = json.loads(cli_ep.info_json())
        addr = host_ep.serve_direct("127.0.0.1:0")
        # The announcer starts on first use: publish the host's route set before enrolling.
        host_ep.refresh_routes(None)
        token = host_ep.mint_enrollment_token(host_info["host_id"], cli_info["device_id"], 900)
        t = threading.Thread(target=lambda: host_ep.pair_accept(5000))
        t.start()
        try:
            res = json.loads(
                cli_ep.enroll_initiate(
                    addr,
                    host_info["host_id"],
                    b64u_dec(host_info["static_pub"]),
                    b64u_dec(host_info["signing_pub"]),
                    token,
                )
            )
        finally:
            t.join(timeout=10)
        routes = json.loads(cli_ep.peer_routes(host_info["host_id"]))
        return res, routes

    def test_enroll_initiate_stores_routes_per_route_policy(self) -> None:
        def sources(routes):
            return [(r["source"], r["hint"]) for r in routes["routes"]]

        def run(cfg):
            with tempfile.TemporaryDirectory() as hd, tempfile.TemporaryDirectory() as cd:
                host_ep = tendril.Endpoint(hd, "py-enr-host")
                cli_ep = tendril.Endpoint(cd)
                try:
                    return self._enroll_into(host_ep, cli_ep, cfg)
                finally:
                    host_ep.close()
                    cli_ep.close()

        res, routes = run(None)
        self.assertEqual(res["status"], "active")
        self.assertTrue(res["routes_persisted"], res)
        stored = sources(routes)
        self.assertIn(("signed", ADVERTISED_ROUTE), stored, routes)
        self.assertIn("committed", [s for s, _ in stored], routes)

        res, routes = run({"route_policy": "committed_only"})
        self.assertEqual(res["status"], "active")
        stored = sources(routes)
        self.assertTrue(stored and all(s == "committed" for s, _ in stored), routes)

        res, routes = run({"route_policy": "none"})
        self.assertEqual(res["status"], "active")
        self.assertEqual(res["routes_persisted"], [])
        self.assertEqual(routes["routes"], [])

    def test_enroll_initiate_without_a_state_dir_stores_no_route(self) -> None:
        with tempfile.TemporaryDirectory() as hd:
            host_ep = tendril.Endpoint(hd, "py-enr-host")
            cli_ep = tendril.Endpoint(None)
            try:
                res, routes = self._enroll_into(host_ep, cli_ep)
                self.assertEqual(res["status"], "active")
                self.assertEqual(res["routes_persisted"], [])
                self.assertEqual(res["routes_reason"], "no_state_dir")
                self.assertEqual(routes["routes"], [])
            finally:
                host_ep.close()
                cli_ep.close()

    def test_m2m_enrollment_and_replay(self) -> None:
        host_ep = tendril.Endpoint(None, "py-m2m-host")
        anchor_ep = tendril.Endpoint(None, "py-m2m-anchor")
        cli_ep = tendril.Endpoint(None, "py-m2m-cli")
        cli2_ep = tendril.Endpoint(None, "py-m2m-cli2")
        try:
            host_info = json.loads(host_ep.info_json())
            anchor_info = json.loads(anchor_ep.info_json())

            def b64u_dec(s: str) -> bytes:
                return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

            host_static = b64u_dec(host_info["static_pub"])
            host_signing = b64u_dec(host_info["signing_pub"])
            host_signing_hash = b64u_dec(host_info["signing_pub_hash"])
            anchor_signing = b64u_dec(anchor_info["signing_pub"])
            self.assertEqual(len(host_signing), 1984)
            self.assertEqual(len(host_signing_hash), 32)
            self.assertEqual(len(anchor_signing), 1984)

            host_ep.add_trust_anchor("py-m2m-anchor", anchor_signing)
            addr = host_ep.serve_direct("127.0.0.1:0")
            tok_json = anchor_ep.mint_enrollment_token("py-m2m-host", None, 900)

            acc_holder: dict = {}

            def accept_pair() -> None:
                acc_holder["res"] = json.loads(host_ep.pair_accept(5000))

            t = threading.Thread(target=accept_pair)
            t.start()
            init_res = json.loads(
                cli_ep.enroll_initiate(
                    addr,
                    "py-m2m-host",
                    host_static,
                    host_signing,
                    tok_json,
                    name="py-worker",
                    kind="machine",
                )
            )
            t.join(timeout=5)
            acc = acc_holder["res"]
            self.assertEqual(init_res["status"], "active")
            self.assertEqual(acc["status"], "active")
            self.assertEqual(init_res["device_id"], acc["device_id"])

            def accept_ignore_err() -> None:
                try:
                    host_ep.pair_accept(5000)
                except RuntimeError:
                    pass

            t_rep = threading.Thread(target=accept_ignore_err)
            t_rep.start()
            with self.assertRaisesRegex(RuntimeError, "token_replayed"):
                cli_ep.enroll_initiate(
                    addr,
                    "py-m2m-host",
                    host_static,
                    host_signing,
                    tok_json,
                )
            t_rep.join(timeout=5)

            grant_json = host_ep.mint_grant(init_res["device_id"], ["fs.read"], 3600)
            sess_holder: dict = {}
            t_sess = threading.Thread(
                target=lambda: sess_holder.__setitem__("sess", host_ep.accept_session(5000))
            )
            t_sess.start()
            cli_sess = cli_ep.connect(addr, "py-m2m-host", grant_json)
            t_sess.join(timeout=5)
            host_sess = sess_holder["sess"]
            self.assertTrue(host_sess.authorize("fs.read"))
            self.assertFalse(host_sess.authorize("shell.exec"))
            self.assertEqual(cli_sess.peer_id, "py-m2m-host")
            self.assertEqual(host_sess.peer_id, init_res["device_id"])
            cli_sess.close()

            # Revoking the sole trust anchor disables M2M policy -> unauthorized.
            host_ep.revoke_trust_anchor("py-m2m-anchor")
            fresh_tok = anchor_ep.mint_enrollment_token("py-m2m-host", None, 900)
            t_rev = threading.Thread(target=accept_ignore_err)
            t_rev.start()
            with self.assertRaisesRegex(RuntimeError, "unauthorized"):
                cli2_ep.enroll_initiate(
                    addr,
                    "py-m2m-host",
                    host_static,
                    host_signing,
                    fresh_tok,
                )
            t_rev.join(timeout=5)

            # Re-enabling M2M via self-issued minting still blocks revoked anchor with untrusted_anchor
            # while allowing the self-issued token to enroll.
            self_tok = host_ep.mint_enrollment_token("py-m2m-host", None, 900)
            t_rev2 = threading.Thread(target=accept_ignore_err)
            t_rev2.start()
            with self.assertRaisesRegex(RuntimeError, "untrusted_anchor"):
                cli2_ep.enroll_initiate(
                    addr,
                    "py-m2m-host",
                    host_static,
                    host_signing,
                    fresh_tok,
                )
            t_rev2.join(timeout=5)

            t_self = threading.Thread(target=lambda: acc_holder.__setitem__("self", json.loads(host_ep.pair_accept(5000))))
            t_self.start()
            self_res = json.loads(
                cli2_ep.enroll_initiate(
                    addr,
                    "py-m2m-host",
                    host_static,
                    host_signing_hash,
                    self_tok,
                    name="py-worker-2",
                    kind="machine",
                )
            )
            t_self.join(timeout=5)
            self.assertEqual(self_res["status"], "active")
            self.assertEqual(acc_holder["self"]["status"], "active")
        finally:
            cli2_ep.close()
            cli_ep.close()
            anchor_ep.close()
            host_ep.close()

    def test_configure_transports_json_validation_and_redaction(self) -> None:
        ep = tendril.Endpoint(None, "py-cfg-test")
        try:
            # Unknown field rejected (deny_unknown_fields).
            with self.assertRaises(ValueError):
                ep.configure_transports_json('{"unknown_field": true}')

            # Scalar secret redaction: error message must not leak the scalar value.
            with self.assertRaises(ValueError) as ctx:
                ep.configure_transports_json('{"relay_auth_secret":123456}')
            self.assertNotIn("123456", str(ctx.exception))

            # Redacted pinned_host_json parse error in pair_v2_initiate.
            with self.assertRaises(ValueError) as ctx_pin:
                ep.pair_v2_initiate("127.0.0.1:1", "1234-5678", pinned_host_json='{"static_pub_b64":998877}')
            self.assertNotIn("998877", str(ctx_pin.exception))

            # Mutual-exclusion checks.
            ticket_json = ep.mint_relay_ticket("localhost", "any", "*", 300)
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                ep.configure_transports_json(
                    json.dumps(
                        {
                            "relay_auth_secret": "a" * 32,
                            "relay_ticket": json.loads(ticket_json),
                        }
                    )
                )
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                ep.configure_transports_json(
                    json.dumps(
                        {
                            "p2p_relay_auth_token": "tok-123",
                            "p2p_api_secret": "sec-456",
                        }
                    )
                )
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                ep.configure_transports_json(
                    json.dumps(
                        {
                            "p2p_relay_mode": "disabled",
                            "p2p_relay_urls": ["https://relay.example"],
                        }
                    )
                )

            # p2p_api_secret either requires p2p-iroh-services feature or succeeds when built with it.
            if os.environ.get("TENDRIL_PY_IROH_SERVICES") == "1":
                ep.configure_transports_json(json.dumps({"p2p_api_secret": "iroh-sec-1234"}))
            else:
                with self.assertRaisesRegex(RuntimeError, "p2p-iroh-services"):
                    ep.configure_transports_json(json.dumps({"p2p_api_secret": "iroh-sec-1234"}))
        finally:
            ep.close()

    def test_mint_relay_ticket_and_gated_relay_v1_and_v2(self) -> None:
        if not RELAY_BIN.exists():
            subprocess.run(
                ["cargo", "build", "-p", "tendril-relay", "--bin", "tendril-relay"],
                cwd=str(ROOT),
                check=True,
            )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        secret_val = "tendril-test-relay-hmac-secret-32b"
        issuer_ep = tendril.Endpoint(None, "py-ticket-issuer")
        issuer_info = json.loads(issuer_ep.info_json())

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = pathlib.Path(tmpdir) / "relay.secret"
            secret_file.write_text(secret_val, encoding="utf-8")
            secret_file.chmod(0o600)

            relay_proc = subprocess.Popen(
                [
                    str(RELAY_BIN),
                    "--listen",
                    f"127.0.0.1:{port}",
                    "--host",
                    "localhost",
                    "--auth-secret-file",
                    str(secret_file),
                    "--issuer-pub",
                    issuer_info["relay_pub"],
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("tendril-relay did not listen in time")

                relay_v1_url = f"ws://127.0.0.1:{port}/v1/relay"
                relay_v2_url = f"ws://127.0.0.1:{port}/v2/relay"

                host_ep = tendril.Endpoint(str(pathlib.Path(tmpdir) / "host"), "py-gated-host")
                cli_ep = tendril.Endpoint(str(pathlib.Path(tmpdir) / "cli"), "py-gated-cli")
                unauth_ep = tendril.Endpoint(None, "py-gated-unauth")
                try:
                    # 1. /v1/relay: unauthenticated, wrong secret, and wrong-role ticket fail closed.
                    with self.assertRaises(RuntimeError):
                        unauth_ep.serve_relay(relay_v1_url, "localhost")

                    wrong_sec_ep = tendril.Endpoint(None, "py-wrong-sec")
                    wrong_sec_ep.configure_transports_json(
                        json.dumps({"relay_auth_secret": "wrong-secret-000000000000000000"})
                    )
                    with self.assertRaises(RuntimeError):
                        wrong_sec_ep.serve_relay(relay_v1_url, "localhost")
                    wrong_sec_ep.close()

                    dial_only_ticket = json.loads(
                        issuer_ep.mint_relay_ticket("localhost", "dial", "*", 300)
                    )
                    host_ep.configure_transports_json(
                        json.dumps({"relay_ticket": dial_only_ticket})
                    )
                    with self.assertRaises(RuntimeError):
                        host_ep.serve_relay(relay_v1_url, "localhost")

                    reg_ticket = json.loads(
                        issuer_ep.mint_relay_ticket("localhost", "register", "*", 300)
                    )
                    host_ep.configure_transports_json(json.dumps({"relay_ticket": reg_ticket}))
                    v1_ep = host_ep.serve_relay(relay_v1_url, "localhost")

                    code = host_ep.issue_code("remote")
                    with self.assertRaises(RuntimeError):
                        unauth_ep.pair_initiate(v1_ep, code, relay_host="localhost")

                    cli_ep.configure_transports_json(
                        json.dumps({"relay_auth_secret": secret_val})
                    )
                    t_acc = threading.Thread(target=lambda: host_ep.pair_accept(5000))
                    t_acc.start()
                    p1 = json.loads(cli_ep.pair_initiate(v1_ep, code, relay_host="localhost"))
                    t_acc.join(timeout=5)
                    host_ep.confirm_peer(p1["device_id"], p1["sas"])
                    cli_ep.confirm_peer("py-gated-host", p1["sas"])
                    g1 = host_ep.mint_grant(p1["device_id"], ["fs.read"], 3600)

                    with self.assertRaises(RuntimeError):
                        unauth_ep.connect(v1_ep, "py-gated-host", g1, relay_host="localhost")

                    s_holder: dict = {}
                    t_s = threading.Thread(
                        target=lambda: s_holder.__setitem__("s", host_ep.accept_session(5000))
                    )
                    t_s.start()
                    c1 = cli_ep.connect(v1_ep, "py-gated-host", g1, relay_host="localhost")
                    t_s.join(timeout=5)
                    c1.send_data(b"v1-gated-ok")
                    ev1 = json.loads(s_holder["s"].poll_event(2000))
                    self.assertEqual(ev1["event"], "data")
                    c1.close()

                    # 2. /v2/relay: pair via direct first so both endpoints hold v2 mailbox_secret.
                    direct_addr = host_ep.serve_direct("127.0.0.1:0")
                    v2_code = host_ep.issue_code("lan")
                    v2_acc: dict = {}
                    t_v2p = threading.Thread(
                        target=lambda: v2_acc.__setitem__("res", json.loads(host_ep.pair_v2_accept(5000)))
                    )
                    t_v2p.start()
                    v2_init = json.loads(cli_ep.pair_v2_initiate(direct_addr, v2_code))
                    t_v2p.join(timeout=5)
                    self.assertEqual(v2_acc["res"]["sas"], v2_init["sas"])
                    host_ep.confirm_peer(v2_acc["res"]["device_id"], v2_init["sas"])
                    cli_ep.confirm_peer("py-gated-host", v2_init["sas"])
                    g2 = host_ep.mint_grant(v2_acc["res"]["device_id"], ["fs.read"], 3600)

                    host_ep.configure_transports_json(json.dumps({"relay_ticket": dial_only_ticket}))
                    with self.assertRaises(RuntimeError):
                        host_ep.serve_relay_v2(relay_v2_url, "localhost", v2_acc["res"]["device_id"])

                    host_ep.configure_transports_json(json.dumps({"relay_auth_secret": secret_val}))
                    v2_ep = host_ep.serve_relay_v2(
                        relay_v2_url, "localhost", v2_acc["res"]["device_id"]
                    )
                    self.assertIn("/v2/relay#", v2_ep)

                    with self.assertRaises(RuntimeError):
                        unauth_ep.connect_v2(v2_ep, "py-gated-host", g2, relay_host="localhost")

                    cli_ep.configure_transports_json(
                        json.dumps({"relay_auth_secret": "wrong-secret-000000000000000000"})
                    )
                    with self.assertRaises(RuntimeError):
                        cli_ep.connect_v2(v2_ep, "py-gated-host", g2, relay_host="localhost")

                    cli_ep.configure_transports_json(json.dumps({"relay_ticket": reg_ticket}))
                    with self.assertRaises(RuntimeError):
                        cli_ep.connect_v2(v2_ep, "py-gated-host", g2, relay_host="localhost")

                    cli_ep.configure_transports_json(json.dumps({"relay_ticket": dial_only_ticket}))
                    v2_sh: dict = {}
                    t_v2s = threading.Thread(
                        target=lambda: v2_sh.__setitem__("s", host_ep.accept_v2(5000))
                    )
                    t_v2s.start()
                    c2 = cli_ep.connect_v2(v2_ep, "py-gated-host", g2, relay_host="localhost")
                    t_v2s.join(timeout=5)
                    self.assertEqual(c2.peer_id, "py-gated-host")
                    self.assertEqual(v2_sh["s"].peer_id, v2_acc["res"]["device_id"])
                    c2.send_data(b"v2-gated-ok")
                    ev2 = json.loads(v2_sh["s"].poll_event(2000))
                    self.assertEqual(ev2["event"], "data")
                    c2.close()
                finally:
                    unauth_ep.close()
                    cli_ep.close()
                    host_ep.close()
            finally:
                issuer_ep.close()
                if relay_proc.poll() is None:
                    relay_proc.kill()
                relay_proc.wait()

    def test_wire_v2_interop_with_conformance_peer(self) -> None:
        if not RELAY_BIN.exists():
            subprocess.run(
                ["cargo", "build", "-p", "tendril-relay", "--bin", "tendril-relay"],
                cwd=str(ROOT),
                check=True,
            )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        relay_proc = subprocess.Popen(
            [str(RELAY_BIN), "--listen", f"127.0.0.1:{port}", "--host", "localhost"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        peer = PeerProc()
        with tempfile.TemporaryDirectory() as tmpdir:
            py_cli = tendril.Endpoint(str(pathlib.Path(tmpdir) / "py_cli"), "py-v2-cli")
            try:
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("tendril-relay did not listen in time")

                relay_v2_url = f"ws://127.0.0.1:{port}/v2/relay"

                peer.call({"op": "init", "host_id": "rust-v2-host"})
                direct_ep = peer.call({"op": "serve_direct"})["endpoint"]

                # Wrong-code rejection on pair_v2_initiate.
                code_bad = peer.call({"op": "issue_code", "kind": "lan"})["code"]
                peer.send({"op": "pair_v2_accept", "timeout_ms": 5000})
                with self.assertRaises(RuntimeError):
                    py_cli.pair_v2_initiate(direct_ep, "0000-0000")
                self.assertFalse(peer.recv()["ok"])

                # Valid Wire v2 pairing.
                code_ok = peer.call({"op": "issue_code", "kind": "lan"})["code"]
                peer.send({"op": "pair_v2_accept", "timeout_ms": 5000})
                p_res = json.loads(
                    py_cli.pair_v2_initiate(direct_ep, code_ok, name="py-v2-dev", kind="python")
                )
                peer_pair = peer.recv()
                self.assertTrue(peer_pair["ok"])
                self.assertEqual(p_res["wire_version"], 2)
                self.assertEqual(peer_pair["sas"], p_res["sas"])
                dev_id = peer_pair["device_id"]

                peer.call({"op": "confirm", "peer_id": dev_id, "sas": p_res["sas"]})
                py_cli.confirm_peer("rust-v2-host", p_res["sas"])
                grant_obj = peer.call({"op": "mint", "peer_id": dev_id, "caps": ["fs.read"]})[
                    "grant"
                ]

                # Serve /v2/relay on Rust peer and connect_v2 from Python.
                v2_ep = peer.call(
                    {
                        "op": "serve_relay_v2",
                        "relay_url": relay_v2_url,
                        "expected_host": "localhost",
                        "peer_id": dev_id,
                    }
                )["endpoint"]

                peer.send({"op": "accept_v2", "timeout_ms": 5000})
                sess = py_cli.connect_v2(
                    v2_ep, "rust-v2-host", json.dumps(grant_obj), relay_host="localhost"
                )
                self.assertTrue(peer.recv()["ok"])
                self.assertEqual(sess.peer_id, "rust-v2-host")
                self.assertTrue(peer.call({"op": "authorize", "cap": "fs.read"})["allowed"])
                self.assertFalse(peer.call({"op": "authorize", "cap": "shell.exec"})["allowed"])

                sess.send_data(b"v2-from-python")
                ev = peer.call({"op": "recv", "timeout_ms": 2000})
                self.assertEqual(ev["data_utf8"], "v2-from-python")

                sess.rekey()
                ev_rk = json.loads(sess.poll_event(2000))
                self.assertEqual(ev_rk["event"], "rekeyed")
                ev_peer_rk = peer.call({"op": "recv", "timeout_ms": 2000})
                self.assertEqual(ev_peer_rk["event"], "rekeyed")

                peer.call({"op": "send", "data_utf8": "v2-back-to-python"})
                ev_py = json.loads(sess.poll_event(2000))
                self.assertEqual(ev_py["event"], "data")
                b64 = ev_py["data_b64"]
                self.assertEqual(
                    base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)),
                    b"v2-back-to-python",
                )

                sess.close()
                ev_peer_close = peer.call({"op": "recv", "timeout_ms": 2000})
                self.assertEqual(ev_peer_close["event"], "closed")

                # Revoking peer fails authorization and subsequent connect_v2.
                peer.call({"op": "revoke", "peer_id": dev_id})
                peer.send({"op": "accept_v2", "timeout_ms": 2000})
                with self.assertRaises(RuntimeError):
                    py_cli.connect_v2(
                        v2_ep, "rust-v2-host", json.dumps(grant_obj), relay_host="localhost"
                    )
                self.assertFalse(peer.recv()["ok"])

                peer.call({"op": "shutdown"})
            finally:
                py_cli.close()
                peer.close()
                if relay_proc.poll() is None:
                    relay_proc.kill()
                relay_proc.wait()

    def test_wake_and_dial_v2_http_delivery(self) -> None:
        wake_requests: list[dict] = []

        class WakeHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(405)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                wake_requests.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "body": json.loads(raw.decode("utf-8")),
                    }
                )
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), WakeHandler)
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()
        wake_port = server.server_address[1]

        host_ep = tendril.Endpoint(None, "py-wake-host")
        cli_ep = tendril.Endpoint(None, "py-wake-cli")
        try:
            direct_addr = host_ep.serve_direct("127.0.0.1:0")
            code = host_ep.issue_code("lan")
            acc_holder: dict = {}
            t_acc = threading.Thread(
                target=lambda: acc_holder.__setitem__("res", json.loads(host_ep.pair_v2_accept(5000)))
            )
            t_acc.start()
            pair_res = json.loads(
                cli_ep.pair_v2_initiate(direct_addr, code, name="py-wake-cli", kind="python")
            )
            t_acc.join(timeout=5)
            self.assertEqual(acc_holder["res"]["sas"], pair_res["sas"])

            host_ep.confirm_peer(acc_holder["res"]["device_id"], pair_res["sas"])
            cli_ep.confirm_peer("py-wake-host", pair_res["sas"])
            grant_json = host_ep.mint_grant(acc_holder["res"]["device_id"], ["fs.read"], 3600)

            wake_secret_b64 = (
                base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
            )
            cli_ep.configure_transports_json(
                json.dumps(
                    {
                        "wake_url": f"http://127.0.0.1:{wake_port}/wake",
                        "wake_adapter": "webhook",
                        "wake_secret_b64": wake_secret_b64,
                        "wake_auth_token": "py-wake-token",
                        "wake_pre_wake": True,
                        "wake_retry_delay_ms": 25,
                        "wake_max_attempts": 10,
                        "wake_timeout_ms": 2000,
                    }
                )
            )

            sess_holder: dict = {}
            t_sess = threading.Thread(
                target=lambda: sess_holder.__setitem__("s", host_ep.accept_v2(5000))
            )
            t_sess.start()
            cli_sess = cli_ep.connect_v2(direct_addr, "py-wake-host", grant_json)
            t_sess.join(timeout=5)

            self.assertGreaterEqual(len(wake_requests), 1)
            self.assertEqual(wake_requests[0]["path"], "/wake")
            self.assertEqual(wake_requests[0]["auth"], "Bearer py-wake-token")
            self.assertIsInstance(wake_requests[0]["body"].get("wake_tag"), str)
            self.assertTrue(len(wake_requests[0]["body"]["wake_tag"]) > 0)

            cli_sess.send_data(b"py-wake-v2-ok")
            ev = json.loads(sess_holder["s"].poll_event(2000))
            self.assertEqual(ev["event"], "data")
            b64 = ev["data_b64"]
            self.assertEqual(
                base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)),
                b"py-wake-v2-ok",
            )
            cli_sess.close()
        finally:
            cli_ep.close()
            host_ep.close()
            server.shutdown()
            server.server_close()
            srv_thread.join(timeout=2)

    def test_verify_wake_tag_and_apns_mutable_alert_coalesce(self) -> None:
        import hashlib
        import hmac

        secret = bytes(range(32))
        wrong = bytes([0xEE] * 32)
        now = 1_764_115_200
        epoch = now // 3600
        prk = hmac.new(epoch.to_bytes(8, "big"), secret, hashlib.sha256).digest()
        tag = hmac.new(prk, b"tendril/wake/epoch-tag/v1\x01", hashlib.sha256).digest()[:16]
        tag_b64 = base64.urlsafe_b64encode(tag).rstrip(b"=").decode("ascii")

        for check_now in (now - 3600, now, now + 3600):
            self.assertTrue(tendril.verify_wake_tag(secret, tag_b64, check_now))
        for check_now in (now - 7200, now + 7200):
            self.assertFalse(tendril.verify_wake_tag(secret, tag_b64, check_now))
        self.assertFalse(tendril.verify_wake_tag(wrong, tag_b64, now))
        with self.assertRaises(ValueError):
            tendril.verify_wake_tag(b"short", tag_b64, now)
        with self.assertRaises(ValueError):
            tendril.verify_wake_tag(secret, "bad-tag", now)

        p8_pem = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout

        apns_requests: list[dict] = []

        class ApnsHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                apns_requests.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "push_type": self.headers.get("apns-push-type"),
                        "priority": self.headers.get("apns-priority"),
                        "topic": self.headers.get("apns-topic"),
                        "body": json.loads(raw.decode("utf-8")),
                    }
                )
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), ApnsHandler)
        apns_port = server.server_address[1]
        srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
        srv_thread.start()

        host_ep = tendril.Endpoint(None, "py-apns-host")
        cli_ep = tendril.Endpoint(None, "py-apns-cli")
        try:
            secret_b64 = base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
            dev_tok = "0" * 64
            cli_ep.configure_transports_json(
                json.dumps(
                    {
                        "wake_url": f"https://api.sandbox.push.apple.com/3/device/{dev_tok}",
                        "wake_adapter": "apns_h2",
                        "wake_secret_b64": secret_b64,
                        "wake_apns_mode": "mutable_alert",
                        "wake_apns_topic": "app.tendril.py",
                        "wake_apns_loc_key": "TENDRIL_WAKE_PY",
                        "wake_apns_team_id": "TEAM123456",
                        "wake_apns_key_id": "KEY1234567",
                        "wake_apns_p8_pem": p8_pem,
                        "wake_coalesce_secs": 15,
                    }
                )
            )
            for bad in (
                {
                    "wake_url": f"http://127.0.0.1:{apns_port}/3/device/{dev_tok}",
                    "wake_adapter": "apns_h2",
                    "wake_secret_b64": secret_b64,
                    "wake_auth_token": "tok",
                    "wake_apns_topic": "app.tendril.py",
                },
                {
                    "wake_url": f"https://api.push.apple.com/3/device/{dev_tok}",
                    "wake_adapter": "apns_h2",
                    "wake_secret_b64": secret_b64,
                    "wake_auth_token": "tok",
                },
                {
                    "wake_url": f"https://api.push.apple.com/3/device/{dev_tok}",
                    "wake_adapter": "apns_h2",
                    "wake_secret_b64": secret_b64,
                    "wake_auth_token": "tok",
                    "wake_apns_topic": "app.tendril.py",
                    "wake_apns_mode": "mutable_alert",
                    "wake_apns_loc_key": "BAD KEY",
                },
            ):
                with self.assertRaises(ValueError):
                    cli_ep.configure_transports_json(json.dumps(bad))

            direct_addr = host_ep.serve_direct("127.0.0.1:0")
            code = host_ep.issue_code("lan")
            acc_holder: dict = {}
            t_acc = threading.Thread(
                target=lambda: acc_holder.__setitem__("raw", host_ep.pair_v2_accept(5000))
            )
            t_acc.start()
            pair_res = json.loads(
                cli_ep.pair_v2_initiate(direct_addr, code, None, "py-apns-cli", "python", None)
            )
            t_acc.join(timeout=5)
            acc_res = json.loads(acc_holder["raw"])
            host_ep.confirm_peer(acc_res["device_id"], pair_res["sas"])
            cli_ep.confirm_peer("py-apns-host", pair_res["sas"])
            grant_json = host_ep.mint_grant(acc_res["device_id"], ["fs.read"], 3600)

            cli_ep.configure_transports_json(
                json.dumps(
                    {
                        "wake_url": f"http://127.0.0.1:{apns_port}/3/device/deadbeef",
                        "wake_adapter": "apns",
                        "wake_secret_b64": secret_b64,
                        "wake_auth_token": "py-apns-tok",
                        "wake_pre_wake": True,
                        "wake_coalesce_secs": 60,
                        "wake_apns_mode": "mutable_alert",
                        "wake_apns_topic": "app.tendril.py",
                        "wake_apns_loc_key": "TENDRIL_WAKE_PY",
                    }
                )
            )

            for _ in range(2):
                sess_holder: dict = {}
                t_sess = threading.Thread(
                    target=lambda: sess_holder.__setitem__("s", host_ep.accept_v2(5000))
                )
                t_sess.start()
                cli_sess = cli_ep.connect_v2(direct_addr, "py-apns-host", grant_json)
                t_sess.join(timeout=5)
                cli_sess.close()
                sess_holder["s"].close()

            self.assertEqual(len(apns_requests), 1)
            req = apns_requests[0]
            self.assertEqual(req["path"], "/3/device/deadbeef")
            self.assertEqual(req["auth"], "Bearer py-apns-tok")
            self.assertEqual(req["push_type"], "alert")
            self.assertEqual(req["priority"], "10")
            self.assertEqual(req["topic"], "app.tendril.py")
            self.assertEqual(req["body"]["aps"]["mutable-content"], 1)
            self.assertEqual(req["body"]["aps"]["alert"]["loc-key"], "TENDRIL_WAKE_PY")
            self.assertTrue(
                tendril.verify_wake_tag(secret, req["body"]["wake_tag"], int(time.time()))
            )
        finally:
            cli_ep.close()
            host_ep.close()
            server.shutdown()
            server.server_close()
            srv_thread.join(timeout=2)

    def test_serve_p2p_v2_zero_peers_and_ephemeral(self) -> None:
        ep = tendril.Endpoint(None, "py-p2p-v2")
        host_ep = tendril.Endpoint(None, "py-v2-pending-host")
        cli_ep = tendril.Endpoint(None, "py-v2-pending-cli")
        try:
            self.assertEqual(ep.serve_p2p_v2("disabled"), "iroh://v2")
            self.assertEqual(ep.serve_p2p_v2("disabled"), "iroh://v2")
            ep.configure_transports_json('{"p2p_ephemeral":true,"p2p_port_mapping":false}')
            eph1 = ep.serve_p2p("disabled").split("?", 1)[0]
            eph2 = ep.serve_p2p("disabled").split("?", 1)[0]
            self.assertTrue(eph1.startswith("iroh://"))
            self.assertNotEqual(eph1, eph2)

            direct_addr = host_ep.serve_direct("127.0.0.1:0")
            code = host_ep.issue_code("lan")
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                f_acc = pool.submit(host_ep.pair_v2_accept, 5000)
                f_cli = pool.submit(
                    cli_ep.pair_v2_initiate, direct_addr, code, None, "py-cli", "python"
                )
                acc = json.loads(f_acc.result(timeout=10))
                pair_res = json.loads(f_cli.result(timeout=10))
            pending_dev = acc["device_id"]
            with self.assertRaisesRegex(RuntimeError, r"(?i)pending|not active"):
                host_ep.serve_p2p_v2("disabled", pending_dev)
            with self.assertRaisesRegex(RuntimeError, r"(?i)pending|not active"):
                host_ep.serve_relay_v2("ws://127.0.0.1:9/v2/relay", None, pending_dev)

            host_ep.confirm_peer(pending_dev, pair_res["sas"])
            self.assertEqual(host_ep.serve_p2p_v2("disabled"), "iroh://v2")
            self.assertEqual(host_ep.serve_p2p_v2("disabled"), "iroh://v2")
        finally:
            ep.close()
            host_ep.close()
            cli_ep.close()


if __name__ == "__main__":
    unittest.main()
