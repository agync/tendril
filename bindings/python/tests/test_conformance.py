import base64
import json
import pathlib
import subprocess
import threading
import time
import unittest

import tendril

ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS = ROOT / "spec" / "vectors"
PEER_BIN = ROOT / "target" / "debug" / "tendril-conformance-peer"


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
        grant = host_ep.mint_grant(accepted_holder["res"]["device_id"], ["fs.read"], 3600)

        sess_holder: dict = {}

        def accept_sess() -> None:
            sess_holder["sess"] = host_ep.accept_session(5000)

        t2 = threading.Thread(target=accept_sess)
        t2.start()
        cli_sess = cli_ep.connect(addr, "py-host", grant)
        t2.join(timeout=5)
        host_sess = sess_holder["sess"]
        self.assertTrue(host_sess.authorize("fs.read"))
        self.assertFalse(host_sess.authorize("shell.exec"))
        cli_sess.send_data(b"hello-gil-free")
        ev = json.loads(host_sess.poll_event(2000))
        self.assertEqual(ev["event"], "data")
        host_ep.revoke_peer(accepted_holder["res"]["device_id"])
        self.assertFalse(host_sess.authorize("fs.read"))
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

            peer.send({"op": "connect"})
            s = py_cli.connect(ep, "rust-host", json.dumps(grant_obj))
            self.assertTrue(peer.recv()["ok"])
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

            py_host_sess.close()
            peer2.call({"op": "shutdown"})
        finally:
            py_host.close()
            peer2.close()

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


if __name__ == "__main__":
    unittest.main()
