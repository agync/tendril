import base64
import json
import pathlib
import subprocess
import threading
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

    def test_multithreaded_gil_release_and_interop_with_peer(self) -> None:
        # 1. Two Python threads running pair_accept / pair_initiate simultaneously prove GIL release.
        host_ep = tendril.Endpoint(None, "py-host")
        cli_ep = tendril.Endpoint(None, "py-cli")
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

            peer.call({"op": "send", "data_utf8": "back-to-python"})
            ev_py = json.loads(s.poll_event(2000))
            b64 = ev_py["data_b64"]
            decoded = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            self.assertEqual(decoded, b"back-to-python")

            s.close()
            py_cli.close()
            peer.call({"op": "shutdown"})
        finally:
            peer.close()


if __name__ == "__main__":
    unittest.main()
