"""Revocations survive commits, reloads and restarts through the Python binding.

A memory-only revocation (one a live session learned and the store lacks) needs a session
that forks a rotation chain or receives a revocation frame, which the public API cannot
produce. These tests are regression guards for the roster handle every path now shares: they
pass on a binding without the shared fold too, and the runtime and FFI tests carry the red
cases (`crates/tendril-runtime/tests/held_revocations.rs`).
"""

import base64
import json
import pathlib
import tempfile
import threading
import unittest

import tendril


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signing_pub_of(ep: "tendril.Endpoint") -> bytes:
    return b64url_decode(json.loads(ep.info_json())["signing_pub"])


def read_roster(state_dir: str) -> dict:
    return json.loads((pathlib.Path(state_dir) / "roster.json").read_text(encoding="utf-8"))


def pair_v2(host, cli, host_addr: str, host_id: str) -> str:
    code = host.issue_code("lan")
    accepted: dict = {}

    def accept() -> None:
        accepted["res"] = json.loads(host.pair_v2_accept(8000))

    t = threading.Thread(target=accept)
    t.start()
    cli_res = json.loads(cli.pair_v2_initiate(host_addr, code, name="held-cli", kind="python"))
    t.join(timeout=10)
    dev_id = accepted["res"]["device_id"]
    host.confirm_peer(dev_id, cli_res["sas"])
    cli.confirm_peer(host_id, cli_res["sas"])
    return dev_id


class HeldRevocationTests(unittest.TestCase):
    def test_a_stale_handle_and_a_restart_never_unrevoke_a_peer_or_an_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "held-host")
            cli = tendril.Endpoint(cli_dir, "held-cli")
            anchor = tendril.Endpoint(None, "held-anchor")
            other = tendril.Endpoint(None, "held-other")
            # Loaded before any revocation: its copy of the roster is stale.
            stale = tendril.Endpoint(host_dir, None)
            try:
                host_addr = host.serve_direct("127.0.0.1:0")
                dev_id = pair_v2(host, cli, host_addr, "held-host")
                host.add_trust_anchor("held-anchor", signing_pub_of(anchor))
                host.revoke_peer(dev_id)
                host.revoke_trust_anchor("held-anchor")

                stale.add_trust_anchor("held-other", signing_pub_of(other))

                disk = read_roster(host_dir)
                self.assertEqual(disk["entries"][dev_id]["state"], "revoked")
                self.assertEqual(disk["trust_anchors"]["held-anchor"]["state"], "revoked")
                self.assertEqual(disk["trust_anchors"]["held-other"]["state"], "active")

                host.close()
                reopened = tendril.Endpoint(host_dir, None)
                try:
                    with self.assertRaises(RuntimeError):
                        reopened.mint_grant(dev_id, ["fs.read"], 60)
                    with self.assertRaises(RuntimeError):
                        reopened.add_trust_anchor("held-anchor", signing_pub_of(anchor))
                finally:
                    reopened.close()
            finally:
                host.close()
                cli.close()
                anchor.close()
                other.close()
                stale.close()

    def test_a_policy_connect_refuses_a_host_revoked_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "held-host")
            cli = tendril.Endpoint(cli_dir, "held-cli")
            try:
                host_addr = host.serve_direct("127.0.0.1:0")
                dev_id = pair_v2(host, cli, host_addr, "held-host")
                grant = host.mint_grant(dev_id, ["fs.read"], 3600)
                cli.revoke_peer("held-host")

                with self.assertRaises(RuntimeError):
                    cli.connect_v2(host_addr, "held-host", grant)
                disk = read_roster(cli_dir)
                self.assertEqual(disk["entries"]["held-host"]["state"], "revoked")
            finally:
                host.close()
                cli.close()


if __name__ == "__main__":
    unittest.main()
