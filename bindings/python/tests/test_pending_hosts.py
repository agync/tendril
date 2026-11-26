import json
import tempfile
import threading
import unittest

import tendril


class PendingHostsTest(unittest.TestCase):
    def test_list_remove_and_revoke_unconfirmed_claims(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "pend-host")
            cli = tendril.Endpoint(cli_dir, "pend-cli")
            try:
                addr = host.serve_direct("127.0.0.1:0")
                code = host.issue_code("lan")
                t = threading.Thread(target=lambda: host.pair_accept(5000))
                t.start()
                cli.pair_initiate(addr, code)
                t.join(timeout=10)

                claims = json.loads(cli.pending_hosts())
                self.assertEqual([c["host_id"] for c in claims], ["pend-host"])
                device_id = json.loads(host.info_json())["device_id"]
                self.assertEqual(claims[0]["device_id"], device_id)
                self.assertTrue(claims[0]["pairing_sas"])

                # A claimed host_id is not an authenticated id.
                with self.assertRaises(Exception):
                    cli.revoke_pending_host("pend-host")
                self.assertEqual(len(json.loads(cli.pending_hosts())), 1)

                cli.revoke_pending_host(device_id)
                self.assertEqual(json.loads(cli.pending_hosts()), [])
                with self.assertRaises(Exception):
                    cli.remove_pending_host("pend-host")
            finally:
                host.close()
                cli.close()

    def test_remove_pending_host_drops_the_claim_and_revokes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "rm-host")
            cli = tendril.Endpoint(cli_dir, "rm-cli")
            try:
                addr = host.serve_direct("127.0.0.1:0")
                code = host.issue_code("lan")
                t = threading.Thread(target=lambda: host.pair_accept(5000))
                t.start()
                cli.pair_initiate(addr, code)
                t.join(timeout=10)
                self.assertEqual(len(json.loads(cli.pending_hosts())), 1)
                cli.remove_pending_host("rm-host")
                self.assertEqual(json.loads(cli.pending_hosts()), [])
                reopened = tendril.Endpoint(cli_dir, None)
                self.assertEqual(json.loads(reopened.pending_hosts()), [])
                reopened.close()
            finally:
                host.close()
                cli.close()

    def test_remove_never_touches_an_inbound_pending_device(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "inb-host")
            cli = tendril.Endpoint(cli_dir, "inb-cli")
            try:
                addr = host.serve_direct("127.0.0.1:0")
                code = host.issue_code("lan")
                accepted = {}
                t = threading.Thread(target=lambda: accepted.update(json.loads(host.pair_accept(5000))))
                t.start()
                sas = json.loads(cli.pair_initiate(addr, code))["sas"]
                t.join(timeout=10)
                inbound = accepted["device_id"]

                # The host holds the client as a pending device, not a claim.
                with self.assertRaises(Exception):
                    host.remove_pending_host(inbound)
                host.confirm_peer(inbound, sas)

                # An active entry is no claim either.
                cli.confirm_peer("inb-host", sas)
                with self.assertRaises(Exception):
                    cli.remove_pending_host("inb-host")
                self.assertEqual(json.loads(cli.peer_routes("inb-host"))["routes"], [])
            finally:
                host.close()
                cli.close()


if __name__ == "__main__":
    unittest.main()
