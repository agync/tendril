"""Pairing URI, route policy, endpoint-free connect and route announcement flows."""

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import tendril


def snapshot(*addrs: str) -> str:
    return json.dumps(
        {
            "networks": [
                {
                    "id": "wlan0",
                    "iface": "wlan0",
                    "if_index": 3,
                    "transports": ["wifi"],
                    "addrs": list(addrs),
                }
            ]
        }
    )


def hints(uri: str) -> list[str]:
    """The `ep` hints of a pairing URI, percent-decoded."""
    from urllib.parse import parse_qs, urlsplit

    return [h for ep in parse_qs(urlsplit(uri).query).get("ep", []) for h in ep.split(",")]


def accept_in_thread(fn, *args) -> tuple[threading.Thread, dict]:
    holder: dict = {}

    def run() -> None:
        try:
            holder["res"] = fn(*args)
        except Exception as exc:  # noqa: BLE001 - surfaced by the caller
            holder["err"] = exc

    t = threading.Thread(target=run)
    t.start()
    return t, holder


def pair_over_uri(host, cli, uri: str, v2: bool = False, options: dict | None = None) -> dict:
    """Pairs `cli` with `host` through `uri` and confirms both sides."""
    accept = host.pair_v2_accept if v2 else host.pair_accept
    t, holder = accept_in_thread(accept, 8000)
    pair = cli.pair_v2_uri if v2 else cli.pair_uri
    opts = json.dumps(options) if options is not None else None
    res = json.loads(pair(uri, "py-uri-cli", "python", opts))
    t.join(timeout=10)
    if "err" in holder:
        raise holder["err"]
    # The URI pins the host, so the client side is already active; the host confirms the device.
    assert res["host_confirmed"] and res["status"] == "active", res
    host.confirm_peer(res["device_id"], res["sas"])
    return res


def open_session(host, cli, target: str, grant: str, endpoint=None, v2: bool = False):
    accept = host.accept_v2 if v2 else host.accept_session
    connect = cli.connect_v2 if v2 else cli.connect
    t, holder = accept_in_thread(accept, 10000)
    try:
        cli_sess = connect(endpoint, target, grant)
    finally:
        t.join(timeout=15)
    if "err" in holder:
        raise holder["err"]
    return cli_sess, holder["res"]


class PairingUriConfigTests(unittest.TestCase):
    def test_new_transport_config_keys_are_validated(self) -> None:
        ep = tendril.Endpoint(None, "py-cfg")
        try:
            ep.configure_transports_json(
                json.dumps(
                    {
                        "relay_auth_origins": ["wss://relay.example", "ws://127.0.0.1:8080"],
                        "advertise": "explicit",
                        "advertised_endpoints": ["wss://relay.example/v1/relay"],
                        "route_policy": "committed_only",
                        "sign_routes": False,
                        "power_profile": "low_power",
                    }
                )
            )
            for bad in (
                {"advertise": "sometimes"},
                {"relay_auth_origins": ["wss://relay.example/with/path"]},
                {"relay_auth_origins": ["not an origin"]},
                {"route_policy": "most"},
                {"power_profile": "ultra"},
                {"wake_retry_max_delay_ms": 2000},
            ):
                with self.assertRaises(ValueError, msg=str(bad)):
                    ep.configure_transports_json(json.dumps(bad))
            with self.assertRaises(ValueError):
                ep.configure_transports_json(json.dumps({"relay_origins": []}))
        finally:
            ep.close()


class PairingUriFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.host = tendril.Endpoint(f"{self._tmp.name}/host", "py-uri-host")
        self.cli = tendril.Endpoint(f"{self._tmp.name}/cli", "py-uri-cli")
        self.addCleanup(self.host.close)
        self.addCleanup(self.cli.close)

    def grant_for(self, device_id: str) -> str:
        return self.host.mint_grant(device_id, ["fs.read"], 3600)

    def test_issue_pairing_uri_report(self) -> None:
        addr = self.host.serve_direct("127.0.0.1:0")
        issued = json.loads(self.host.issue_pairing_uri())
        self.assertEqual(
            sorted(issued),
            ["code_kind", "dropped", "qr_version_m", "route_seq", "uri", "uri_len"],
        )
        self.assertEqual(issued["code_kind"], "lan")
        self.assertEqual(issued["route_seq"], 1)
        self.assertEqual(issued["dropped"], [])
        self.assertEqual(issued["uri_len"], len(issued["uri"]))
        self.assertEqual(hints(issued["uri"]), [f"direct:{addr}"])
        self.assertIn("&rq=1&", issued["uri"])
        self.assertIn("&rs=", issued["uri"])

        unsigned = json.loads(
            self.host.issue_pairing_uri(json.dumps({"sign_routes": False, "host_name": "named"}))
        )
        self.assertIsNone(unsigned["route_seq"])
        self.assertNotIn("&rs=", unsigned["uri"])
        self.assertIn("host=named", unsigned["uri"])

        with self.assertRaises(ValueError):
            self.host.issue_pairing_uri(json.dumps({"kind": "sideways"}))
        with self.assertRaises(ValueError):
            self.host.issue_pairing_uri(json.dumps({"extra_endpoints": ["direct:1.2.3.4:5"]}))

    def test_issue_pairing_uri_reports_announced_set_drops(self) -> None:
        self.host.configure_transports_json(
            json.dumps({"advertise": "explicit", "advertised_endpoints": ["direct:0.0.0.0:7000"]})
        )
        self.host.serve_direct("127.0.0.1:0")
        issued = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))
        self.assertEqual(
            issued["dropped"], [{"hint": "direct:0.0.0.0:7000", "reason": "unspecified_bind"}]
        )

    def test_dropped_hints_are_printed_redacted(self) -> None:
        self.host.configure_transports_json(
            json.dumps(
                {
                    "advertise": "explicit",
                    "advertised_endpoints": ["ws://user:SECRETPW@relay.example/v1/relay?t=SECRETTOKEN"],
                }
            )
        )
        self.host.serve_direct("127.0.0.1:0")
        raw = self.host.issue_pairing_uri()
        self.assertNotIn("SECRETPW", raw)
        self.assertNotIn("SECRETTOKEN", raw)
        dropped = json.loads(raw)["dropped"]
        self.assertEqual(
            [(d["hint"], d["reason"]) for d in dropped],
            [("ws://relay.example", "invalid")],
        )

    def test_code_kind_names_are_case_insensitive(self) -> None:
        self.host.serve_direct("127.0.0.1:0")
        self.assertEqual(
            json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "REMOTE"})))["code_kind"],
            "remote",
        )
        self.assertEqual(
            json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "Auto"})))["code_kind"],
            "lan",
        )
        self.assertGreater(
            len(self.host.issue_code("Remote").split("-")),
            len(self.host.issue_code("LAN").split("-")),
        )
        with self.assertRaises(ValueError):
            self.host.issue_code("sideways")

    def test_pair_uri_v1_persists_signed_routes_and_connects_endpoint_free(self) -> None:
        addr = self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        res = pair_over_uri(self.host, self.cli, uri)

        self.assertEqual(res["provider"], "direct")
        self.assertEqual(res["endpoint"], f"direct:{addr}")
        self.assertTrue(res["committed"])
        self.assertEqual(res["route_check"], "verified")
        self.assertEqual(
            res["routes_persisted"], [{"hint": f"direct:{addr}", "source": "signed"}]
        )
        self.assertEqual(res["skipped"], [])
        self.assertEqual(res["status"], "active")
        self.assertNotIn("wire_version", res)

        view = json.loads(self.cli.peer_routes("py-uri-host"))
        self.assertEqual(view["routes"], [{"hint": f"direct:{addr}", "source": "signed"}])
        self.assertEqual(view["route_meta"]["seq"], 1)
        self.assertEqual(view["route_meta"]["origin"], "uri")
        self.assertIsNone(view["last_route_set"])

        sess, host_sess = open_session(
            self.host, self.cli, "py-uri-host", self.grant_for(res["device_id"])
        )
        sess.send_data(b"endpoint-free")
        ev = json.loads(host_sess.poll_event(3000))
        self.assertEqual(ev["event"], "data")
        sess.close()

    def test_pair_uri_route_policy_none_persists_no_routes(self) -> None:
        self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        res = pair_over_uri(
            self.host, self.cli, uri, options={"route_policy": "none"}
        )
        self.assertEqual(res["route_check"], "verified")
        self.assertEqual(res["routes_persisted"], [])
        self.assertEqual(json.loads(self.cli.peer_routes("py-uri-host"))["routes"], [])
        with self.assertRaises(RuntimeError) as ctx:
            self.cli.connect(None, "py-uri-host", None)
        self.assertIn("no dialable stored routes", str(ctx.exception))

    def test_configured_route_policy_is_the_pairing_default(self) -> None:
        self.cli.configure_transports_json(json.dumps({"route_policy": "none"}))
        self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        res = pair_over_uri(self.host, self.cli, uri)
        self.assertEqual(res["routes_persisted"], [])

    def test_unsigned_uri_saves_the_committed_route_only_on_request(self) -> None:
        addr = self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri(json.dumps({"sign_routes": False})))["uri"]
        res = pair_over_uri(self.host, self.cli, uri, options={"save_route": True})
        self.assertEqual(res["route_check"], "unsigned")
        self.assertEqual(
            res["routes_persisted"], [{"hint": f"direct:{addr}", "source": "committed"}]
        )

        other = tendril.Endpoint(f"{self._tmp.name}/other", "py-uri-other")
        self.addCleanup(other.close)
        uri2 = json.loads(self.host.issue_pairing_uri(json.dumps({"sign_routes": False})))["uri"]
        res2 = pair_over_uri(self.host, other, uri2)
        self.assertEqual(res2["route_check"], "unsigned")
        self.assertEqual(res2["routes_persisted"], [])

        with self.assertRaises(RuntimeError):
            self.cli.pair_uri(uri2, options_json=json.dumps({"route_policy": "none", "save_route": True}))

    def test_pair_v2_uri_and_endpoint_free_connect_v2(self) -> None:
        addr = self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        res = pair_over_uri(self.host, self.cli, uri, v2=True)
        self.assertEqual(res["wire_version"], 2)
        self.assertEqual(res["route_check"], "verified")
        self.assertEqual(res["provider"], "direct")
        self.assertEqual(
            res["routes_persisted"], [{"hint": f"direct:{addr}", "source": "signed"}]
        )

        sess, host_sess = open_session(
            self.host, self.cli, "py-uri-host", self.grant_for(res["device_id"]), v2=True
        )
        sess.send_data(b"v2-endpoint-free")
        ev = json.loads(host_sess.poll_event(3000))
        self.assertEqual(ev["event"], "data")
        sess.close()

    def test_store_less_endpoints_pair_and_connect_endpoint_free(self) -> None:
        host = tendril.Endpoint(None, "py-mem-host")
        cli = tendril.Endpoint(None, "py-mem-cli")
        self.addCleanup(host.close)
        self.addCleanup(cli.close)
        addr = host.serve_direct("127.0.0.1:0")
        uri = json.loads(host.issue_pairing_uri())["uri"]
        res = pair_over_uri(host, cli, uri)
        self.assertEqual(res["route_check"], "verified")
        view = json.loads(cli.peer_routes("py-mem-host"))
        self.assertEqual(view["routes"], [{"hint": f"direct:{addr}", "source": "signed"}])
        cli.set_peer_routes("py-mem-host", json.dumps(["127.0.0.1:19"]))
        self.assertEqual(
            sorted(r["source"] for r in json.loads(cli.peer_routes("py-mem-host"))["routes"]),
            ["operator", "signed"],
        )
        grant = host.mint_grant(res["device_id"], ["fs.read"], 3600)
        sess, host_sess = open_session(host, cli, "py-mem-host", grant)
        sess.send_data(b"store-less")
        self.assertEqual(json.loads(host_sess.poll_event(3000))["event"], "data")
        sess.close()

    def test_pair_uri_endpoint_override_is_dialed_alone_and_saved_as_operator(self) -> None:
        self.host.configure_transports_json(
            json.dumps({"advertise": "explicit", "advertised_endpoints": ["direct:192.168.77.5:9"]})
        )
        addr = self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]
        self.assertIn("direct:192.168.77.5:9", hints(uri))
        res = pair_over_uri(self.host, self.cli, uri, options={"endpoint": addr})
        self.assertEqual(res["endpoint"], f"direct:{addr}")
        by_source = {r["source"]: r["hint"] for r in res["routes_persisted"]}
        self.assertEqual(by_source["operator"], f"direct:{addr}")
        self.assertEqual(by_source["signed"], "direct:192.168.77.5:9")

    def test_pair_uri_refusals_before_any_dial(self) -> None:
        self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        with self.assertRaises(ValueError):
            self.cli.pair_uri("not a pairing uri")
        with self.assertRaises(ValueError):
            self.cli.pair_uri(uri, options_json=json.dumps({"route_polcy": "none"}))
        with self.assertRaises(ValueError):
            self.cli.pair_uri(uri, options_json=json.dumps({"route_policy": "none "}))
        with self.assertRaises(RuntimeError) as bad_code:
            self.cli.pair_uri(uri, options_json=json.dumps({"code": "0000-0000"}))
        self.assertIn("pairing code", str(bad_code.exception).lower())
        with self.assertRaises(RuntimeError) as blocked:
            self.cli.pair_uri(
                uri, options_json=json.dumps({"endpoint": "direct:169.254.169.254:80"})
            )
        self.assertIn("169.254.169.254", str(blocked.exception))
        with self.assertRaises(RuntimeError) as relay_v2:
            self.cli.pair_v2_uri(
                uri, options_json=json.dumps({"endpoint": "ws://127.0.0.1:9/v2/relay"})
            )
        self.assertIn("/v2/relay is not used for pairing", str(relay_v2.exception))

    def test_peer_route_setter_roundtrip(self) -> None:
        addr = self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        pair_over_uri(self.host, self.cli, uri)

        set_res = json.loads(
            self.cli.set_peer_routes(
                "py-uri-host", json.dumps(["127.0.0.1:19", "/tmp/tendril-uri-test.sock"])
            )
        )
        self.assertEqual(
            sorted((r["source"], r["hint"]) for r in set_res),
            [
                ("operator", "direct:127.0.0.1:19"),
                ("operator", "local:/tmp/tendril-uri-test.sock"),
                ("signed", f"direct:{addr}"),
            ],
        )

        # A bad entry fails the whole batch and writes nothing.
        with self.assertRaises(RuntimeError):
            self.cli.set_peer_routes(
                "py-uri-host", json.dumps(["127.0.0.1:20", "direct:169.254.169.254:80"])
            )
        with self.assertRaises(RuntimeError):
            self.cli.set_peer_routes("py-uri-host", json.dumps([f"127.0.0.1:{n}" for n in range(30, 37)]))
        with self.assertRaises(ValueError):
            self.cli.set_peer_routes("py-uri-host", json.dumps({"not": "a list"}))
        with self.assertRaises(RuntimeError):
            self.cli.set_peer_routes("nobody", json.dumps(["127.0.0.1:19"]))
        kept = json.loads(self.cli.peer_routes("py-uri-host"))["routes"]
        self.assertEqual(len([r for r in kept if r["source"] == "operator"]), 2)

        self.cli.clear_peer_routes("py-uri-host")
        left = json.loads(self.cli.peer_routes("py-uri-host"))["routes"]
        self.assertEqual(left, [{"hint": f"direct:{addr}", "source": "signed"}])

        self.cli.set_peer_routes("py-uri-host", json.dumps(["127.0.0.1:19"]))
        self.cli.clear_peer_routes("py-uri-host", "signed")
        self.assertEqual(
            json.loads(self.cli.peer_routes("py-uri-host"))["routes"],
            [{"hint": "direct:127.0.0.1:19", "source": "operator"}],
        )
        self.cli.clear_peer_routes("py-uri-host", "all")
        self.assertEqual(json.loads(self.cli.peer_routes("py-uri-host"))["routes"], [])
        with self.assertRaises(ValueError):
            self.cli.clear_peer_routes("py-uri-host", "everything")
        with self.assertRaises(RuntimeError):
            self.cli.peer_routes("nobody")

    def test_refresh_routes_snapshot_and_apply_route_uri(self) -> None:
        port_addr = self.host.serve_direct("0.0.0.0:0")
        port = port_addr.rsplit(":", 1)[1]
        first = json.loads(self.host.refresh_routes(snapshot("192.168.1.20/24")))
        self.assertEqual(first, {"route_seq": 1, "changed": True})
        again = json.loads(self.host.refresh_routes(snapshot("192.168.1.20")))
        self.assertEqual(again, {"route_seq": 1, "changed": False})
        with self.assertRaises(ValueError):
            self.host.refresh_routes("{not json")

        uri_a = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]
        self.assertEqual(hints(uri_a), [f"direct:192.168.1.20:{port}"])

        # The LAN address is not reachable here: dial the loopback bind as the operator.
        res = pair_over_uri(
            self.host, self.cli, uri_a, options={"endpoint": f"127.0.0.1:{port}"}
        )
        self.assertEqual(res["route_check"], "verified")

        changed = json.loads(self.host.refresh_routes(snapshot("192.168.1.99")))
        self.assertEqual(changed, {"route_seq": 2, "changed": True})
        uri_b = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]
        self.assertEqual(hints(uri_b), [f"direct:192.168.1.99:{port}"])

        applied = json.loads(self.cli.apply_route_uri(uri_b))
        self.assertEqual(
            applied, {"peer_id": "py-uri-host", "applied": True, "reason": None, "route_seq": 2}
        )
        signed = [
            r["hint"]
            for r in json.loads(self.cli.peer_routes("py-uri-host"))["routes"]
            if r["source"] == "signed"
        ]
        self.assertEqual(signed, [f"direct:192.168.1.99:{port}"])

        stale = json.loads(self.cli.apply_route_uri(uri_a))
        self.assertFalse(stale["applied"])
        self.assertEqual(stale["reason"], "stale_route_seq")
        approved = json.loads(
            self.cli.apply_route_uri(uri_a, json.dumps({"replace_routes": True}))
        )
        self.assertTrue(approved["applied"])
        none_policy = json.loads(
            self.cli.apply_route_uri(uri_b, json.dumps({"route_policy": "none"}))
        )
        self.assertFalse(none_policy["applied"])
        self.assertEqual(none_policy["reason"], "route_policy")

        stranger = tendril.Endpoint(None, "py-uri-stranger")
        self.addCleanup(stranger.close)
        with self.assertRaises(RuntimeError) as ctx:
            stranger.apply_route_uri(uri_b)
        self.assertIn("no paired host matches", str(ctx.exception))
        with self.assertRaises(ValueError):
            self.cli.apply_route_uri(uri_b, json.dumps({"replace": True}))

    def test_connect_with_options_recovery_uri_and_policy(self) -> None:
        port_addr = self.host.serve_direct("0.0.0.0:0")
        port = port_addr.rsplit(":", 1)[1]
        self.host.refresh_routes(snapshot("192.168.1.20"))
        uri_a = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]
        res = pair_over_uri(
            self.host, self.cli, uri_a, options={"endpoint": f"127.0.0.1:{port}"}
        )
        grant = json.loads(self.grant_for(res["device_id"]))
        self.host.refresh_routes(snapshot("192.168.1.99"))
        uri_b = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]

        options = {
            "wire": 1,
            "grant": grant,
            "endpoint": f"127.0.0.1:{port}",
            "recovery_uri": uri_b,
        }
        for bad in ({"wire": 3}, {"wire": 1, "bogus": True}, {"route_policy": "sometimes"}):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.cli.connect_with_options("py-uri-host", json.dumps(bad))

        t, holder = accept_in_thread(self.host.accept_session, 10000)
        sess = self.cli.connect_with_options("py-uri-host", json.dumps(options))
        t.join(timeout=15)
        self.assertNotIn("err", holder)
        sess.send_data(b"recovered")
        self.assertEqual(json.loads(holder["res"].poll_event(3000))["event"], "data")
        signed = [
            r["hint"]
            for r in json.loads(self.cli.peer_routes("py-uri-host"))["routes"]
            if r["source"] == "signed"
        ]
        self.assertEqual(signed, [f"direct:192.168.1.99:{port}"])
        sess.close()

        # A recovery URI under route_policy none checks the host keys but changes no routes.
        self.host.refresh_routes(snapshot("192.168.1.150"))
        uri_c = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]
        t2, holder2 = accept_in_thread(self.host.accept_session, 10000)
        sess2 = self.cli.connect_with_options(
            "py-uri-host",
            json.dumps(
                {
                    "grant": grant,
                    "endpoint": f"127.0.0.1:{port}",
                    "recovery_uri": uri_c,
                    "route_policy": "none",
                }
            ),
        )
        t2.join(timeout=15)
        self.assertNotIn("err", holder2)
        signed_after = [
            r["hint"]
            for r in json.loads(self.cli.peer_routes("py-uri-host"))["routes"]
            if r["source"] == "signed"
        ]
        self.assertEqual(signed_after, [f"direct:192.168.1.99:{port}"])
        sess2.close()

    def _pair_for_route_sets(self):
        port_addr = self.host.serve_direct("0.0.0.0:0")
        port = port_addr.rsplit(":", 1)[1]
        self.host.refresh_routes(snapshot("192.168.1.20"))
        uri = json.loads(self.host.issue_pairing_uri(json.dumps({"kind": "lan"})))["uri"]
        res = pair_over_uri(
            self.host, self.cli, uri, options={"endpoint": f"127.0.0.1:{port}"}
        )
        return port, res

    def _wait_for_route_set(self, sess, seq: int, seconds: float) -> dict:
        deadline = time.monotonic() + seconds
        view: dict = {}
        while time.monotonic() < deadline:
            ev = json.loads(sess.poll_event(250))
            self.assertNotIn(ev["status"], ("eof",))
            self.assertNotEqual(ev.get("event"), "data")
            view = json.loads(self.cli.peer_routes("py-uri-host"))
            last = view["last_route_set"]
            if last is not None and last["seq"] == seq:
                return view
        self.fail(f"route set {seq} not applied in time: {view}")

    def test_session_start_sends_the_current_route_set(self) -> None:
        port, res = self._pair_for_route_sets()
        self.assertEqual(json.loads(self.host.refresh_routes(snapshot("192.168.1.77")))["route_seq"], 2)
        sess, host_sess = open_session(
            self.host,
            self.cli,
            "py-uri-host",
            self.grant_for(res["device_id"]),
            endpoint=f"127.0.0.1:{port}",
        )
        try:
            view = self._wait_for_route_set(sess, 2, 20)
            self.assertEqual(view["last_route_set"], {"outcome": "applied", "seq": 2})
            signed = [r["hint"] for r in view["routes"] if r["source"] == "signed"]
            self.assertEqual(signed, [f"direct:192.168.1.77:{port}"])
            self.assertEqual(view["route_meta"]["seq"], 2)
            self.assertEqual(view["route_meta"]["origin"], "session")
            # The route set never surfaced as an application event.
            sess.send_data(b"still-open")
            self.assertEqual(json.loads(host_sess.poll_event(3000))["event"], "data")
        finally:
            sess.close()

    def test_live_session_receives_a_refreshed_route_set(self) -> None:
        port, res = self._pair_for_route_sets()
        sess, host_sess = open_session(
            self.host,
            self.cli,
            "py-uri-host",
            self.grant_for(res["device_id"]),
            endpoint=f"127.0.0.1:{port}",
        )
        try:
            self._wait_for_route_set(sess, 1, 20)
            self.assertEqual(json.loads(self.host.refresh_routes(snapshot("192.168.1.88")))["route_seq"], 2)
            # The host sends at most one route set per session every 30 s.
            view = self._wait_for_route_set(sess, 2, 60)
            signed = [r["hint"] for r in view["routes"] if r["source"] == "signed"]
            self.assertEqual(signed, [f"direct:192.168.1.88:{port}"])
        finally:
            sess.close()


class WakeServer:
    """A webhook endpoint that records every wake request it receives."""

    def __init__(self, on_wake=None) -> None:
        self.requests: list[dict] = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                requests.append(json.loads(self.rfile.read(length).decode("utf-8")))
                if on_wake is not None:
                    on_wake()
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/wake"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class WakePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.host = tendril.Endpoint(f"{self._tmp.name}/host", "py-wake-host")
        self.cli = tendril.Endpoint(f"{self._tmp.name}/cli", "py-wake-cli")
        self.addCleanup(self.host.close)
        self.addCleanup(self.cli.close)
        self.wake = WakeServer()
        self.addCleanup(self.wake.close)

    def configure(self, pre_wake: bool, wake: WakeServer | None = None) -> None:
        secret = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        self.cli.configure_transports_json(
            json.dumps(
                {
                    "wake_url": (wake or self.wake).url,
                    "wake_adapter": "webhook",
                    "wake_secret_b64": secret,
                    "wake_pre_wake": pre_wake,
                    "wake_retry_delay_ms": 25,
                    "wake_max_attempts": 3,
                    "wake_timeout_ms": 2000,
                }
            )
        )

    def pair_v2(self) -> tuple[str, dict]:
        addr = self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        res = pair_over_uri(self.host, self.cli, uri, v2=True)
        return addr, res

    def options(self, res: dict, addr: str) -> dict:
        grant = json.loads(self.host.mint_grant(res["device_id"], ["fs.read"], 3600))
        recovery = json.loads(self.host.issue_pairing_uri())["uri"]
        return {"wire": 2, "grant": grant, "endpoint": addr, "recovery_uri": recovery}

    def test_pre_wake_wakes_before_the_connect(self) -> None:
        self.configure(pre_wake=True)
        addr, res = self.pair_v2()
        options = self.options(res, addr)
        t, holder = accept_in_thread(self.host.accept_v2, 10000)
        sess = self.cli.connect_with_options("py-wake-host", json.dumps(options))
        t.join(timeout=15)
        self.assertNotIn("err", holder)
        self.assertEqual(len(self.wake.requests), 1)
        sess.send_data(b"woken")
        self.assertEqual(json.loads(holder["res"].poll_event(3000))["event"], "data")
        sess.close()

    def test_connect_first_does_not_wake_a_reachable_host(self) -> None:
        self.configure(pre_wake=False)
        addr, res = self.pair_v2()
        options = self.options(res, addr)
        t, holder = accept_in_thread(self.host.accept_v2, 10000)
        sess = self.cli.connect_with_options("py-wake-host", json.dumps(options))
        t.join(timeout=15)
        self.assertNotIn("err", holder)
        self.assertEqual(self.wake.requests, [])
        sess.close()

    def test_connect_first_wakes_on_a_transient_miss_and_retries(self) -> None:
        sleeping = socket.socket()
        sleeping.bind(("127.0.0.1", 0))
        port = sleeping.getsockname()[1]
        sleeping.close()
        accepted: dict = {}

        def start_host() -> None:
            # The wake hint arrives: the sleeping host starts listening on the dialed port.
            self.host.serve_direct(f"127.0.0.1:{port}")
            t, holder = accept_in_thread(self.host.accept_v2, 10000)
            accepted.update(thread=t, holder=holder)

        wake = WakeServer(on_wake=start_host)
        self.addCleanup(wake.close)
        self.configure(pre_wake=False, wake=wake)
        _, res = self.pair_v2()
        options = self.options(res, f"127.0.0.1:{port}")
        sess = self.cli.connect_with_options("py-wake-host", json.dumps(options))
        accepted["thread"].join(timeout=15)
        self.assertNotIn("err", accepted["holder"])
        self.assertEqual(len(wake.requests), 1)
        sess.close()

    def test_a_transient_miss_after_wake_exhausts_the_attempts(self) -> None:
        sleeping = socket.socket()
        sleeping.bind(("127.0.0.1", 0))
        port = sleeping.getsockname()[1]
        sleeping.close()
        self.configure(pre_wake=False)
        _, res = self.pair_v2()
        options = self.options(res, f"127.0.0.1:{port}")
        with self.assertRaises(RuntimeError):
            self.cli.connect_with_options("py-wake-host", json.dumps(options))
        self.assertEqual(len(self.wake.requests), 1)

    def test_wake_connect_refuses_a_blocked_destination_without_a_legacy_dial(self) -> None:
        _, res = self.pair_v2()
        grant = self.host.mint_grant(res["device_id"], ["fs.read"], 3600)
        for pre_wake in (False, True):
            with self.subTest(pre_wake=pre_wake):
                self.configure(pre_wake=pre_wake)
                before = len(self.wake.requests)
                with self.assertRaises(RuntimeError) as ctx:
                    self.cli.connect_v2("169.254.169.254:9", "py-wake-host", grant)
                self.assertIn("invalid endpoint", str(ctx.exception))
                # A policy refusal is final. Connect-first never wakes the host for it; pre-wake
                # has already sent its one hint.
                self.assertEqual(len(self.wake.requests) - before, 1 if pre_wake else 0)

    def test_low_power_stored_route_v2_wake_idle_timeout_and_external_monitor(self) -> None:
        _, res = self.pair_v2()
        grant = json.loads(self.host.mint_grant(res["device_id"], ["fs.read"], 3600))
        sleeping = socket.socket()
        sleeping.bind(("127.0.0.1", 0))
        port = sleeping.getsockname()[1]
        sleeping.close()

        self.cli.clear_peer_routes("py-wake-host", "all")
        self.cli.set_peer_routes("py-wake-host", json.dumps([f"127.0.0.1:{port}"]))

        with self.assertRaises(ValueError):
            self.cli.connect_with_options(
                "py-wake-host",
                json.dumps({"wire": 2, "grant": grant, "idle_timeout_ms": 0}),
            )

        secret = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        accepted: dict = {}

        def start_host() -> None:
            self.host.serve_direct(f"127.0.0.1:{port}")
            t, holder = accept_in_thread(self.host.accept_v2, 10000)
            accepted.update(thread=t, holder=holder)

        wake = WakeServer(on_wake=start_host)
        self.addCleanup(wake.close)
        self.cli.configure_transports_json(
            json.dumps(
                {
                    "power_profile": "low_power",
                    "wake_url": wake.url,
                    "wake_adapter": "webhook",
                    "wake_secret_b64": secret,
                    "wake_pre_wake": False,
                    "wake_retry_delay_ms": 25,
                    "wake_retry_max_delay_ms": 200,
                    "wake_max_attempts": 3,
                    "wake_timeout_ms": 2000,
                }
            )
        )
        self.host.configure_transports_json(json.dumps({"power_profile": "low_power"}))
        self.host.set_external_path_monitor(True)
        self.host.refresh_routes(None)
        self.host.set_external_path_monitor(False)

        sess = self.cli.connect_with_options(
            "py-wake-host",
            json.dumps({"wire": 2, "grant": grant, "idle_timeout_ms": 5000}),
        )
        accepted["thread"].join(timeout=15)
        self.assertNotIn("err", accepted["holder"])
        self.assertEqual(len(wake.requests), 1)
        sess.send_data(b"py-low-power")
        self.assertEqual(json.loads(accepted["holder"]["res"].poll_event(3000))["event"], "data")
        sess.close()


class PairingLockOrderTests(unittest.TestCase):
    def test_issuing_uris_while_a_pairing_runs_on_a_state_dir_host_completes(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        host = tendril.Endpoint(f"{tmp.name}/host", "py-lock-host")
        self.addCleanup(host.close)
        host.serve_direct("127.0.0.1:0")
        stop = threading.Event()
        # An issuance that fails after the publish (an empty host name is refused by the core
        # builder) takes no pairing code, so hammering it never fills the live-code cap, yet it
        # keeps the publish-then-issue path busy next to the pairings.
        refusals = [0]

        def hammer() -> None:
            while not stop.is_set():
                try:
                    host.issue_pairing_uri(json.dumps({"host_name": "\u0001"}))
                except RuntimeError:
                    refusals[0] += 1

        errors: list[BaseException] = []
        paired = [0]

        def pairings() -> None:
            try:
                for i in range(10):
                    cli = tendril.Endpoint(None, f"py-lock-cli-{i}")
                    try:
                        uri = json.loads(host.issue_pairing_uri())["uri"]
                        pair_over_uri(host, cli, uri, v2=bool(i % 2))
                        paired[0] += 1
                    finally:
                        cli.close()
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        hammers = [threading.Thread(target=hammer, daemon=True) for _ in range(3)]
        worker = threading.Thread(target=pairings, daemon=True)
        for t in hammers:
            t.start()
        worker.start()
        worker.join(timeout=90)
        stop.set()
        deadlocked = worker.is_alive()
        if not deadlocked:
            for t in hammers:
                t.join(timeout=10)
            deadlocked = any(t.is_alive() for t in hammers)
        self.assertFalse(deadlocked, "issuing and pairing deadlocked")
        self.assertEqual(errors, [])
        self.assertEqual(paired[0], 10)
        self.assertGreater(refusals[0], 0)


class SdkHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.host = tendril.Endpoint(f"{self._tmp.name}/host", "py-hard-host")
        self.cli = tendril.Endpoint(f"{self._tmp.name}/cli", "py-hard-cli")
        self.addCleanup(self.host.close)
        self.addCleanup(self.cli.close)

    def test_errors_never_echo_origins_hints_or_nested_urls(self) -> None:
        secret = "SECRETPW"
        ticket = "SECRETTICKET"
        with self.assertRaises(ValueError) as origin:
            self.cli.configure_transports_json(
                json.dumps({"relay_auth_origins": [f"wss://user:{secret}@relay.example/p?t={ticket}"]})
            )
        self.assertNotIn(secret, str(origin.exception))
        self.assertNotIn(ticket, str(origin.exception))

        self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        hint = f"wss://user:{secret}@169.254.169.254:9/v1/relay?ticket={ticket}"
        with self.assertRaises(RuntimeError) as pair:
            self.cli.pair_uri(uri, options_json=json.dumps({"endpoint": hint}))
        text = str(pair.exception)
        self.assertNotIn(secret, text)
        self.assertNotIn(ticket, text)
        self.assertIn("169.254.169.254", text)
        with self.assertRaises(RuntimeError) as dial:
            self.cli.connect_with_options(
                "py-hard-host", json.dumps({"wire": 1, "endpoint": hint})
            )
        self.assertNotIn(secret, str(dial.exception))
        self.assertNotIn(ticket, str(dial.exception))

        bad_uri = f"tendril://pair?v=1&host=x&code={secret}&junk={ticket}"
        with self.assertRaises(ValueError) as parse:
            self.cli.pair_uri(bad_uri)
        self.assertNotIn(secret, str(parse.exception))
        self.assertNotIn(ticket, str(parse.exception))

    def test_empty_code_override_is_rejected_before_any_dial(self) -> None:
        self.host.serve_direct("127.0.0.1:0")
        uri = json.loads(self.host.issue_pairing_uri())["uri"]
        t, holder = accept_in_thread(self.host.pair_accept, 1500)
        with self.assertRaises(RuntimeError) as ctx:
            self.cli.pair_uri(uri, options_json=json.dumps({"code": ""}))
        self.assertIn("pairing code", str(ctx.exception).lower())
        t.join(timeout=10)
        # Nothing dialed: the host timed out waiting, and the URI code is still unspent.
        self.assertIn("err", holder)
        self.assertNotIn("res", holder)

    def test_close_is_terminal_for_the_announcer(self) -> None:
        self.host.serve_direct("127.0.0.1:0")
        json.loads(self.host.issue_pairing_uri())
        self.host.close()
        with self.assertRaises(RuntimeError) as refresh:
            self.host.refresh_routes()
        self.assertIn("closed", str(refresh.exception))
        with self.assertRaises(RuntimeError) as issue:
            self.host.issue_pairing_uri()
        self.assertIn("closed", str(issue.exception))

    def test_configure_transports_does_not_hold_the_gil_while_publishing(self) -> None:
        self.host.serve_direct("127.0.0.1:0")
        json.loads(self.host.issue_pairing_uri())  # starts the announcer
        lock_path = os.path.join(self._tmp.name, "host", ".roster.lock")
        # Another process holds the roster lock, so the publish blocks without any Python thread.
        holder_proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import fcntl,sys,time;f=open(sys.argv[1],'a+');"
                "fcntl.flock(f,fcntl.LOCK_EX);print('held',flush=True);time.sleep(1.5)",
                lock_path,
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder_proc.wait)
        self.assertEqual(holder_proc.stdout.readline().strip(), "held")
        stamps: list[float] = []
        stop = threading.Event()

        def ticker() -> None:
            while not stop.is_set():
                stamps.append(time.monotonic())
                time.sleep(0.01)

        counter = threading.Thread(target=ticker)
        counter.start()
        while len(stamps) < 5:
            time.sleep(0.01)
        worker, holder = accept_in_thread(
            self.host.configure_transports_json,
            json.dumps({"advertise": "explicit", "advertised_endpoints": ["192.0.2.9:7000"]}),
        )
        worker.join(timeout=15)
        stop.set()
        counter.join(timeout=5)
        self.assertNotIn("err", holder)
        gaps = [later - earlier for earlier, later in zip(stamps, stamps[1:])]
        self.assertLess(max(gaps), 0.5, "other Python threads stalled behind publish")
        # The call returned only after the publish: the roster already holds the new set.
        with open(os.path.join(self._tmp.name, "host", "roster.json"), encoding="utf-8") as f:
            routes = json.load(f)["local_routes"]["routes"]
        self.assertIn("direct:192.0.2.9:7000", routes)


if __name__ == "__main__":
    unittest.main()
