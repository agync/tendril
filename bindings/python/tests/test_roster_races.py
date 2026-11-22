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

ROOT = pathlib.Path(__file__).resolve().parents[3]
TENDRIL_BIN = ROOT / "target" / "debug" / "tendril"


def ensure_tendril_bin() -> None:
    if not TENDRIL_BIN.exists():
        subprocess.run(
            ["cargo", "build", "-p", "tendril-cli", "--bin", "tendril"],
            cwd=ROOT,
            check=True,
        )


def run_cli(state_dir: str, *args: str) -> dict:
    res = subprocess.run(
        [str(TENDRIL_BIN), "--state-dir", state_dir, *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    lines = [line for line in res.stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


def start_cli_serve(state_dir: str, issue_code: bool = False):
    cmd = [
        str(TENDRIL_BIN),
        "--state-dir",
        state_dir,
        "serve",
        "--listen",
        "127.0.0.1:0",
    ]
    if issue_code:
        cmd.extend(["--issue-code", "lan"])
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"tendril serve exited early ({proc.poll()}): {stderr}")
        ev = json.loads(line)
        if ev.get("event") == "listening":
            return proc, ev
    proc.kill()
    raise RuntimeError("tendril serve timed out")


def stop_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()
    if proc.stderr is not None:
        proc.stderr.close()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signing_pub_of(ep: "tendril.Endpoint") -> bytes:
    return b64url_decode(json.loads(ep.info_json())["signing_pub"])


def read_roster(state_dir: str) -> dict:
    return json.loads((pathlib.Path(state_dir) / "roster.json").read_text(encoding="utf-8"))


def pair_v2(host, cli, host_addr: str, host_id: str, cli_name: str = "py-cli") -> str:
    code = host.issue_code("lan")
    accepted: dict = {}

    def accept() -> None:
        accepted["res"] = json.loads(host.pair_v2_accept(8000))

    t = threading.Thread(target=accept)
    t.start()
    cli_res = json.loads(
        cli.pair_v2_initiate(host_addr, code, name=cli_name, kind="python")
    )
    t.join(timeout=10)
    dev_id = accepted["res"]["device_id"]
    host.confirm_peer(dev_id, cli_res["sas"])
    cli.confirm_peer(host_id, cli_res["sas"])
    return dev_id


def open_v2_session(host, cli, host_addr: str, host_id: str, grant: str):
    holder: dict = {}

    def accept() -> None:
        try:
            holder["sess"] = host.accept_v2(8000)
        except RuntimeError as exc:
            holder["err"] = str(exc)

    t = threading.Thread(target=accept)
    t.start()
    try:
        cli_sess = cli.connect_v2(host_addr, host_id, grant)
    except RuntimeError:
        t.join(timeout=10)
        raise
    t.join(timeout=10)
    if "sess" not in holder:
        raise RuntimeError(holder.get("err", "accept_v2 failed"))
    return holder["sess"], cli_sess


class RosterRaceTests(unittest.TestCase):
    def test_concurrent_revoke_vs_poll_authorize_and_trust_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "race-host")
            cli = tendril.Endpoint(cli_dir, "race-cli")
            anchor_eps = [tendril.Endpoint(None, f"race-anchor-{i}") for i in range(5)]
            try:
                host_addr = host.serve_direct("127.0.0.1:0")
                dev_id = pair_v2(host, cli, host_addr, "race-host")
                grant = host.mint_grant(dev_id, ["fs.read"], 3600)
                host_sess, cli_sess = open_v2_session(host, cli, host_addr, "race-host", grant)
                self.assertTrue(host_sess.authorize("fs.read"))

                stop = threading.Event()
                revoke_done = threading.Event()
                violations: list = []
                errors: list = []

                def poller() -> None:
                    while not stop.is_set():
                        try:
                            host_sess.poll_event(1)
                        except RuntimeError:
                            pass
                        revoked_before = revoke_done.is_set()
                        allowed = host_sess.authorize("fs.read")
                        if revoked_before and allowed:
                            violations.append("authorize succeeded after revoke_peer returned")

                def session_churn() -> None:
                    for _ in range(40):
                        if stop.is_set():
                            return
                        try:
                            open_v2_session(host, cli, host_addr, "race-host", grant)
                        except RuntimeError:
                            pass

                def anchor_churn() -> None:
                    try:
                        for idx, anchor_ep in enumerate(anchor_eps):
                            host.add_trust_anchor(f"race-anchor-{idx}", signing_pub_of(anchor_ep))
                            host.revoke_trust_anchor(f"race-anchor-{idx}")
                    except Exception as exc:  # noqa: BLE001
                        errors.append(repr(exc))

                def revoker() -> None:
                    time.sleep(0.15)
                    try:
                        host.revoke_peer(dev_id)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(repr(exc))
                    revoke_done.set()

                pollers = [threading.Thread(target=poller) for _ in range(3)]
                workers = [
                    threading.Thread(target=session_churn),
                    threading.Thread(target=anchor_churn),
                    threading.Thread(target=revoker),
                ]
                for t in pollers + workers:
                    t.start()
                for t in workers:
                    t.join(timeout=60)
                time.sleep(0.2)
                stop.set()
                for t in pollers:
                    t.join(timeout=10)

                self.assertEqual(errors, [])
                self.assertEqual(violations, [])
                self.assertTrue(revoke_done.is_set())
                self.assertFalse(host_sess.authorize("fs.read"))
                with self.assertRaises(RuntimeError):
                    host.mint_grant(dev_id, ["fs.read"], 60)

                disk = read_roster(host_dir)
                self.assertEqual(disk["entries"][dev_id]["state"], "revoked")
                for idx in range(len(anchor_eps)):
                    self.assertEqual(
                        disk["trust_anchors"][f"race-anchor-{idx}"]["state"], "revoked"
                    )

                reopened = tendril.Endpoint(host_dir, None)
                try:
                    with self.assertRaises(RuntimeError):
                        reopened.mint_grant(dev_id, ["fs.read"], 60)
                finally:
                    reopened.close()
            finally:
                host.close()
                cli.close()
                for ep in anchor_eps:
                    ep.close()

    def test_external_revocation_reaches_memory_on_connect_and_accept_v2(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "sync-host")
            cli = tendril.Endpoint(cli_dir, "sync-cli")
            try:
                host_addr = host.serve_direct("127.0.0.1:0")
                dev_id = pair_v2(host, cli, host_addr, "sync-host")
                grant = host.mint_grant(dev_id, ["fs.read"], 3600)
                host_sess, cli_sess = open_v2_session(host, cli, host_addr, "sync-host", grant)
                self.assertTrue(host_sess.authorize("fs.read"))
                self.assertTrue(cli_sess.authorize("fs.read"))

                external = tendril.Endpoint(host_dir, None)
                try:
                    external.revoke_peer(dev_id)
                finally:
                    external.close()
                self.assertTrue(host_sess.authorize("fs.read"))
                with self.assertRaises(RuntimeError):
                    open_v2_session(host, cli, host_addr, "sync-host", grant)
                self.assertFalse(host_sess.authorize("fs.read"))

                external_cli = tendril.Endpoint(cli_dir, None)
                try:
                    external_cli.revoke_peer("sync-host")
                finally:
                    external_cli.close()
                self.assertTrue(cli_sess.authorize("fs.read"))
                with self.assertRaises(RuntimeError):
                    cli.connect_v2(host_addr, "sync-host", grant)
                self.assertFalse(cli_sess.authorize("fs.read"))
            finally:
                host.close()
                cli.close()

    def test_v1_connect_refuses_v2_pinned_peer_before_dialing(self) -> None:
        with tempfile.TemporaryDirectory() as cli_dir:
            for cli_state in (cli_dir, None):
                host = tendril.Endpoint(None, "floor-host")
                cli = tendril.Endpoint(cli_state, "floor-cli")
                mock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                mock.bind(("127.0.0.1", 0))
                mock.listen(8)
                mock.settimeout(0.5)
                try:
                    host_addr = host.serve_direct("127.0.0.1:0")
                    pair_v2(host, cli, host_addr, "floor-host")
                    mock_addr = f"127.0.0.1:{mock.getsockname()[1]}"
                    with self.assertRaises(RuntimeError) as ctx:
                        cli.connect(mock_addr, "floor-host", None)
                    self.assertIn("downgrade", str(ctx.exception).lower())
                    with self.assertRaises(socket.timeout):
                        mock.accept()
                finally:
                    mock.close()
                    host.close()
                    cli.close()

    def test_custom_relay_uri_refuses_bearer_auth_before_network(self) -> None:
        host = tendril.Endpoint(None, "relay-host")
        cli = tendril.Endpoint(None, "relay-cli")
        try:
            p2p_addr = host.serve_p2p("disabled")
            endpoint_id = p2p_addr.split("://", 1)[1].split("?", 1)[0]
            uri = f"iroh://{endpoint_id}?relay=http://127.0.0.1:9/"
            cli.configure_transports_json(
                json.dumps(
                    {
                        "p2p_allow_private_addrs": True,
                        "p2p_relay_auth_token": "secret-bearer-token",
                    }
                )
            )
            with self.assertRaises(RuntimeError) as ctx:
                cli.connect_v2(uri, "relay-host", None)
            self.assertIn("peer URI", str(ctx.exception))
            self.assertNotIn("secret-bearer-token", str(ctx.exception))
        finally:
            host.close()
            cli.close()

    def test_v1_host_rotation_persists_across_reconnects(self) -> None:
        ensure_tendril_bin()
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            run_cli(host_dir, "init", "--host-id", "rot-host")
            cli = tendril.Endpoint(cli_dir, "rot-cli")
            cli_id = json.loads(cli.info_json())["device_id"]
            proc1 = None
            proc2 = None
            proc3 = None
            try:
                proc1, ev1 = start_cli_serve(host_dir, issue_code=True)
                pair = json.loads(
                    cli.pair_initiate(ev1["direct_endpoint"], ev1["pairing_code"])
                )
                cli.confirm_peer("rot-host", pair["sas"])
                stop_proc(proc1)
                proc1 = None

                run_cli(host_dir, "confirm", cli_id, "--sas", pair["sas"])

                rot1 = run_cli(host_dir, "rotate")
                self.assertEqual(rot1["rotation_seq"], 1)
                grant1 = json.dumps(run_cli(host_dir, "mint", cli_id, "--cap", "fs.read"))
                proc2, ev2 = start_cli_serve(host_dir)
                sess1 = cli.connect(ev2["direct_endpoint"], "rot-host", grant1)
                sess1.send_data(b"rot1")
                sess1.close()
                stop_proc(proc2)
                proc2 = None

                disk1 = read_roster(cli_dir)
                self.assertEqual(disk1["entries"]["rot-host"]["rotation_seq"], 1)
                self.assertEqual(
                    bytes(disk1["entries"]["rot-host"]["static_pub"]),
                    b64url_decode(rot1["static_pub"]),
                )

                rot2 = run_cli(host_dir, "rotate")
                self.assertEqual(rot2["rotation_seq"], 2)
                grant2 = json.dumps(run_cli(host_dir, "mint", cli_id, "--cap", "fs.read"))
                proc3, ev3 = start_cli_serve(host_dir)
                sess2 = cli.connect(ev3["direct_endpoint"], "rot-host", grant2)
                sess2.send_data(b"rot2")
                sess2.close()

                disk2 = read_roster(cli_dir)
                self.assertEqual(disk2["entries"]["rot-host"]["rotation_seq"], 2)
                self.assertEqual(
                    bytes(disk2["entries"]["rot-host"]["static_pub"]),
                    b64url_decode(rot2["static_pub"]),
                )

                reopened = tendril.Endpoint(cli_dir, None)
                try:
                    sess3 = reopened.connect(ev3["direct_endpoint"], "rot-host", grant2)
                    sess3.send_data(b"rot3")
                    sess3.close()
                finally:
                    reopened.close()
            finally:
                for proc in (proc1, proc2, proc3):
                    if proc is not None:
                        stop_proc(proc)
                cli.close()


if __name__ == "__main__":
    unittest.main()
