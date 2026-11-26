import base64
import json
import os
import socket
import tempfile
import time
import unittest

import tendril


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def closed_port_endpoint() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"direct:127.0.0.1:{port}"


class EnrolPersistenceTest(unittest.TestCase):
    def test_a_failed_enrol_with_nothing_new_leaves_roster_json_alone(self) -> None:
        with tempfile.TemporaryDirectory() as host_dir, tempfile.TemporaryDirectory() as cli_dir:
            host = tendril.Endpoint(host_dir, "enr-host")
            cli = tendril.Endpoint(cli_dir, "enr-cli")
            try:
                host_info = json.loads(host.info_json())
                cli_info = json.loads(cli.info_json())
                token = host.mint_enrollment_token(host_info["host_id"], cli_info["device_id"], 900)
                roster = os.path.join(cli_dir, "roster.json")

                def enrol() -> None:
                    with self.assertRaises(Exception):
                        cli.enroll_initiate(
                            closed_port_endpoint(),
                            host_info["host_id"],
                            b64u_dec(host_info["static_pub"]),
                            b64u_dec(host_info["signing_pub"]),
                            token,
                        )

                enrol()
                self.assertFalse(os.path.exists(roster), "an enrol with nothing to persist")

                with open(roster, "w", encoding="utf-8") as f:
                    f.write('{"entries":{},"crls":{}}')
                os.chmod(roster, 0o600)
                before = os.stat(roster).st_mtime_ns
                time.sleep(0.02)
                enrol()
                self.assertEqual(os.stat(roster).st_mtime_ns, before)
            finally:
                host.close()
                cli.close()


if __name__ == "__main__":
    unittest.main()
