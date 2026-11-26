"""Replays spec/vectors/routes.json through the Python binding."""

import base64
import json
import pathlib
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

import tendril

ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "spec" / "vectors" / "routes.json").read_text(encoding="utf-8"))

COVERED_SECTIONS = {"pairing_route_statement", "pairing_route_check", "route_set"}
SKIPPED_SECTIONS = {
    "session_hello_route_seq": (
        "SessionHello is built inside the core handshake; no binding exposes the wire JSON."
    ),
}
# Cases whose URI names a host key the pinned vector host does not hold, so the offline apply
# path can only report that no paired host matches.
# - route_key_rotated, route_key_rotated_stale_rs: the URI carries the pre-rotation key. Pinning
#   it and following the rotation needs a RotationRecord, which no binding API or vector exposes.
# - unchained_key: a pin_ok=false / host_key_unverified handshake outcome (responder
#   "unrelated_key"); the apply path sees only a host that is not paired.
NO_HOST_MATCH_CASES = {"route_key_rotated", "route_key_rotated_stale_rs", "unchained_key"}
# Case fields the offline apply path does not model. A new field must fail the field test until
# it is covered or listed here with a reason.
COVERED_CASE_FIELDS = {"name", "uri", "route_check"}
HANDSHAKE_ONLY_FIELDS = {
    "pin_ok": "outcome of the host key pin check in the pairing handshake",
    "commit_error": "error raised when the handshake commits the pairing",
    "relay_pub_ok": "rp relay key check, made by the pairing initiator against the dialed relay",
    "operator_relay_key_hex": "operator relay key given to the pairing initiator",
    "responder": "which identity answers the handshake in the replay",
    "wires": "wire versions the handshake replay runs on",
    "presented_static_pub_hex": "key material the responder presents in the handshake",
    "presented_ed25519_pub_hex": "key material the responder presents in the handshake",
    "presented_signing_pub_sha256_hex": "key material the responder presents in the handshake",
    "presented_rotation_seq": "rotation chain length the responder presents in the handshake",
}

SIGNING_PUB = bytes.fromhex(VECTORS["route_set"]["signing_pub_hex"])


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_cases() -> list[dict]:
    return VECTORS["route_set"]["sign_deterministic"]


def payload_of(case: dict) -> bytes:
    return bytes.fromhex(case["body_hex"] + case["sig_hex"])


class SectionCoverageTest(unittest.TestCase):
    def test_every_section_is_covered_or_explicitly_skipped(self) -> None:
        self.assertEqual(set(VECTORS), COVERED_SECTIONS | set(SKIPPED_SECTIONS))
        self.assertTrue(all(SKIPPED_SECTIONS.values()))

    def test_every_check_case_is_accounted_for(self) -> None:
        names = {c["name"] for c in VECTORS["pairing_route_check"]["cases"]}
        self.assertTrue(NO_HOST_MATCH_CASES <= names)

    def test_every_check_case_field_is_covered_or_handshake_only(self) -> None:
        self.assertTrue(all(HANDSHAKE_ONLY_FIELDS.values()))
        known = COVERED_CASE_FIELDS | set(HANDSHAKE_ONLY_FIELDS)
        for case in VECTORS["pairing_route_check"]["cases"]:
            self.assertLessEqual(set(case), known, case["name"])


class VerifyRouteSetTest(unittest.TestCase):
    def test_sign_deterministic_vectors_verify_and_decode(self) -> None:
        self.assertTrue(sign_cases())
        for case in sign_cases():
            with self.subTest(case["name"]):
                got = json.loads(tendril.verify_route_set(payload_of(case), SIGNING_PUB))
                self.assertEqual(
                    got,
                    {
                        "seq": case["seq"],
                        "issued_at": case["issued_at"],
                        "routes": case["routes"],
                    },
                )

    def test_flipped_signature_byte_fails_the_signature_check(self) -> None:
        for case in sign_cases():
            sig_len = len(case["sig_hex"]) // 2
            for offset in (0, 31, 32, sig_len - 1):
                with self.subTest(f"{case['name']}[{offset}]"):
                    payload = bytearray(payload_of(case))
                    payload[len(payload) - sig_len + offset] ^= 0x01
                    with self.assertRaisesRegex(ValueError, "signature"):
                        tendril.verify_route_set(bytes(payload), SIGNING_PUB)

    def test_flipped_body_byte_fails_the_signature_check(self) -> None:
        case = sign_cases()[0]
        payload = bytearray(payload_of(case))
        payload[40] ^= 0x01
        with self.assertRaisesRegex(ValueError, "signature"):
            tendril.verify_route_set(bytes(payload), SIGNING_PUB)

    def test_wrong_signing_key_fails_the_signature_check(self) -> None:
        other = bytearray(SIGNING_PUB)
        other[40] ^= 0x01
        case = sign_cases()[0]
        with self.assertRaisesRegex(ValueError, "signature"):
            tendril.verify_route_set(payload_of(case), bytes(other))
        with self.assertRaisesRegex(ValueError, "signing key"):
            tendril.verify_route_set(payload_of(case), SIGNING_PUB[:-1])

    def test_appended_byte_fails_the_decode_check(self) -> None:
        for case in sign_cases():
            with self.subTest(case["name"]):
                with self.assertRaisesRegex(ValueError, "decode"):
                    tendril.verify_route_set(payload_of(case) + b"\x00", SIGNING_PUB)

    def test_decode_rejections_fail_the_decode_check(self) -> None:
        rejections = VECTORS["route_set"]["decode_rejections"]
        self.assertTrue(rejections)
        for case in rejections:
            with self.subTest(case["name"]):
                payload = bytes.fromhex(case["body_hex"]) + bytes(case["zero_filler_len"])
                with self.assertRaisesRegex(ValueError, "decode"):
                    tendril.verify_route_set(payload, SIGNING_PUB)


class ApplyRouteUriTest(unittest.TestCase):
    def setUp(self) -> None:
        self.new_client()

    def new_client(self) -> None:
        """A fresh client pinned to the vector host: every URI carries the same `rq`."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        keys = VECTORS["route_set"]
        static_pub = bytes.fromhex(keys["static_pub_hex"])
        self.assertEqual(
            b64url(bytes.fromhex(keys["sh_hex"])),
            parse_qs(urlsplit(VECTORS["pairing_route_statement"]["uri"]).query)["sh"][0],
        )
        self.host_id = tendril.device_id(static_pub)
        # This writes roster.json by hand, coupling the test to the internal roster schema: no
        # public API pins a host from raw key material (pairing needs a live handshake).
        roster = {
            "entries": {
                self.host_id: {
                    "device_id": self.host_id,
                    "name": "vector-host",
                    "kind": "host",
                    "static_pub": list(static_pub),
                    "signing_pub": b64url(SIGNING_PUB),
                    "rotation_seq": 0,
                    "state": "active",
                    "min_wire_version": 1,
                }
            },
            "crls": {},
        }
        roster_path = pathlib.Path(tmp.name, "roster.json")
        roster_path.write_text(json.dumps(roster), encoding="utf-8")
        roster_path.chmod(0o600)
        self.client = tendril.Endpoint(tmp.name, "py-routes-vectors")
        self.addCleanup(self.client.close)

    def apply(self, uri: str) -> dict:
        return json.loads(self.client.apply_route_uri(uri))

    def signed_routes(self) -> list[str]:
        routes = json.loads(self.client.peer_routes(self.host_id))["routes"]
        return [r["hint"] for r in routes if r["source"] == "signed"]

    def test_pairing_route_statement_applies_its_hints(self) -> None:
        stmt = VECTORS["pairing_route_statement"]
        applied = self.apply(stmt["uri"])
        self.assertEqual(
            applied,
            {
                "peer_id": self.host_id,
                "applied": True,
                "reason": None,
                "route_seq": stmt["route_seq"],
            },
        )
        self.assertEqual(self.signed_routes(), stmt["hints"])

    def test_pairing_route_statement_with_tampered_rq_is_rejected(self) -> None:
        uri = VECTORS["pairing_route_statement"]["uri"]
        tampered = uri.replace("&rq=7", "&rq=8")
        self.assertNotEqual(uri, tampered)
        with self.assertRaisesRegex((ValueError, RuntimeError), "does not verify"):
            self.client.apply_route_uri(tampered)
        self.assertEqual(self.signed_routes(), [])

    def test_pairing_route_check_outcomes(self) -> None:
        # Asserts the route_check outcome only; handshake-only fields are not exercised here.
        keys = VECTORS["route_set"]
        host_k = b64url(bytes.fromhex(keys["static_pub_hex"]))
        for case in VECTORS["pairing_route_check"]["cases"]:
            name = case["name"]
            with self.subTest(name):
                self.new_client()
                uri_k = parse_qs(urlsplit(case["uri"]).query)["k"][0]
                if name in NO_HOST_MATCH_CASES:
                    self.assertNotEqual(uri_k, host_k)
                    with self.assertRaisesRegex(
                        (ValueError, RuntimeError), "no paired host matches"
                    ):
                        self.client.apply_route_uri(case["uri"])
                    continue
                self.assertEqual(uri_k, host_k)
                if case["route_check"] == "verified":
                    self.assertTrue(self.apply(case["uri"])["applied"])
                    self.assertTrue(self.signed_routes())
                elif case["route_check"] == "unsigned":
                    with self.assertRaisesRegex((ValueError, RuntimeError), "not host-signed"):
                        self.client.apply_route_uri(case["uri"])
                else:
                    self.assertEqual(case["route_check"], "invalid")
                    with self.assertRaisesRegex((ValueError, RuntimeError), "does not verify"):
                        self.client.apply_route_uri(case["uri"])


if __name__ == "__main__":
    unittest.main()
