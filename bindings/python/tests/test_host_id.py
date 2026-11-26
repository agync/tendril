import json
import os
import tempfile
import unittest

import tendril


class HostIdTest(unittest.TestCase):
    def test_an_invalid_host_id_cannot_be_configured(self) -> None:
        for bad in ("has#hash", "ctl\x07char", "x" * 257):
            with self.assertRaises(Exception, msg=repr(bad)):
                tendril.Endpoint(None, bad)
            with tempfile.TemporaryDirectory() as state:
                with self.assertRaises(Exception, msg=repr(bad)):
                    tendril.Endpoint(state, bad)
                self.assertFalse(os.path.exists(os.path.join(state, "identity.json")))

    def test_a_tampered_identity_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as state:
            tendril.Endpoint(state, "good-host").close()
            path = os.path.join(state, "identity.json")
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            doc["host_id"] = "has#hash"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            os.chmod(path, 0o600)
            with self.assertRaises(Exception):
                tendril.Endpoint(state, None)


if __name__ == "__main__":
    unittest.main()
