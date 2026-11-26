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


if __name__ == "__main__":
    unittest.main()
