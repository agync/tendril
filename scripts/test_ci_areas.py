#!/usr/bin/env python3
"""Unit tests for scripts/ci-areas.sh."""

import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "ci-areas.sh"


def classify(paths, *args):
    proc = subprocess.run(
        ["bash", str(SCRIPT), *args],
        input="\n".join(paths) + ("\n" if paths else ""),
        text=True,
        capture_output=True,
        check=True,
    )
    out = {}
    for line in proc.stdout.strip().splitlines():
        key, value = line.split("=", 1)
        out[key] = value == "true"
    return out


class CiAreasTests(unittest.TestCase):
    def test_site_and_docs_only_change(self):
        for changed in (["docs/overview.md", "docs/index.md"], ["site/index.html"]):
            areas = classify(changed)
            self.assertTrue(areas["site"], changed)
            for other in areas:
                if other != "site":
                    self.assertFalse(areas[other], f"{changed}: {other}")

    def test_web_binding_only_change(self):
        areas = classify(["bindings/web/src/index.js"])
        self.assertTrue(areas["web"])
        for other in areas:
            if other != "web":
                self.assertFalse(areas[other], other)

    def test_cloudflare_deploy_triggers_web_area(self):
        areas = classify(["deploy/cloudflare/src/relay_core.js"])
        self.assertTrue(areas["web"])
        for other in areas:
            if other != "web":
                self.assertFalse(areas[other], other)

    def test_core_change_fans_out_to_runtime_bindings_and_container(self):
        areas = classify(["crates/tendril-core/src/lib.rs"])
        for expected in (
            "rust",
            "rust-platforms",
            "vectors-go",
            "python",
            "node",
            "web",
            "android",
            "apple",
            "container",
        ):
            self.assertTrue(areas[expected], expected)
        self.assertFalse(areas["site"])
        self.assertFalse(areas["scripts"])

    def test_workflow_or_makefile_runs_everything(self):
        for trigger in ("Makefile", ".github/workflows/ci.yml", "rust-toolchain.toml"):
            areas = classify([trigger])
            self.assertTrue(all(areas.values()), trigger)

    def test_local_flag_ignores_everything_pattern(self):
        areas = classify(["Makefile"], "--local")
        self.assertFalse(any(areas.values()))

    def test_all_flag_enables_all_areas(self):
        areas = classify([], "--all")
        self.assertTrue(all(areas.values()))


if __name__ == "__main__":
    unittest.main()
