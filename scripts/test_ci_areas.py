#!/usr/bin/env python3
"""Unit tests for scripts/ci-areas.sh and scripts/build-xcframework.sh."""

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
SCRIPT = SCRIPTS_DIR / "ci-areas.sh"
BUILD_XCFRAMEWORK = SCRIPTS_DIR / "build-xcframework.sh"


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

    def test_apple_manifest_and_xcframework_script_areas(self):
        for changed in (["Package.swift"], ["bindings/swift/Package.swift"]):
            areas = classify(changed)
            self.assertTrue(areas["apple"], changed)
            for other in areas:
                if other != "apple":
                    self.assertFalse(areas[other], f"{changed}: {other}")

        areas = classify(["scripts/build-xcframework.sh"])
        self.assertTrue(areas["apple"])
        self.assertTrue(areas["scripts"])
        for other in areas:
            if other not in ("apple", "scripts"):
                self.assertFalse(areas[other], other)

        nested_areas = classify(["examples/Package.swift"])
        self.assertFalse(nested_areas["apple"])


class BuildXcframeworkTests(unittest.TestCase):
    def _populate_fixture(
        self,
        fw_dir: Path,
        mtime_sec: int,
        regular_mode: int,
        exec_mode: int,
        dir_mode: int,
        reverse_order: bool = False,
    ) -> None:
        subdirs = [
            fw_dir / "ios-arm64" / "Headers",
            fw_dir / "ios-arm64" / "bin",
            fw_dir / "macos-arm64" / "Versions" / "A",
        ]
        if reverse_order:
            subdirs = list(reversed(subdirs))
        for d in subdirs:
            d.mkdir(parents=True, exist_ok=True)

        files = [
            (fw_dir / "Info.plist", b"<plist><dict/></plist>\n", regular_mode),
            (fw_dir / "ios-arm64" / "Headers" / "tendril.h", b"#define TENDRIL_H 1\n", regular_mode),
            (
                fw_dir / "ios-arm64" / "Headers" / "module.modulemap",
                b'module CTendril [system] {\n  header "tendril.h"\n  export *\n}\n',
                regular_mode,
            ),
            (fw_dir / "ios-arm64" / "libtendril_ffi.a", b"!<arch>\n" + b"payload" * 128, regular_mode),
            (fw_dir / "ios-arm64" / "bin" / "helper", b"#!/bin/sh\nexit 0\n", exec_mode),
            (fw_dir / "macos-arm64" / "Versions" / "A" / "libtendril_ffi.a", b"!<arch>\n" + b"mac" * 64, regular_mode),
        ]
        if reverse_order:
            files = list(reversed(files))
        for path, content, mode in files:
            path.write_bytes(content)
            os.chmod(path, mode)
            os.utime(path, (mtime_sec, mtime_sec))

        symlink_path = fw_dir / "macos-arm64" / "Versions" / "Current"
        os.symlink("A", symlink_path)

        # Apply directory modes and timestamps bottom-up after creating children.
        dirs = sorted(
            [fw_dir, *[p for p in fw_dir.rglob("*") if p.is_dir() and not p.is_symlink()]],
            key=lambda p: len(p.parts),
            reverse=True,
        )
        for d in dirs:
            os.chmod(d, dir_mode)
            os.utime(d, (mtime_sec, mtime_sec))

    def test_pack_only_is_deterministic_across_mtimes_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            fw_a = Path(tmp_a) / "TendrilFFI.xcframework"
            fw_b = Path(tmp_b) / "TendrilFFI.xcframework"
            zip_a = Path(tmp_a) / "out" / "TendrilFFI-a.zip"
            zip_b = Path(tmp_b) / "out" / "TendrilFFI-b.zip"

            self._populate_fixture(fw_a, 1600000000, 0o644, 0o755, 0o755, reverse_order=False)
            self._populate_fixture(fw_b, 1800000000, 0o600, 0o711, 0o700, reverse_order=True)

            res_a = subprocess.run(
                [str(BUILD_XCFRAMEWORK), "--pack-only", str(fw_a), str(zip_a)],
                text=True,
                capture_output=True,
                check=True,
            )
            res_b = subprocess.run(
                [str(BUILD_XCFRAMEWORK), "--pack-only", str(fw_b), str(zip_b)],
                text=True,
                capture_output=True,
                check=True,
            )

            sha_a = res_a.stdout.strip()
            sha_b = res_b.stdout.strip()
            self.assertRegex(sha_a, r"^[0-9a-f]{64}$")
            self.assertEqual(sha_a, sha_b)
            self.assertEqual(stat.S_IMODE(zip_a.stat().st_mode), 0o644)

            bytes_a = zip_a.read_bytes()
            bytes_b = zip_b.read_bytes()
            self.assertEqual(bytes_a, bytes_b)
            self.assertEqual(hashlib.sha256(bytes_a).hexdigest(), sha_a)

            with zipfile.ZipFile(zip_a, "r") as zf:
                infos = zf.infolist()
                names = [i.filename for i in infos]
                self.assertEqual(names, sorted(names))
                for info in infos:
                    self.assertEqual(info.date_time, (2020, 1, 1, 0, 0, 0), info.filename)
                    self.assertEqual(info.flag_bits & 0x800, 0, info.filename)
                    mode = info.external_attr >> 16
                    if info.is_dir():
                        self.assertEqual(stat.S_IFMT(mode), stat.S_IFDIR)
                        self.assertEqual(stat.S_IMODE(mode), 0o755)
                    elif info.filename.endswith("/Current"):
                        self.assertEqual(stat.S_IFMT(mode), stat.S_IFLNK)
                        self.assertEqual(zf.read(info), b"A")
                    elif info.filename.endswith("/helper"):
                        self.assertEqual(stat.S_IFMT(mode), stat.S_IFREG)
                        self.assertEqual(stat.S_IMODE(mode), 0o755)
                        self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)
                    else:
                        self.assertEqual(stat.S_IFMT(mode), stat.S_IFREG)
                        self.assertEqual(stat.S_IMODE(mode), 0o644)
                        self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)

    def test_pack_only_rejects_missing_dir_invalid_bundle_or_bad_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            unused_zip = Path(tmp) / "unused.zip"
            bad_bundle = Path(tmp) / "not-a-framework"
            bad_bundle.mkdir()
            dot_bundle = Path(tmp) / ".xcframework"
            dot_bundle.mkdir()

            for invalid_dir in (
                "/",
                "///",
                str(Path(tmp) / "missing.xcframework"),
                str(bad_bundle),
                str(dot_bundle),
            ):
                proc = subprocess.run(
                    [str(BUILD_XCFRAMEWORK), "--pack-only", invalid_dir, str(unused_zip)],
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(proc.returncode, 0, invalid_dir)
                self.assertFalse(unused_zip.exists(), invalid_dir)

            bad_args = subprocess.run(
                [str(BUILD_XCFRAMEWORK), "--pack-only", str(unused_zip)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(bad_args.returncode, 2)


if __name__ == "__main__":
    unittest.main()
