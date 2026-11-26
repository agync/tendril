---
type: Log Entry
title: "apple: add remote SwiftPM Package.swift and release automation"
description: "apple: add remote SwiftPM Package.swift and release automation"
tags: [log, update]
kind: Update
status: stable
---

apple: add remote SwiftPM Package.swift and release automation

Add root `Package.swift` exposing `.binaryTarget` for `TendrilFFI.xcframework` by default with zero `.unsafeFlags` and switching `CTendril` to local linking when `TENDRIL_LOCAL_FFI=1`, alongside `scripts/build-xcframework.sh` (deterministic XCFramework builder and `--pack-only` zip packer) and `scripts/ci-areas.sh` / `scripts/test_ci_areas.py` coverage. Wire `bindings-apple` remote and local checks into `.github/workflows/ci.yml`, add `apple-release-pr` and `commit-apple-manifest` checksum automation in `.github/workflows/release-please.yml`, and verify the rebuilt archive checksum against `Package.swift` in `.github/workflows/release.yml`. Updated [CI, releases, and registry publishing](../../contribution/release.md) and [Web and mobile bindings](../../reference/web-and-mobile.md).
