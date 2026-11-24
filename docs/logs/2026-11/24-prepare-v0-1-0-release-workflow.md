---
type: Log Entry
title: "Prepare v0.1.0 release workflow, package metadata, and install docs"
description: "Fix npm OIDC publishing, order SLSA provenance before Cosign, add Node release tarballs, and align package READMEs and v0.1.0 install docs."
tags: [log, update]
kind: Update
status: stable
---

Prepare v0.1.0 release workflow, package metadata, and install docs:

- Updated `.github/workflows/release.yml` to drop `registry-url` from `publish-npm` (unblocking npm OIDC Trusted Publishing), generate SLSA build provenance before Cosign blob signing, log `cosign version`, and build signed `tendril-node` release tarballs.
- Updated root `README.md`, added package READMEs for `tendril-sdk`, `@tendril-sdk/web`, and `@tendril-sdk/node`, and excluded `demo/` from the `@tendril-sdk/web` npm tarball.
- Aligned `site/index.html`, `docs/contribution/website.md`, `docs/contribution/release.md`, and `docs/reference/ffi-and-bindings.md` with the `v0.1.0` artifact layout, OIDC bootstrap rules, Go archive linking, and Cosign/attestation verification steps.
