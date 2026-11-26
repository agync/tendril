---
type: Log Entry
title: "runtime: store-backed enrol persists only real changes"
description: "Enrolling through the C ABI, Python or Node writes roster.json before the dial only when a session holds CRLs or revocations the store lacks; otherwise no file is created and no mtime moves."
tags: [log, update]
kind: Update
status: stable
---

runtime: store-backed enrol persists only real changes:

- `StateStore::update_roster_if_changed` writes only when the transaction changed the roster (compared by serialized form), so an unchanged roster creates no `roster.json` and keeps the mtime of an existing one.
- The store-backed enrol in the C ABI, Python and Node persists the CRLs and revocations that live sessions hold in memory through it before the driver reads the on-disk roster. Python and Node session commits use the same path.
