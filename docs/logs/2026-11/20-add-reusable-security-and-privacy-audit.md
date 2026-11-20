---
type: Log Entry
title: "Add reusable security and privacy audit skill"
description: "Add reusable security and privacy audit skill"
tags: [log, update]
kind: Update
status: stable
---

Added the standalone, tool-agnostic `.agents/skills/security-privacy-audit/` repository skill (two-wave fan-out across `core`, `runtime`, `bindings`, and `web-privacy` lanes, proof-backed triage, six-adversary privacy matrix, and `audit-worktrees.sh` CoW worktree helper) and linked it from [Contribution guide](../../contribution/guide.md).
