---
type: Log Entry
title: "Add a Windows named-pipe local provider"
description: "Add a Windows named-pipe local provider"
tags: [log, update]
kind: Update
status: stable
---

Add a Windows named-pipe local provider

The `local` provider now has a named-pipe backend on Windows. The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and an owner-only DACL, remote clients are rejected, and the next instance is created after each accept with a short busy retry on the client. Because the pipe namespace is machine-global, a dial also verifies that the server process runs as the current user. `dial_endpoint` and operator-endpoint normalization recognize `local:` and `\\.\pipe\` paths. The `tendril-runtime` suite now runs on `windows-2022`: the Unix-only permission assertions are gated and the session, provider contract, announce and hardening suites run against the Windows backend.

Updated [Relay and runtime](../../design/relay-and-runtime.md) and [Providers and the relay ladder](../../design/providers-and-relay-ladder.md).
