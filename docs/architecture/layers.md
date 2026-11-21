---
type: Architecture
title: Layers and boundaries
description: The trust boundary between host applications, thin bindings, the Rust core, and untrusted path providers.
status: draft
tags: [architecture, security]
---

# Layers and boundaries

Tendril isolates security-critical logic inside one Rust core. Host applications provide storage and UI, language bindings translate types, and path providers move opaque bytes.

```mermaid
flowchart TB
  APP["App: keystore, roster store, pairing UI"]
  BIND["Thin bindings: Rust, Go, Python, TypeScript, Swift, Kotlin, WASM"]
  subgraph CORE["Tendril core (sole trust boundary)"]
    ID["identity"]
    RO["roster"]
    PR["pairing"]
    SE["session"]
    GR["grants"]
    PO["path policy"]
  end
  subgraph PROV["Untrusted path providers"]
    L["local"]
    D["direct"]
    O["overlay"]
    P["p2p"]
    R["relay"]
    B["broker"]
  end
  APP --> BIND --> CORE
  CORE --> L & D & O & P & R & B
```

## Module responsibilities

| Module | Owns | Never owns |
|---|---|---|
| `identity` | Static and signing keypairs, device IDs, fingerprints, signed rotations | Platform keystore I/O, user accounts |
| `roster` | Known peers, device status (`pending`, `active`, `revoked`), grants, rotation chain | Network discovery, live presence inference |
| `pairing` | Pairing code proof, handshake binding, confirmation state, minting split | Socket dialing, UI rendering |
| `session` | Noise XXhfs handshake, length-prefixed framing, rekeying, close on fault | Path ranking, retries |
| `grants` | Capability grammar, signature verification, subset delegation, revocation lists | App authorization prompts |
| `path policy` | Provider registry, locality ranking, probing, fall-up triggers, rebuild on failure | Provider transport internals |

## Provider boundary

Providers carry sealed frames only. A provider may drop, delay, reorder, duplicate, or inject bytes, and it may misreport liveness. On any path failure, the core closes the bound session and rebuilds a fresh session on the next eligible provider rather than reusing a broken path.
