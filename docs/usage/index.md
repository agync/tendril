# Usage

Guides for operating Tendril endpoints, deploying a stateless relay, and driving conformance tests:

- [Reference CLI, relay deployment, and conformance peer](cli-demo.md) - Walkthrough of `tendril` pair/confirm/mint/dial/revoke workflows, running `tendril-relay`, and using `tendril-conformance-peer` over JSON stdio.
- [Layering CRDT, sync, and group engines](layering-sync-engines.md) - Run transport-agnostic sync and group-encryption libraries such as p2panda, Automerge, or Yjs over Tendril sessions without duplicating network stacks or exceeding frame ceilings.
