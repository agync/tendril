# Usage

Guides for pairing and reconnecting with default routes, operating Tendril endpoints, deploying a stateless relay, and driving conformance tests:

- [Reference CLI, relay deployment, and conformance peer](cli-demo.md) - Walkthrough of `tendril` pair/confirm/mint/dial/revoke and `route` workflows, running `tendril-relay`, and using `tendril-conformance-peer` over JSON stdio.
- [Private relay hosting and deployment](relay-hosting.md) - Single-entry guide for developers and app end users covering one-click Cloudflare Workers, PaaS containers, Oracle Cloud Always Free, and home tunnels.
- [Seamless pairing defaults](seamless-pairing.md) - One signed QR code, automatic LAN, overlay and relay fallback, route policies, signed route updates, relay credential origins, endpoint-free connect, and recovery by a fresh QR.
- [Layering CRDT, sync, and group engines](layering-sync-engines.md) - Run transport-agnostic sync and group-encryption libraries such as p2panda, Automerge, or Yjs over Tendril sessions without duplicating network stacks or exceeding frame ceilings.
