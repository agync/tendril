# @tendril-sdk/node

Node.js N-API v8 native addon over `tendril-core` and `tendril-runtime` for private, end-to-end encrypted device-to-device links.

## Installation

Prebuilt release tarballs for `linux-x86_64`, `linux-arm64`, and `darwin-arm64` are attached to [GitHub Releases](https://github.com/agync/tendril/releases).

1. Download `tendril-node-0.1.0-<platform>.tar.gz` and `tendril-node-0.1.0-<platform>.tar.gz.sigstore.json`.
2. Verify the Cosign bundle:

```bash
cosign verify-blob \
  --bundle tendril-node-0.1.0-<platform>.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/agync/tendril/\.github/workflows/release\.yml@refs/tags/v0\.1\.0$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  tendril-node-0.1.0-<platform>.tar.gz
```

3. Install the verified tarball into your project:

```bash
npm install ./tendril-node-0.1.0-<platform>.tar.gz
```

To build from a source checkout instead, run `make bindings/node`.

## Example

```js
import tendril from "@tendril-sdk/node";

const host = new tendril.Endpoint("./laptop-state", "laptop");
const addr = await host.serveDirect("127.0.0.1:0");
const code = host.issueCode("lan");

const req = JSON.parse(await host.pairAccept(5000));
host.confirmPeer(req.device_id, req.sas); // after comparing the check string
const grant = host.mintGrant(req.device_id, ["notes.sync"], 3600);

const session = await host.acceptSession(5000);
await session.authorize("notes.sync"); // true
```

## P2P sockets

A P2P endpoint probes the local router for a port mapping and binds its QUIC UDP sockets on every interface. Turn the probe off or pin the bind addresses in the transport configuration:

```js
host.configureTransportsJson('{"p2p_port_mapping": false, "p2p_bind_addrs": ["0.0.0.0:0"]}');
```

The sockets a P2P endpoint opens, and which option controls each, are listed in [Sockets a P2P endpoint opens](https://github.com/agync/tendril/blob/main/docs/design/providers-and-relay-ladder.md#sockets-a-p2p-endpoint-opens).

## Links

- Documentation: https://tendril.agync.dev
- Repository: https://github.com/agync/tendril
- License: Apache-2.0
