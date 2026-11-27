# @tendril-sdk/web

Browser WebAssembly client SDK over `tendril-wasm` for direct browser WebTransport (`wt://`), Tendril relays (`/v1/relay`, `/v2/relay`), reverse-proxied WebSocket brokers (`broker+ws(s)://`), and opt-in `iroh://` peer-to-peer relays (`pkg-p2p`) with Happy Eyeballs multi-route dialing, an IndexedDB WebCrypto vault (`openTendrilVault`), and Web Worker Argon2id offload.

## Installation

```bash
npm install @tendril-sdk/web
```

## Example

```js
import {
  TendrilWebClient,
  initTendrilP2p,
  openTendrilVault,
} from "@tendril-sdk/web";

const vault = openTendrilVault();
const existingIdentity = await vault.readBytes("identity");
const client = await TendrilWebClient.create({
  hostId: "browser-client",
  identityBytes: existingIdentity,
  rosterBytes: await vault.readBytes("roster"),
  onPersistRosterBytes: (bytes) => vault.writeBytes("roster", bytes),
});

if (!existingIdentity) {
  const exportedId = client.exportIdentityBytes();
  try {
    await vault.writeBytes("identity", exportedId);
  } finally {
    exportedId.fill(0);
  }
}

// Optional: preload the opt-in iroh WASM module up front
// (pair and connect otherwise load it lazily on demand for iroh:// URIs).
// await initTendrilP2p();

const paired = await client.pair({ pairingUri });
// Compare paired.sas out of band; the host then confirms the peer and mints a grant.
// Connect using stored routes with the host-minted grant JSON:
const session = await client.connect({
  targetHostId: paired.host_id,
  grantJson,
});
session.authorize("notes.sync"); // true when grantJson authorizes notes.sync
await session.sendData("hello-tendril");
```

## Refusals

A host that knows this device and refuses it says so. A refused Wire v2 `connectV2` rejects with a `TendrilAttemptError` whose `code` is `refused_revoked` (the host blocks this device key for good, so re-pairing needs a new device identity), `refused_pending` (the host has not confirmed this device yet, so retry with backoff) or `refused`. A Wire v1 `connect` resolves before the refusal arrives and never rejects with it: `session.pollEvent()` then returns a `closed` event whose `refusal` is `"revoked"`, `"pending"` or `"other"`. A host sends at most one notice per peer in a short window, so a rapid retry can fail with another code.

## Links

- Documentation: https://tendril.agync.dev
- Repository: https://github.com/agync/tendril
- License: Apache-2.0
