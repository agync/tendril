---
type: Log Entry
title: "Add in-band WebRTC direct path upgrade"
description: "Add negotiated upgrade capability, encrypted PATH_UPGRADE signaling, and in-band WebRTC DataChannel direct path cutover."
tags: [log, update]
kind: Update
status: stable
---

# Add in-band WebRTC direct path upgrade

Added negotiated in-band path upgrade (`"webrtc/v1"`) so connected sessions can promote from a relay link to a direct `RTCDataChannel("tendril/v1")` (`ProviderId::P2p`) with a fresh `Noise_XXhfs` handshake and atomic session cutover:

- **Core (`tendril-core`):** Added `upgrade` capability negotiation (`MAX_UPGRADE_CAPS = 4`, `MAX_UPGRADE_CAP_LEN = 32`) in `HostHello`/`SessionHello` (omitted when empty, forbidden in `Intent::Pair`, suppressed on Wire v2 when padding is disabled) and encrypted `0x0D PATH_UPGRADE` signaling (`Offer`, `Answer`, `Reject`, `MAX_PATH_UPGRADE_LEN = 16384`, 4-offer cap, `0x09 PADDED`-only on Wire v2).
- **Runtime (`tendril-runtime`):** Added opt-in `webrtc` feature (`str0m 0.26.0` + `str0m-rust-crypto 0.7.0`, excluded from `tendril-ffi`), `WebRtcUpgradeEndpoint`/`WebRtcUpgradeHandle`/`WebRtcUpgradeListener`/`WebRtcStream`, and v1/v2 driver auto-responder support.
- **CLI & Browser (`tendril-cli`, `tendril-wasm`, `@tendril-sdk/web`):** Added `--webrtc-upgrade` to `tendril serve`, `conformance_peer` WebRTC upgrade support, `WasmSessionClient`/`WasmV2SessionInitiator` upgrade methods, `WebRtcStream`, `TendrilWebSession.upgradeToWebRtc()` (`iceServers: []` default, `#epoch`-guarded atomic cutover, relay fallback), and live headless Chrome E2E verification.
