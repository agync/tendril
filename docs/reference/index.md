# Reference

Specifications, conformance vector schemas, and language-binding reference surfaces.

- [Conformance vectors](conformance-vectors.md) - Canonical JSON test vectors and cross-language verification targets under spec/vectors/.
- [FFI ABI and cross-language bindings](ffi-and-bindings.md) - Callback-free C ABI surface, thin Go/Python/Node wrappers, `power_profile` / `wake_retry_max_delay_ms` / `idle_timeout_ms` / external monitor APIs, the per-language pairing URI and route surface, and Gate #7 baselines.
- [Web and mobile bindings](web-and-mobile.md) - Browser WASM SDK (`lowPower`, LKG affinity, `idleTimeoutMs`), demo application, Android Kotlin JNI wrapper (`TendrilEndpointOptions`, event-only `TendrilForegroundService`), Swift SPM package (`TendrilPowerProfile`, extension activity guards), browser pairing URI and route handling, and Gate #7/#8 measurements.
- [Pairing URI measurements](pairing-measurements.md) - Measured pairing URI sizes and QR versions for realistic route sets, plus a two host check of the route ladder and signed route updates.
