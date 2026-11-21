import init, { compute_code_mac, compute_code_mac_bytes } from "../pkg/tendril_wasm.js";

let readyPromise = null;

function ensureReady() {
  if (!readyPromise) {
    readyPromise = init();
  }
  return readyPromise;
}

self.addEventListener("message", async (ev) => {
  const { id, op, code, codeBytes, handshakeHash } = ev.data || {};
  try {
    await ensureReady();
    if (op === "compute_code_mac") {
      let mac;
      if (codeBytes instanceof Uint8Array) {
        try {
          mac = compute_code_mac_bytes(codeBytes, handshakeHash);
        } finally {
          codeBytes.fill(0);
        }
      } else {
        mac = compute_code_mac(code, handshakeHash);
      }
      self.postMessage({ id, ok: true, mac }, [mac.buffer]);
      return;
    }
    self.postMessage({ id, ok: false, error: `unsupported worker op: ${op}` });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err) });
  }
});
