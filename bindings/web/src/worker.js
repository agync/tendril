import init, { compute_code_mac } from "../pkg/tendril_wasm.js";

let readyPromise = null;

function ensureReady() {
  if (!readyPromise) {
    readyPromise = init();
  }
  return readyPromise;
}

self.addEventListener("message", async (ev) => {
  const { id, op, code, handshakeHash } = ev.data || {};
  try {
    await ensureReady();
    if (op === "compute_code_mac") {
      const mac = compute_code_mac(code, handshakeHash);
      self.postMessage({ id, ok: true, mac }, [mac.buffer]);
      return;
    }
    self.postMessage({ id, ok: false, error: `unsupported worker op: ${op}` });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err) });
  }
});
