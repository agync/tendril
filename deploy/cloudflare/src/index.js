import { DurableObject } from "cloudflare:workers";

import wasmModule from "../pkg/tendril_wasm_bg.wasm";
import { TendrilRelayCore, createRelayHandler } from "./relay_core.js";
import { initWasm } from "./wasm.js";

/** Hibernatable singleton Durable Object coordinating `/v1/relay` and `/v2/relay` mailboxes. */
export class TendrilRelay extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    initWasm(wasmModule);
    this.core = new TendrilRelayCore(ctx, env);
  }

  fetch(request) {
    return this.core.fetch(request);
  }

  webSocketMessage(ws, message) {
    return this.core.webSocketMessage(ws, message);
  }

  webSocketClose(ws, code, reason, wasClean) {
    return this.core.webSocketClose(ws, code, reason, wasClean);
  }

  webSocketError(ws, error) {
    return this.core.webSocketError(ws, error);
  }

  alarm() {
    return this.core.alarm();
  }
}

const baseHandler = createRelayHandler();

export default {
  fetch(request, env, ctx) {
    initWasm(wasmModule);
    return baseHandler.fetch(request, env, ctx);
  },
};
