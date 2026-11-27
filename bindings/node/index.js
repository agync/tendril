"use strict";

const native = require("./index.node");

// A refused session fails with `code` `refused_revoked`, `refused_pending` or `refused` and the
// wire `closeCode`. An async N-API method can reject only with a napi status code, so the
// native layer prefixes the message with `[tendril:CODE:CLOSE] ` and this layer moves the two
// fields onto the error.
const REFUSAL_TAG = /^\[tendril:(refused(?:_revoked|_pending)?):(\d+)\] /;

function typed(err) {
  if (err instanceof Error && typeof err.message === "string") {
    const m = REFUSAL_TAG.exec(err.message);
    if (m) {
      err.message = err.message.slice(m[0].length);
      err.code = m[1];
      err.closeCode = Number(m[2]);
    }
  }
  return err;
}

function wrap(proto, names) {
  for (const name of names) {
    const original = proto[name];
    const wrapped = {
      async [name](...args) {
        try {
          return await original.apply(this, args);
        } catch (err) {
          throw typed(err);
        }
      },
    }[name];
    Object.defineProperty(proto, name, {
      value: wrapped,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  }
}

wrap(native.Endpoint.prototype, ["connect", "connectV2", "connectWithOptions"]);
wrap(native.Session.prototype, ["sendData", "pollEvent", "rekey", "close"]);

/** `true` for the error of a refused session: `code` is `refused_*` and `closeCode` is set. */
function isRefusedError(err) {
  return (
    err instanceof Error &&
    typeof err.code === "string" &&
    err.code.startsWith("refused") &&
    typeof err.closeCode === "number"
  );
}

module.exports = native;
module.exports.isRefusedError = isRefusedError;
