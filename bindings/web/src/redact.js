/** Display redaction for route hints in error text. */

const HOST_PORT_HINT = /^(?:direct:|overlay:\/\/)(?:[A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\]):\d{1,5}$/;
const HINT_PREFIX = /^(?:p2p:|relay:|broker\+)/i;
const WS_URL = /^wss?:\/\//i;
const WT_URL = /^wt:\/\//i;
const IROH_ID = /^iroh:\/\/([0-9A-Fa-f]{64})(?:[?/]|$)/i;
const STANDARD_HOST = /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/;
// Core `contains_code`: `tnd-` in any case, or two consecutive four-character alphanumeric
// groups in a `-` joined run (`wss://abcd-efgh.x/`, `direct:abcd-efgh:9`).
const PAIRING_CODE = /tnd-|(?<![A-Za-z0-9])[A-Za-z0-9]{4}-[A-Za-z0-9]{4}(?![A-Za-z0-9])/i;
const NON_PRINTABLE_ASCII = /[^\x21-\x7e]/;

/**
 * A hint reduced to its prefix, scheme and host for error text: `direct:`/`overlay://`
 * `host:port`, `wt://host:port`, `ws(s)://host[:port]` (also under `relay:` or `broker+`) and
 * an `iroh://` 64-hex node id. Anything else, including every other scheme and any text holding
 * a pairing code, whitespace or non-ASCII characters, is `<redacted>`.
 */
export function redactHint(hint) {
  const text = String(hint);
  if (PAIRING_CODE.test(text) || NON_PRINTABLE_ASCII.test(text)) {
    return "<redacted>";
  }
  if (HOST_PORT_HINT.test(text)) {
    return text;
  }
  const prefix = (text.match(HINT_PREFIX)?.[0] ?? "").toLowerCase();
  const rest = text.slice(prefix.length);
  const iroh = rest.match(IROH_ID);
  if (iroh && prefix !== "broker+" && prefix !== "relay:") {
    return `${prefix}iroh://${iroh[1].toLowerCase()}`;
  }
  if (prefix === "" && WT_URL.test(rest) && !rest.includes("\\")) {
    try {
      const url = new URL(`https://${rest.slice(5)}`);
      if (
        !url.username &&
        !url.password &&
        !url.pathname.includes("@") &&
        !url.search.includes("@") &&
        !url.hash.includes("@") &&
        STANDARD_HOST.test(url.host)
      ) {
        const rawAuth = rest.slice(5).split(/[/?#]/)[0];
        const explicit443 = url.port === "" && rawAuth.endsWith(":443");
        const hostPort = explicit443 ? `${url.host}:443` : url.host;
        return `wt://${hostPort}`;
      }
    } catch {}
  }
  if (WS_URL.test(rest) && prefix !== "p2p:") {
    try {
      const url = new URL(rest);
      if (!url.username && !url.password && STANDARD_HOST.test(url.host)) {
        return `${prefix}${url.protocol}//${url.host}`;
      }
    } catch {}
  }
  return "<redacted>";
}
