import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { pipeline } from "node:stream";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(WEB_ROOT, "..", "..");

function parseArgs(argv) {
  const cfg = {
    listenHost: "127.0.0.1",
    listenPort: 8080,
    relayHost: null,
    relayPort: null,
    serveVectors: false,
    demoConfigFile: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--listen") {
      const val = argv[++i];
      const idx = val.lastIndexOf(":");
      cfg.listenHost = val.slice(0, idx);
      cfg.listenPort = Number(val.slice(idx + 1));
    } else if (arg === "--relay-upstream") {
      const val = argv[++i];
      const idx = val.lastIndexOf(":");
      cfg.relayHost = val.slice(0, idx);
      cfg.relayPort = Number(val.slice(idx + 1));
    } else if (arg === "--serve-vectors") {
      cfg.serveVectors = true;
    } else if (arg === "--demo-config") {
      cfg.demoConfigFile = path.resolve(argv[++i]);
    }
  }
  return cfg;
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};
const COMPRESSIBLE_EXTS = new Set([".wasm", ".js", ".mjs", ".html", ".css", ".json"]);
const DEMO_PUBLIC_FILES = new Set(["index.html", "app.js"]);
const ALLOWED_UPGRADE_HEADERS = new Set([
  "host",
  "upgrade",
  "connection",
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-protocol",
  "sec-websocket-extensions",
]);
const SINGLETON_UPGRADE_HEADERS = new Set([
  "host",
  "upgrade",
  "connection",
  "sec-websocket-key",
  "sec-websocket-version",
]);
const UPGRADE_CONNECT_TIMEOUT_MS = 5000;
const DEMO_CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "worker-src 'self'",
  "style-src 'unsafe-inline'",
  "connect-src 'self' wss: https: ws://127.0.0.1:* ws://localhost:* http://127.0.0.1:* http://localhost:*",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function applySecurityHeaders(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", DEMO_CSP);
}

function rejectUpgrade(socket, statusLine = "400 Bad Request") {
  try {
    socket.end(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`);
  } catch {
    socket.destroy();
  }
}

function validateUpgradeRequest(req, head) {
  if (head && head.length > 0) {
    return null;
  }
  const seen = new Map();
  const forwardedLines = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const rawName = req.rawHeaders[i];
    const rawValue = req.rawHeaders[i + 1];
    if (/[\r\n\0]/.test(rawName) || /[\r\n\0]/.test(rawValue)) {
      return null;
    }
    const lower = rawName.toLowerCase();
    if (lower === "content-length" || lower === "transfer-encoding") {
      return null;
    }
    if (SINGLETON_UPGRADE_HEADERS.has(lower) && seen.has(lower)) {
      return null;
    }
    if (!seen.has(lower)) {
      seen.set(lower, rawValue);
    }
    if (ALLOWED_UPGRADE_HEADERS.has(lower)) {
      forwardedLines.push(`${rawName}: ${rawValue}`);
    }
  }

  const hostHdr = seen.get("host");
  const upgradeHdr = seen.get("upgrade");
  const connectionHdr = seen.get("connection");
  const wsKeyHdr = seen.get("sec-websocket-key");
  const wsVersionHdr = seen.get("sec-websocket-version");

  if (!hostHdr || !hostHdr.trim()) {
    return null;
  }
  if (!upgradeHdr || upgradeHdr.trim().toLowerCase() !== "websocket") {
    return null;
  }
  if (
    !connectionHdr ||
    !connectionHdr
      .split(",")
      .some((tok) => tok.trim().toLowerCase() === "upgrade")
  ) {
    return null;
  }
  if (!wsVersionHdr || wsVersionHdr.trim() !== "13") {
    return null;
  }
  if (!wsKeyHdr || !/^[A-Za-z0-9+/]{22}==$/.test(wsKeyHdr.trim())) {
    return null;
  }
  if (Buffer.from(wsKeyHdr.trim(), "base64").length !== 16) {
    return null;
  }
  return forwardedLines;
}

function resolveSafe(baseDir, relPath) {
  const clean = path.normalize(relPath).replace(/^(\.\.(\/|\\|$))+/, "");
  const full = path.resolve(baseDir, clean);
  if (full !== baseDir && !full.startsWith(baseDir + path.sep)) {
    return null;
  }
  return full;
}

const cfg = parseArgs(process.argv.slice(2));

const server = http.createServer((req, res) => {
  applySecurityHeaders(res);
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("method not allowed");
    return;
  }
  let url;
  try {
    url = new URL(req.url || "/", "http://127.0.0.1");
  } catch {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("bad request");
    return;
  }
  const pathname = url.pathname;

  if (pathname === "/demo-config.json") {
    if (cfg.demoConfigFile && fs.existsSync(cfg.demoConfigFile)) {
      res.writeHead(200, { "Content-Type": MIME[".json"] });
      res.end(fs.readFileSync(cfg.demoConfigFile));
    } else {
      res.writeHead(200, { "Content-Type": MIME[".json"] });
      res.end("{}");
    }
    return;
  }

  let filePath = null;
  if (pathname === "/" || pathname === "/index.html") {
    filePath = path.join(WEB_ROOT, "demo", "index.html");
  } else if (pathname.startsWith("/demo/")) {
    const rel = pathname.slice("/demo/".length);
    if (DEMO_PUBLIC_FILES.has(rel)) {
      filePath = path.join(WEB_ROOT, "demo", rel);
    }
  } else if (pathname.startsWith("/src/")) {
    filePath = resolveSafe(path.join(WEB_ROOT, "src"), pathname.slice("/src/".length));
  } else if (pathname.startsWith("/pkg/")) {
    filePath = resolveSafe(path.join(WEB_ROOT, "pkg"), pathname.slice("/pkg/".length));
  } else if (pathname.startsWith("/pkg-p2p/")) {
    filePath = resolveSafe(path.join(WEB_ROOT, "pkg-p2p"), pathname.slice("/pkg-p2p/".length));
  } else if (cfg.serveVectors && pathname.startsWith("/spec/vectors/")) {
    filePath = resolveSafe(
      path.join(REPO_ROOT, "spec", "vectors"),
      pathname.slice("/spec/vectors/".length)
    );
  }

  if (!filePath || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("not found");
    return;
  }
  const ext = path.extname(filePath);
  const contentType = MIME[ext] || "application/octet-stream";
  const compressible = COMPRESSIBLE_EXTS.has(ext);
  const acceptsGzip = /\bgzip\b/i.test(String(req.headers["accept-encoding"] || ""));
  const useGzip = compressible && acceptsGzip;
  const headers = { "Content-Type": contentType };
  if (compressible) {
    headers.Vary = "Accept-Encoding";
  }
  if (useGzip) {
    headers["Content-Encoding"] = "gzip";
  }
  res.writeHead(200, headers);
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  const raw = fs.createReadStream(filePath);
  if (useGzip) {
    pipeline(raw, zlib.createGzip(), res, () => {});
  } else {
    pipeline(raw, res, () => {});
  }
});

server.on("upgrade", (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url || "/", "http://127.0.0.1");
  } catch {
    rejectUpgrade(socket, "400 Bad Request");
    return;
  }
  if (req.method !== "GET" || url.pathname !== "/v1/relay" || !cfg.relayHost || !cfg.relayPort) {
    rejectUpgrade(socket, "404 Not Found");
    return;
  }
  if (url.search !== "") {
    rejectUpgrade(socket, "400 Bad Request");
    return;
  }
  const headerLines = validateUpgradeRequest(req, head);
  if (!headerLines) {
    rejectUpgrade(socket, "400 Bad Request");
    return;
  }

  const upstream = net.connect(cfg.relayPort, cfg.relayHost);
  let connected = false;
  const connectTimer = setTimeout(() => {
    if (!connected) {
      rejectUpgrade(socket, "504 Gateway Timeout");
      upstream.destroy();
    }
  }, UPGRADE_CONNECT_TIMEOUT_MS);

  upstream.on("error", () => {
    clearTimeout(connectTimer);
    if (!connected) {
      rejectUpgrade(socket, "502 Bad Gateway");
    }
    socket.destroy();
  });
  socket.on("error", () => {
    clearTimeout(connectTimer);
    upstream.destroy();
  });
  upstream.on("close", () => {
    clearTimeout(connectTimer);
    socket.destroy();
  });
  socket.on("close", () => {
    clearTimeout(connectTimer);
    upstream.destroy();
  });
  upstream.on("connect", () => {
    connected = true;
    clearTimeout(connectTimer);
    const reqHead = `GET /v1/relay HTTP/1.1\r\n${headerLines.join("\r\n")}\r\n\r\n`;
    upstream.write(reqHead);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
});

server.listen(cfg.listenPort, cfg.listenHost, () => {
  const addr = server.address();
  process.stdout.write(`listening=http://${addr.address}:${addr.port}\n`);
});
