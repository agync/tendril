import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
  let url;
  try {
    url = new URL(req.url || "/", "http://127.0.0.1");
  } catch {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("bad request");
    return;
  }
  const pathname = url.pathname;
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

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
    filePath = resolveSafe(path.join(WEB_ROOT, "demo"), pathname.slice("/demo/".length));
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
  res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
});

server.on("upgrade", (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url || "/", "http://127.0.0.1");
  } catch {
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }
  if (req.method !== "GET" || url.pathname !== "/v1/relay" || !cfg.relayHost || !cfg.relayPort) {
    socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    return;
  }
  const upstream = net.connect(cfg.relayPort, cfg.relayHost);
  upstream.on("error", () => {
    socket.destroy();
  });
  socket.on("error", () => {
    upstream.destroy();
  });
  upstream.on("close", () => {
    socket.destroy();
  });
  socket.on("close", () => {
    upstream.destroy();
  });
  upstream.on("connect", () => {
    const headerLines = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      headerLines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    }
    const targetPath = `${url.pathname}${url.search}`;
    const reqHead = `${req.method} ${targetPath} HTTP/${req.httpVersion}\r\n${headerLines.join("\r\n")}\r\n\r\n`;
    upstream.write(reqHead);
    if (head && head.length > 0) {
      upstream.write(head);
    }
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
});

server.listen(cfg.listenPort, cfg.listenHost, () => {
  const addr = server.address();
  process.stdout.write(`listening=http://${addr.address}:${addr.port}\n`);
});
