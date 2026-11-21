#!/usr/bin/env python3
"""Serve dist/ on loopback the way the Cloudflare static assets do, closely enough to test it.

    serve.py <dist> [port]

Applies _headers (every matching rule, `! Name` detaching a header an earlier rule set), maps
/path/ to /path/index.html and /path to /path.html, and answers unknown paths with the nearest
404.html up the path. It re-reads _headers when the file changes, so a rebuild needs no restart.
"""

import http.server
import pathlib
import re
import sys
import urllib.parse


def load_rules(dist: pathlib.Path) -> list[tuple[re.Pattern, list[tuple[str, str | None]]]]:
    rules = []
    current = None
    for raw in (dist / "_headers").read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            pattern = "^" + re.escape(line).replace(r"\*", ".*") + "$"
            current = (re.compile(pattern), [])
            rules.append(current)
        elif line.strip().startswith("!"):
            current[1].append((line.strip()[1:].strip(), None))
        else:
            name, value = line.strip().split(":", 1)
            current[1].append((name.strip(), value.strip()))
    return rules


class Handler(http.server.SimpleHTTPRequestHandler):
    dist: pathlib.Path
    rules: list = []
    rules_mtime: float = -1.0

    @classmethod
    def current_rules(cls) -> list:
        try:
            mtime = (cls.dist / "_headers").stat().st_mtime
        except FileNotFoundError:
            return cls.rules
        if mtime != cls.rules_mtime:
            cls.rules, cls.rules_mtime = load_rules(cls.dist), mtime
        return cls.rules

    def resolve(self, path: str) -> tuple[pathlib.Path | None, int]:
        root = pathlib.Path(self.directory)
        rel = urllib.parse.unquote(path.split("?", 1)[0]).lstrip("/")
        candidate = (root / rel).resolve()
        if not candidate.is_relative_to(root.resolve()):
            return None, 404
        if candidate.is_dir():
            candidate = candidate / "index.html"
        elif not candidate.exists() and candidate.with_suffix(".html").is_file():
            candidate = candidate.with_suffix(".html")
        if candidate.is_file():
            return candidate, 200
        # As the static assets do: the nearest 404.html up the path.
        for folder in (root / rel).parents:
            if (folder / "404.html").is_file() and folder.resolve().is_relative_to(root.resolve()):
                return folder / "404.html", 404
        return root / "404.html", 404

    def send_head(self):
        file, status = self.resolve(self.path)
        if file is None or not file.is_file():
            self.send_error(404)
            return None
        body = file.open("rb")
        self.send_response(status)
        self.send_header("Content-Type", self.guess_type(str(file)))
        self.send_header("Content-Length", str(file.stat().st_size))
        headers: dict[str, list[str]] = {}
        request_path = urllib.parse.urlsplit(self.path).path
        for pattern, entries in self.current_rules():
            if not pattern.match(request_path):
                continue
            for name, value in entries:
                key = name.lower()
                if value is None:
                    headers.pop(key, None)
                else:
                    headers.setdefault(key, []).append(value)
        for key, values in headers.items():
            self.send_header(key, ", ".join(values))
        self.end_headers()
        return body

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    dist = pathlib.Path(sys.argv[1]).resolve()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4180
    Handler.dist = dist
    Handler.extensions_map = {**Handler.extensions_map, ".webp": "image/webp", ".woff2": "font/woff2"}
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), lambda *a, **k: Handler(*a, directory=str(dist), **k)
    )
    print(f"serving {dist} at http://127.0.0.1:{port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
