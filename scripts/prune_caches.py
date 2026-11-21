#!/usr/bin/env python3
"""Print obsolete GitHub Actions cache rows on main: all but the newest per family."""

import re
import sys
from datetime import datetime, timedelta, timezone

MAIN = "refs/heads/main"
GRACE = timedelta(hours=1)

RUST = re.compile(r"^(v\d+-rust-.+?-(?:Linux|Darwin|Windows_NT)-(?:x64|arm64))-")
RUST_KEY = re.compile(r"^v\d+-rust-")
HASHED = re.compile(r"^(.*)-[0-9a-f]{7,}$")


def family(key):
    """Extract the cache family identifier without content hashes."""
    match = RUST.match(key)
    if match:
        return match[1]
    if RUST_KEY.match(key):
        raise ValueError(f"unrecognised Rust cache key: {key!r}")
    match = HASHED.match(key)
    return match[1] if match else key


def when(value):
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def to_delete(rows, now, grace=GRACE):
    """Return (id, key) pairs for obsolete main caches outside the access grace window."""
    recent = now - grace
    newest = {}
    for cache_id, ref, key, created_at, _ in rows:
        if ref != MAIN:
            continue
        fam = family(key)
        current = newest.get(fam)
        if current is None or (when(created_at), int(cache_id)) > (
            when(current[0]),
            int(current[1]),
        ):
            newest[fam] = (created_at, cache_id, key)
    keep = {cache_id for _, cache_id, _ in newest.values()}
    return [
        (cache_id, key)
        for cache_id, ref, key, _, accessed_at in rows
        if ref == MAIN and cache_id not in keep and when(accessed_at) <= recent
    ]


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    now = datetime.now(timezone.utc)
    if args:
        if len(args) == 2 and args[0] == "--now":
            try:
                now = when(args[1])
            except ValueError:
                print(f"--now is not an ISO date: {args[1]!r}", file=sys.stderr)
                return 2
        else:
            print(
                "usage: prune_caches.py [--now ISO] < id, ref, key, created, accessed",
                file=sys.stderr,
            )
            return 2
    rows = []
    for number, line in enumerate(sys.stdin, 1):
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            print(f"line {number}: expected 5 tab-separated fields: {line!r}", file=sys.stderr)
            return 1
        rows.append(tuple(parts))
    try:
        for cache_id, key in to_delete(rows, now):
            print(f"{cache_id}\t{key}")
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
