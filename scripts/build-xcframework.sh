#!/usr/bin/env bash
# Build TendrilFFI.xcframework deterministically or pack an existing XCFramework bundle.
#
# Usage: scripts/build-xcframework.sh <version> <out-zip>
#        scripts/build-xcframework.sh --pack-only <framework-dir> <out-zip>
set -euo pipefail
export LC_ALL=C

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/build-xcframework.sh <version> <out-zip>
  scripts/build-xcframework.sh --pack-only <framework-dir> <out-zip>
EOF
  exit 2
}

pack_xcframework() {
  local framework_dir="$1"
  local out_zip="$2"

  python3 -I - "$framework_dir" "$out_zip" <<'PY'
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

FIXED_DATE_TIME = (2020, 1, 1, 0, 0, 0)
CHUNK_SIZE = 1024 * 1024

framework_dir = Path(os.path.abspath(sys.argv[1]))
out_zip = Path(os.path.abspath(sys.argv[2]))

if not framework_dir.is_dir():
    raise SystemExit(f"not a directory: {framework_dir}")

root_name = framework_dir.name
if (
    framework_dir.parent == framework_dir
    or not root_name.endswith(".xcframework")
    or len(root_name) <= len(".xcframework")
):
    raise SystemExit(f"invalid xcframework directory name: {framework_dir}")

entries = []


def collect(cur_dir: Path, rel_prefix: str) -> None:
    entries.append((f"{rel_prefix}/", "dir", cur_dir, os.lstat(cur_dir)))
    with os.scandir(cur_dir) as it:
        children = sorted(it, key=lambda item: item.name)
    for child in children:
        child_path = Path(child.path)
        child_rel = f"{rel_prefix}/{child.name}"
        st = os.lstat(child_path)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            entries.append((child_rel, "link", child_path, st))
        elif stat.S_ISDIR(mode):
            collect(child_path, child_rel)
        elif stat.S_ISREG(mode):
            entries.append((child_rel, "file", child_path, st))
        else:
            raise SystemExit(f"unsupported file type in framework: {child_path}")


collect(framework_dir, root_name)
entries.sort(key=lambda item: item[0])

out_zip.parent.mkdir(parents=True, exist_ok=True)
fd, tmp_name = tempfile.mkstemp(prefix=".pack-", suffix=".zip", dir=str(out_zip.parent))
os.close(fd)
tmp_zip = Path(tmp_name)

try:
    with zipfile.ZipFile(
        tmp_zip,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zf:
        for arcname, kind, path, st in entries:
            zi = zipfile.ZipInfo(arcname, date_time=FIXED_DATE_TIME)
            zi.create_system = 3
            zi.flag_bits = 0 if arcname.isascii() else 0x800
            if kind == "dir":
                zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                zf.writestr(zi, b"")
            elif kind == "link":
                target = os.readlink(path).encode("utf-8")
                zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zi, target)
            else:
                perm = 0o755 if (st.st_mode & 0o111) else 0o644
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.compress_level = 9
                zi.external_attr = (stat.S_IFREG | perm) << 16
                zi.file_size = st.st_size
                with open(path, "rb") as src, zf.open(zi, "w") as dst:
                    shutil.copyfileobj(src, dst, CHUNK_SIZE)

    digest = hashlib.sha256()
    with open(tmp_zip, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    os.chmod(tmp_zip, 0o644)
    os.replace(tmp_zip, out_zip)
    print(digest.hexdigest())
except Exception:
    tmp_zip.unlink(missing_ok=True)
    raise
PY
}

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$PWD" "$1" ;;
  esac
}

if [ "$#" -eq 3 ] && [ "$1" = "--pack-only" ]; then
  framework_dir="$2"
  while [[ "$framework_dir" == */ ]]; do
    framework_dir="${framework_dir%/}"
  done
  if [ -z "$framework_dir" ] || [ ! -d "$framework_dir" ] || [ -z "$3" ]; then
    echo "error: framework directory does not exist: $2" >&2
    exit 1
  fi
  fw_base=$(basename "$framework_dir")
  fw_parent=$(dirname "$framework_dir")
  if [ -z "$fw_parent" ] || [ "$fw_base" = ".xcframework" ] || [[ "$fw_base" != *.xcframework ]]; then
    echo "error: framework directory must be a named *.xcframework bundle: $2" >&2
    exit 1
  fi
  out_zip=$(abs_path "$3")
  pack_xcframework "$framework_dir" "$out_zip"
  exit 0
fi

if [ "$#" -ne 2 ]; then
  usage
fi

version="$1"
if [ -z "$version" ] || [[ "$version" == -* ]] || [ -z "$2" ]; then
  usage
fi
out_zip=$(abs_path "$2")

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=$(abs_path "${CARGO_TARGET_DIR:-${root}/target}")
cd "$root"

if [ ! -f "crates/tendril-ffi/include/tendril.h" ]; then
  echo "error: missing crates/tendril-ffi/include/tendril.h" >&2
  exit 1
fi

stage="${target_dir}/xcframework-stage"
rm -rf "$stage"
mkdir -p "${stage}/headers" "${stage}/libs"
trap 'rm -rf "$stage"' EXIT

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$target_dir"
export ZERO_AR_DATE=1
export RUSTFLAGS="--remap-path-prefix=${root}=. -C debuginfo=0"

targets=(
  aarch64-apple-darwin
  aarch64-apple-ios
  aarch64-apple-ios-sim
)

for target in "${targets[@]}"; do
  cargo build --locked --release --target "$target" -p tendril-ffi --lib >&2
  mkdir -p "${stage}/libs/${target}"
  cp "${target_dir}/${target}/release/libtendril_ffi.a" "${stage}/libs/${target}/libtendril_ffi.a"
  strip -S "${stage}/libs/${target}/libtendril_ffi.a" >&2
done

cp crates/tendril-ffi/include/tendril.h "${stage}/headers/tendril.h"
cat > "${stage}/headers/module.modulemap" <<'EOF'
module CTendril [system] {
  header "tendril.h"
  export *
}
EOF

xcframework="${stage}/TendrilFFI.xcframework"
xcodebuild -create-xcframework \
  -library "${stage}/libs/aarch64-apple-darwin/libtendril_ffi.a" -headers "${stage}/headers" \
  -library "${stage}/libs/aarch64-apple-ios/libtendril_ffi.a" -headers "${stage}/headers" \
  -library "${stage}/libs/aarch64-apple-ios-sim/libtendril_ffi.a" -headers "${stage}/headers" \
  -output "$xcframework" >&2

plutil -convert xml1 "${xcframework}/Info.plist" >&2
pack_xcframework "$xcframework" "$out_zip"
