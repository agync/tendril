#!/usr/bin/env bash
# Classify changed paths into CI workflow areas.
#
# Usage: scripts/ci-areas.sh < changed-paths
#        scripts/ci-areas.sh --all
#        scripts/ci-areas.sh --local < changed-paths
set -euo pipefail
export LC_ALL=C

everything='^(\.github/(workflows|actions)/|Makefile$|rust-toolchain\.toml$|scripts/ci-areas\.sh$)'
core_manifests='Cargo\.(toml|lock)$'
ffi_upstream='^(crates/tendril-(core|relay|runtime|ffi|cli)/|'"$core_manifests"'|spec/vectors/)'
py_node_upstream='^(crates/tendril-(core|relay|runtime|cli)/|'"$core_manifests"'|spec/vectors/)'

names=(rust rust-platforms vectors-go python node web android apple site container scripts)
declare -A areas=(
    [rust]="^(crates/|${core_manifests}|spec/vectors/)"
    [rust-platforms]="^(crates/|${core_manifests}|spec/vectors/)"
    [vectors-go]="(${ffi_upstream}|^bindings/go/)"
    [python]="(${py_node_upstream}|^bindings/python/)"
    [node]="(${py_node_upstream}|^bindings/node/)"
    [web]="^(crates/tendril-(core|relay|runtime|cli|wasm)/|${core_manifests}|spec/vectors/|bindings/web/|deploy/cloudflare/)"
    [android]="(${ffi_upstream}|^bindings/kotlin/)"
    [apple]="(${ffi_upstream}|^bindings/swift/|^Package\.swift$|^scripts/build-xcframework\.sh$)"
    [site]='^(site/|docs/)'
    [container]="^(Containerfile$|\.containerignore$|crates/|${core_manifests})"
    [scripts]='^scripts/'
)

matches() {
    local status=0
    grep -Eq "$1" "$2" || status=$?
    [ "$status" -le 1 ] || exit "$status"
    return "$status"
}

changed=$(mktemp)
trap 'rm -f "$changed"' EXIT
all=false
case "$#:${1:-}" in
    1:--all) all=true ;;
    1:--local) cat > "$changed" ;;
    0:)
        cat > "$changed"
        if matches "$everything" "$changed"; then all=true; fi
        ;;
    *)
        printf 'usage: %s [--all|--local] < changed-paths\n' "$0" >&2
        exit 2
        ;;
esac

for area in "${names[@]}"; do
    run=$all
    if [ "$run" = false ] && matches "${areas[$area]}" "$changed"; then run=true; fi
    echo "$area=$run"
done
