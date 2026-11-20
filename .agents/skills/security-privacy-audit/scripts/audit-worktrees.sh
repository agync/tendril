#!/usr/bin/env bash
# Prepare or clean up isolated git worktrees seeded with CoW-reflinked build outputs for security audits.
set -euo pipefail

DEFAULT_LANES="core runtime bindings web-privacy"
DEFAULT_PREFIX=".worktrees/audit"

usage() {
    cat <<'EOF'
Usage:
  audit-worktrees.sh prepare [--commit REF] [--lanes "L1 L2 ..."] [--prefix REL_DIR] [--no-copy-target]
  audit-worktrees.sh cleanup [--lanes "L1 L2 ..."] [--prefix REL_DIR]
  audit-worktrees.sh -h | --help

Subcommands:
  prepare   Create one isolated worktree per lane off REF (default HEAD) on branch audit/<lane>,
            seeding compiled target/ and web/binding artifacts via CoW reflinks when available.
  cleanup   Remove created audit worktrees and delete audit/<lane> branches.
EOF
}

die() {
    printf 'audit-worktrees: %s\n' "$*" >&2
    exit 1
}

validate_prefix() {
    local prefix="$1"
    [ -n "$prefix" ] || die "--prefix must not be empty"
    case "$prefix" in
        /*|*/|*//*|*[[:space:]]*|.|..|./*|*/.|*/./*|../*|*/..|*/../*)
            die "invalid --prefix '${prefix}': must be a clean repository-relative path without '.', '..', whitespace, or trailing '/'"
            ;;
        *[!A-Za-z0-9._/-]*)
            die "invalid --prefix '${prefix}': disallowed character"
            ;;
    esac
}

LANE_LIST=()

validate_lanes() {
    local raw="$1"
    case "$raw" in
        *$'\n'*) die "--lanes must be single-line space-separated names" ;;
    esac
    LANE_LIST=()
    local -a tokens=()
    IFS=$' \t' read -r -a tokens <<< "$raw" || true
    local tok
    for tok in "${tokens[@]}"; do
        case "$tok" in
            *[!A-Za-z0-9_-]*|"")
                die "invalid lane name '${tok}' (use [A-Za-z0-9_-])"
                ;;
        esac
        LANE_LIST+=("$tok")
    done
    [ "${#LANE_LIST[@]}" -gt 0 ] || die "--lanes must name at least one lane"
}

copy_cow() {
    local src="$1"
    local dst="$2"
    if [ ! -e "$src" ]; then
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    if cp --version 2>/dev/null | grep -qi "GNU"; then
        cp --reflink=auto -a "$src" "$dst"
    elif [ "$(uname -s)" = "Darwin" ]; then
        cp -c -a "$src" "$dst" 2>/dev/null || {
            rm -rf "$dst"
            cp -a "$src" "$dst"
        }
    else
        cp -a "$src" "$dst"
    fi
}

cmd_prepare() {
    local commit_ref="HEAD"
    local lanes="$DEFAULT_LANES"
    local prefix="$DEFAULT_PREFIX"
    local copy_target=1

    while [ $# -gt 0 ]; do
        case "$1" in
            --commit)
                [ $# -ge 2 ] || die "--commit requires an argument"
                commit_ref="$2"
                shift 2
                ;;
            --lanes)
                [ $# -ge 2 ] || die "--lanes requires an argument"
                lanes="$2"
                shift 2
                ;;
            --prefix)
                [ $# -ge 2 ] || die "--prefix requires an argument"
                prefix="$2"
                shift 2
                ;;
            --no-copy-target)
                copy_target=0
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option for prepare: $1"
                ;;
        esac
    done

    case "$commit_ref" in
        ""|-*)
            die "invalid --commit ref '${commit_ref}'"
            ;;
    esac
    validate_prefix "$prefix"
    validate_lanes "$lanes"

    local repo_root
    repo_root="$(git rev-parse --show-toplevel)"
    local resolved_sha
    resolved_sha="$(git -C "$repo_root" rev-parse --verify "${commit_ref}^{commit}")" ||
        die "cannot resolve commit '$commit_ref'"

    local lane
    for lane in "${LANE_LIST[@]}"; do
        local wt_dir="${repo_root}/${prefix}-${lane}"
        if [ -e "$wt_dir" ]; then
            die "worktree path already exists: ${wt_dir} (run cleanup first)"
        fi
        if git -C "$repo_root" show-ref --verify --quiet "refs/heads/audit/${lane}"; then
            die "branch already exists: audit/${lane} (run cleanup first)"
        fi
    done

    if [ "$copy_target" -eq 1 ] && [ ! -d "${repo_root}/target" ]; then
        printf 'audit-worktrees: note: %s/target not found; run make check first for cached artifacts\n' "$repo_root" >&2
    fi

    printf 'Creating audit worktrees at %s:\n' "${resolved_sha:0:7}"
    for lane in "${LANE_LIST[@]}"; do
        local wt_dir="${repo_root}/${prefix}-${lane}"
        local branch="audit/${lane}"
        git -C "$repo_root" worktree add -q -b "$branch" "$wt_dir" "$resolved_sha"

        if [ "$copy_target" -eq 1 ]; then
            copy_cow "${repo_root}/target" "${wt_dir}/target"
            copy_cow "${repo_root}/bindings/web/pkg" "${wt_dir}/bindings/web/pkg"
            copy_cow "${repo_root}/bindings/web/pkg-p2p" "${wt_dir}/bindings/web/pkg-p2p"
            if [ "$lane" = "bindings" ]; then
                copy_cow "${repo_root}/bindings/python/target" "${wt_dir}/bindings/python/target"
                copy_cow "${repo_root}/bindings/python/tendril/_tendril.so" "${wt_dir}/bindings/python/tendril/_tendril.so"
                copy_cow "${repo_root}/bindings/node/target" "${wt_dir}/bindings/node/target"
                copy_cow "${repo_root}/bindings/node/index.node" "${wt_dir}/bindings/node/index.node"
                copy_cow "${repo_root}/bindings/kotlin/build-jni" "${wt_dir}/bindings/kotlin/build-jni"
            fi
        fi

        printf '  - %-12s %s (branch %s)\n' "$lane" "${prefix}-${lane}" "$branch"
    done
    printf 'Tip: run builds inside each lane with CARGO_BUILD_JOBS=4.\n'
}

cmd_cleanup() {
    local lanes="$DEFAULT_LANES"
    local prefix="$DEFAULT_PREFIX"

    while [ $# -gt 0 ]; do
        case "$1" in
            --lanes)
                [ $# -ge 2 ] || die "--lanes requires an argument"
                lanes="$2"
                shift 2
                ;;
            --prefix)
                [ $# -ge 2 ] || die "--prefix requires an argument"
                prefix="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option for cleanup: $1"
                ;;
        esac
    done

    validate_prefix "$prefix"
    validate_lanes "$lanes"

    local repo_root
    repo_root="$(git rev-parse --show-toplevel)"

    local lane
    for lane in "${LANE_LIST[@]}"; do
        local wt_dir="${repo_root}/${prefix}-${lane}"
        local branch="audit/${lane}"
        if [ -e "$wt_dir" ]; then
            git -C "$repo_root" worktree remove --force "$wt_dir" 2>/dev/null ||
                die "cannot remove path at ${wt_dir} (not a git worktree; remove manually)"
        fi
        if git -C "$repo_root" show-ref --verify --quiet "refs/heads/${branch}"; then
            git -C "$repo_root" branch -D "$branch"
        fi
    done
    git -C "$repo_root" worktree prune
}

main() {
    [ $# -ge 1 ] || {
        usage >&2
        exit 2
    }
    local subcmd="$1"
    shift
    case "$subcmd" in
        prepare)
            cmd_prepare "$@"
            ;;
        cleanup)
            cmd_cleanup "$@"
            ;;
        -h|--help)
            usage
            ;;
        *)
            die "unknown subcommand '$subcmd'"
            ;;
    esac
}

main "$@"
