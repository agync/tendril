# Orchestration and Dispatch

This audit methodology is tool-agnostic. Choose the dispatch pattern that matches available tooling while preserving worktree isolation and bounded host resource usage.

## Dispatch modes

### Mode A: Workflow or parallel subagents (preferred on multi-core hosts)

1. Run `bash .agents/skills/security-privacy-audit/scripts/audit-worktrees.sh prepare --commit HEAD` once from the repository root after `make check` has populated compiled targets.
2. Launch all Wave 1 lanes in parallel, giving each lane only:
   - Its assigned worktree path (`.worktrees/audit-<lane>`).
   - Its raw output target (`.agents/brain/scratch/security-audit-<date>/raw-<lane>.md`).
   - Its lane focus from [lanes.md](lanes.md) and rules from [proof-and-severity.md](proof-and-severity.md).
   - Model selection: use strong reasoning models on security-critical judgment lanes (`core`, `runtime`, `bindings`, `web-privacy`, and Wave 2 `triage`), keeping cheaper tiers only for initial mechanical inventories if split further.
3. At the Wave 1 barrier, confirm every lane finished and wrote its non-empty raw report.
4. Launch one strong Wave 2 **Security Audit Triage Lead** agent following [triage-and-report.md](triage-and-report.md), pointing it to the 4 raw reports, the 4 audit worktrees (for re-running proofs), and the audited commit (`HEAD` / `main`) for primary-source verification.
5. Spot-check every `P0` and `P1` High claim against the audited commit, then clean up with `audit-worktrees.sh cleanup`.

### Mode B: Multi-reviewer human / separate-session workflow

1. Lead maintainer runs `make check` and `audit-worktrees.sh prepare --commit HEAD`.
2. Four reviewers check out `.worktrees/audit-{core,runtime,bindings,web-privacy}`, commit or stage reproduction tests strictly inside their own worktree, and save raw reports in `.agents/brain/scratch/security-audit-<date>/`.
3. A fifth maintainer runs Wave 2 adversarial triage across the 4 raw reports and merges `outbox/security-privacy-audit-report.md`.
4. Lead runs `audit-worktrees.sh cleanup` after verification.

### Mode C: Single-agent sequential pass

1. Prepare the 4 worktrees (or 1 dedicated audit worktree `.worktrees/audit-single` if only one reviewer runs sequentially, passing `--lanes "single"`).
2. Complete each domain checklist from [lanes.md](lanes.md) one at a time, writing `raw-<lane>.md` for each so context stays focused and proof outputs are preserved on disk.
3. Switch to an adversarial "refute my own findings" pass ([triage-and-report.md](triage-and-report.md)), challenging each raw claim before compiling the unified report.
4. Clean up worktrees with `audit-worktrees.sh cleanup`.

## Resource and workspace hygiene

- **Bound concurrent compilation:** Instruct every lane to export `CARGO_BUILD_JOBS=4` and run targeted crate/test commands (`cargo test -p tendril-core --test ...`) instead of workspace-wide rebuilds.
- **Avoid `target/` corruption:** Never share one mutable `CARGO_TARGET_DIR` across concurrent writers. CoW-reflinked per-worktree `target/` directories (`cp --reflink=auto` or `cp -c`) give zero lock contention and near-zero extra disk usage while reusing compiled external dependencies.
- **Keep `main` untouched:** Audit reproduction tests live only inside `.worktrees/audit-<lane>` during the audit and are discarded by `audit-worktrees.sh cleanup` (save regression tests worth keeping only when fixing confirmed findings later in dedicated fix PRs).
- **No leaked scratch or host data:** Keep all raw and final audit reports under `.agents/brain/` (create `.agents/brain/scratch/<audit-run>/` with `mkdir -p` since `bootstrap.sh` omits `scratch/`), and verify final reports contain zero host-specific paths, private tokens, or en/em-dashes (`--` / `-` only).
