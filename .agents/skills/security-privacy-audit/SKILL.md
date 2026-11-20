---
name: security-privacy-audit
description: >
  Two-wave, proof-backed security and privacy audit for Tendril: isolate compiled worktrees,
  fan out across protocol, runtime, bindings, and web/privacy lanes, adversarially triage raw claims,
  and emit one prioritized report. Use for security audits, threat reviews, privacy/metadata audits,
  or pre-release gate checks.
license: Apache-2.0
compatibility: >
  Tool-agnostic repository skill requiring git, Cargo, and shell tools (`bash`, `shellcheck`);
  uses CoW reflinks when supported (`cp --reflink=auto` or `cp -c`) to share compiled artifacts.
metadata:
  author: tendril
  version: "1.0.0"
  scope: repository
  spec: "https://agentskills.io/specification"
  tags: "security, privacy, audit, threat-model, cryptography, verification, triage"
  triggers: "security audit; privacy audit; threat model review; metadata exposure audit; adversarial code review; pre-release security gate; audit report triage"
---

# Security and Privacy Audit

Repeatable, two-wave adversarial security and privacy audit for the Tendril workspace. Specialist lanes hunt independently across disjoint trust surfaces and prove every claim against the live code at `HEAD`; a second triage pass challenges, deduplicates, and calibrates all raw claims into a single prioritized report.

## Non-negotiables

- **Prove every finding:** Support each claim with an executed defensive test (`PROVEN_BY_TEST`) or an exact line-by-line code/wire trace (`PROVEN_BY_CODE_TRACE`) when a target cannot execute locally. Never write weaponized exploits or touch external networks. Keep unproven speculations out of the findings list.
- **Audit a freshly compiled `HEAD` in isolation:** Prepare one git worktree per lane seeded via CoW reflinks (`scripts/audit-worktrees.sh`) so lanes reuse compiled artifacts without rebuilding external crates or racing on `main`.
- **Separate discovery from triage (two waves):** Wave 1 produces raw lane reports; Wave 2 tries to refute or downgrade every claim, checks cross-layer mitigations, deduplicates overlaps, and assigns calibrated priority (`P0`-`P3`).
- **Real-world threat framing:** Every confirmed finding states adversary position, preconditions, likelihood, CIA/privacy impact, remediation, and effort (`S`/`M`/`L`).
- **Spot-check and leave no residue:** Verify every `P0` and `P1` claim against primary files on the audited commit (`HEAD` / `main`), ensure `.agents/brain/scratch/` exists before writing raw reports, keep audit outputs strictly under `.agents/brain/`, and run `cleanup` to delete temporary worktrees and branches.

## Route

Load only the reference needed for the current step:

| Stage | Objective | Reference / Asset |
|---|---|---|
| 0. Prepare | Spin up CoW-reflinked audit worktrees from `HEAD` and clean them up afterward | [audit-worktrees.sh](scripts/audit-worktrees.sh) |
| 1. Scope | Partition repository crates, bindings, and cross-cutting privacy adversaries across lanes | [lanes.md](references/lanes.md) |
| 2. Prove & Score | Follow defensive proof requirements, finding schema, and severity/priority calibration | [proof-and-severity.md](references/proof-and-severity.md) |
| 3. Dispatch | Run Wave 1 and Wave 2 via parallel agents, multi-reviewer teams, or one agent sequentially | [dispatch.md](references/dispatch.md) |
| 4. Triage & Report | Execute adversarial refutation, Privacy Matrix analysis, and unified report generation | [triage-and-report.md](references/triage-and-report.md) |

## Quick start

```bash
# 0. Compile target commit once, then prepare CoW-reflinked lane worktrees
make check
bash .agents/skills/security-privacy-audit/scripts/audit-worktrees.sh prepare --commit HEAD

# 1. Run Wave 1 lanes (parallel or sequential per references/dispatch.md)
#    Outputs (create directory with mkdir -p if needed):
#      .agents/brain/scratch/security-audit-<YYYY-MM-DD>/raw-<lane>.md
# 2. Run Wave 2 adversarial triage against primary sources and lane proofs
#    Output:  .agents/brain/outbox/security-privacy-audit-report.md
# 3. Spot-check P0/P1 findings on the audited commit (HEAD / main), then remove worktrees
bash .agents/skills/security-privacy-audit/scripts/audit-worktrees.sh cleanup
```
