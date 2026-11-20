# Adversarial Triage and Report Template

Wave 2 exists because single-pass security scanners over-report theoretical issues, miss cross-layer mitigations, and duplicate cross-cutting bugs across crates.

## Wave 2 adversarial triage checklist

For every candidate finding across `raw-{core,runtime,bindings,web-privacy}.md`:

1. **Read primary sources at the audited commit (`HEAD` / `main`):** Open the exact cited files and lines on the audited commit; verify line numbers and symbols match current code.
2. **Re-run or inspect proofs:** Inside the lane's `.worktrees/audit-<lane>`, execute the cited reproduction test (or verify the code/wire trace step by step). Discard claims whose test fails or proves something weaker than stated.
3. **Attempt to refute:** Search callers, `spec/*.md`, and sibling layers (`tendril-core`, `tendril-runtime`, `docs/overview.md`) for existing guards:
   - Does an earlier layer reject the input before the cited function?
   - Does another function actually use a safe path (`tendril-cli` vs `InboundRouter`, live `SessionMachine` CRL signature ingestion vs standalone `verify_grant_json` missing CRL signature validation)?
   - Is the claimed leak an explicitly documented v1 design boundary in `docs/overview.md`?
4. **Deduplicate across lanes:** Collapse identical root causes discovered by multiple lanes (e.g., `Roster::insert_pinned_host` found in Core and Web, or `P2pRelayMode::Custom` found in Runtime and Privacy) into one canonical ID (`SEC-XX` or `PRIV-XX`) listing all affected files.
5. **Assign one disposition:**
   - `CONFIRMED`: Proven vulnerability/defect calibrated at or above raw severity.
   - `DOWNGRADED`: Real issue whose realistic likelihood/impact is lower than Wave 1 claimed (explain exact mitigation reducing it).
   - `UPGRADED`: Impact is greater in realistic production deployments than Wave 1 noted (explain exact operational context).
   - `REFUTED`: False positive or prevented by existing code/protocol guarantees (cite exact proof line; remove from confirmed findings and document in Section 7).

## Mandatory 7-section unified report format

Write `.agents/brain/outbox/security-privacy-audit-report.md` with zero en-dashes or em-dashes and these exact sections:

1. **Executive Verdict & Scrutiny Readiness:** Explicit readiness call (`READY`, `CONDITIONALLY_READY`, or `NOT_READY`) with a 3-part breakdown across Core Cryptographic Protocol, Implementation/Runtime/Bindings Posture, and Privacy & Metadata Posture.
2. **Audit Scope & Methodology:** Target commit SHA, lane inventory, Wave-2 verification caveats (e.g., Linux-only execution skipping Apple/Android SDK compilation).
3. **Summary Scorecard:** Table of canonical counts (`Severity` rows x `P0`/`P1`/`P2`/`P3` columns) plus raw-to-triaged reconciliation (`N` raw -> `M` canonical, refuted, downgraded, upgraded).
4. **Prioritized Confirmed Findings:** Ordered `P0` -> `P1` -> `P2` -> `P3` using the schema in [proof-and-severity.md](proof-and-severity.md).
5. **End-to-End Privacy & Metadata Exposure Matrix:** Six-row table mapping each adversary class (Passive Internet Eavesdropper, Public Discovery/Relay Operator, Self-Hosted Relay/Broker Operator, Same-LAN Attacker, Paired/Revoked Peer, Local Disk/Browser Forensic Observer) to `What Leaks`, `Root Code Location`, and `Mitigation Options`.
6. **Prioritized Remediation Roadmap:** Grouped into Batch 1 (Before External Audit), Batch 2 (Before Public 1.0), Batch 3 (Upcoming Milestone Interactions), and Batch 4 (Documented Architectural Tradeoffs).
7. **Appendix: Verified Strong Controls, Refuted/Downgraded Claims & Deduplication Map:** Preserve institutional memory of what held up under attack, every refuted claim with refutation proof, every downgraded/upgraded item, and a raw-to-canonical mapping table.
