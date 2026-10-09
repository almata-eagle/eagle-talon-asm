# ADR 0007 — OT security as a portable module, offline first

- **Status:** accepted (OT-1 built on it, 2026-10-09)
- **Date:** 2026-10-09

## Context
Almata assesses facility-related control systems (generators, HVAC, fire
suppression) on construction projects against UFC 4-010-06 (2023, RMF for FRCS)
and NIST SP 800-82. It delivers a spreadsheet checklist. Sites may have limited
or no internet, and cloud AI may or may not be allowed per contract. The
product should start inside Talon, but must be able to run alone, on-prem, in
DDIL conditions.

## Decision
1. **Module in this repo, separable.** Code in `ot/`, with its own FastAPI
   router, UI view and **its own SQLite database** (not the Talon DB). It can
   move to its own repo later without a rewrite.
2. **Offline first.** No runtime internet dependency: no CDN, fonts are bundled,
   no telemetry. One container image for Core, a field laptop or an on-prem
   server. `EAGLE_MODE=ot` runs it without the SOC features.
3. **Spreadsheet in, spreadsheet out.** Almata's existing checklist is the
   import and export format. No CCI or control content is bundled; it's
   always imported from the engagement's own source.
4. **UFC concepts are first-class:** C-I-A impact rating, overlay, CCI and its
   UFC category, UFC architecture level, design phase, and status including
   Inherited and Impractical with rationale.
5. **AI optional per engagement,** off by default, with every call logged and
   only assessor-approved text sent. A local-model backend can be added
   behind the same interface.
6. **Monitoring is passive only.** Any future sensor listens on a mirror
   port; there's no code path that sends packets to a control network.
7. **Login, roles and audit log from the first OT release.** Assessment data
   may be sensitive (CUI-marked per contract).
8. **Engagement bundle** (zip with SQLite, evidence and SHA-256 manifest) is
   the unit of transfer between field and HQ.

## Consequences
- Some duplication with Talon (users, audit) until the shared core is
  extracted. That's acceptable: OT must run without the SOC stack.
- Without bundled CCI content, a first-time setup needs an import step.
  That's also what keeps the checklist correct per contract.
- Phase OT-1 has no AI dependency at all, so it's deliverable on any site.
