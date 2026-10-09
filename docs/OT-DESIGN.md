# Eagle Talon OT — design

> OT-1 is built: see [OT.md](OT.md). Later phases below are still the plan.

Working name **Talon OT**. It's a module for facility-related control system
(FRCS) security assessments on construction projects. It starts in this repo and
is packaged so it can run alone, on-prem or in DDIL (disconnected, degraded,
intermittent, limited bandwidth) conditions. The decision record is
[adr/0007](adr/0007-ot-module-portable-ddil.md).

## 1. What it replaces
Today Almata delivers a **spreadsheet checklist** against **UFC 4-010-06** (RMF
for FRCS) and **NIST SP 800-82**. Talon OT keeps the spreadsheet as an
import/export format, so nothing changes for the client. The work behind it
becomes a structured, evidence-backed workflow:

| Today (spreadsheet) | Talon OT |
|---|---|
| Rows of controls with status typed by hand | A checklist per system with status, owner, evidence and finding per item |
| Photos and configs in a folder somewhere | Evidence attached to the item it proves (photo, screenshot, config, scan output), hashed |
| Findings written at the end | Findings and remediation written per item; POA&M (plan of action and milestones) generated |
| One language | Report in English and Japanese |
| Hard to compare sites | Same structure for every project: progress, open findings and repeat issues across sites |

## 2. How UFC 4-010-06 (10 Oct 2023) is modelled
These come straight from the UFC's design process, so the data maps one-to-one:

- **Engagement → Site → System.** One system is one FRCS (HVAC/BAS, generator
  or electrical power system, fire suppression/sprinkler, UMCS, lighting,
  elevators and so on).
- **Impact rating per system:** C-I-A as LOW, MODERATE or HIGH, set by the
  System Owner with AO concurrence. Talon OT records who set it and when. It
  also offers the UFC's Appendix D categorisation flow as a helper.
  Requirements in the UFC target LOW and MODERATE; HIGH is flagged as
  needing customised requirements.
- **Control set:** the NIST SP 800-82 overlay (LOW) or the RMF TAG overlay
  (MODERATE), on NIST SP 800-53 Rev. 4. These expand to **CCIs** (control
  correlation identifiers).
- **CCI category,** exactly as the UFC defines it: DoD-Defined, Designer,
  Non-Designer, Platform Enclave or Impractical. The category decides who is
  responsible (designer, System Owner, platform/site IT), and the checklist
  can filter by it.
- **Architecture level per asset,** using the UFC's levels: 0 sensors and
  actuators, 1 non-IP field control, 2 IP field control, 3 FPOC (field point
  of connection), 4 front end and control-system IP network, 5 external
  connections. "Standard IT" levels and "non-standard IT" levels are shown
  differently, because different people own them.
- **Item status:** Implemented, Partially implemented, Not implemented,
  Inherited (with *from where*), Not applicable, or Impractical (with
  rationale). These are the states the UFC asks to be documented, including
  inherited and infeasible CCIs.
- **Design phases** (Basis of Design → Concept → Interim → Final → Issued for
  Construction) and construction/commissioning checks. Each assessment is
  stamped with the phase it applies to.

**Content licensing.** The UFC and UFGS are public US Government documents.
The full DoD CCI list sits behind the RMF Knowledge Service (CAC required),
so Talon OT ships **no CCI content of its own**. It imports the control and
CCI tables from Almata's existing spreadsheet, or from the WBDG Excel tools.
The checklist is therefore always the version the client contract names.

## 3. Phases
| Phase | What | Done when |
|---|---|---|
| **OT-1** Checklist & evidence | Engagements, sites, systems, impact rating; import Almata's spreadsheet; work the checklist (status, owner, notes, evidence upload with SHA-256); findings and POA&M; export back to the **same spreadsheet layout** plus a PDF report (EN/JA). Works fully offline. Local login, roles and audit log from day 1. | One real (sanitised) checklist imported, worked and exported with no manual fixing |
| **OT-2** Asset inventory | Controllers and devices per system: vendor, model, firmware, protocol (BACnet, Modbus, LonWorks, Niagara/Fox and so on), IP and VLAN, UFC level, and who it talks to. A simple network diagram by level. Links from inventory items to the CCIs they satisfy or fail. | Inventory and diagram included in the report |
| **OT-3** Claude assist (opt-in per engagement) | Draft a finding and remediation from the item and its evidence notes; translate EN↔JA; summarise gaps by category and owner; spot inconsistent statuses. **Off by default.** Never sends evidence files, only text the assessor approves. | Assessor accepts or edits drafts; nothing is sent while off |
| **OT-4** Passive monitoring (optional sensor) | A portable sensor (small box or laptop on a SPAN/mirror port) running Zeek with the CISA/INL ICS protocol parsers and Suricata's Modbus/DNP3 rules. **Listen only, never scan.** Discovers assets into the inventory, builds a who-talks-to-whom baseline, and flags new talkers, external connections and write commands. | Sensor fills OT-2's inventory on a test bench and raises a case on an unexpected connection |
| **OT-5** Field ↔ HQ sync | Carry an engagement out on a laptop and bring it back: signed export bundle, conflict-safe import, multi-tenant at HQ | Two assessors work offline and merge cleanly |

## 4. Portability and DDIL
- **Own package and database.** The code lives in `backend/ot/` (FastAPI router)
  with its own page, `frontend/ot.html`, and stores everything in **its own SQLite file per
  deployment**, never the Talon DB that Eagle Eye shares. Evidence files sit
  next to it on disk.
- **One container, no internet needed.** No CDN, no external fonts, no
  phone-home. The same image runs on Core, on a field laptop (Docker, x86 or
  ARM) or on an on-prem server. Talon's SOC features are off in an OT-only
  deployment: run `backend/ot_app.py` (built in OT-1) instead of `main.py`.
- **Engagement bundle.** Export is one `.zip`: the SQLite file, evidence and a
  manifest with SHA-256 per file. Import verifies the hashes. That's how work
  moves from a disconnected site to HQ, and it doubles as the archive copy
  for the client.
- **AI is a switch, not a dependency.** Every feature works with Claude off.
  The engagement records whether AI was allowed, and every AI call is logged
  (what was sent and when). A local-model option can slot in behind the same
  interface later, for sites where no cloud AI is permitted.
- **Data handling.** Each engagement has a marking banner (e.g. "CUI" if the
  contract requires it). On appliances, disk encryption is required (LUKS).
  Access needs a login, every change goes to the audit log, and nothing is
  shared between engagements.

## 5. Safety rules (in CLAUDE.md since OT-1)
- **Never scan or write to OT devices.** The sensor is passive, and there's no
  code path that sends packets to a control network.
- Evidence files are untrusted input: size limits, type checks, stored by
  hash, never executed or rendered as HTML.
- No CCI or control text is bundled; it's always imported from the
  engagement's own source.
- AI is off unless the engagement says otherwise; only assessor-approved
  text is sent.

## 6. Open questions for Almata
1. **A sanitised copy of the current spreadsheet** (no client data, no CUI): its
   columns decide the importer and the export layout.
2. Who uses it on site: only Almata assessors, or also the contractor and
   designer? That affects roles and whether there's a contractor portal.
3. Report format the client expects: is the spreadsheet enough, or do they
   also want a narrative PDF? In which language(s)?
4. Typical site conditions: is a laptop with Docker acceptable, or does it
   need to be a sealed appliance?
5. Do any contracts already say anything about AI tools or cloud services?
