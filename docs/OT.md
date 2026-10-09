# Talon OT — user and operator guide (OT-1)

Talon OT tracks cybersecurity assessments of facility-related control systems
(FRCS) against **UFC 4-010-06** (10 Oct 2023) and the NIST SP 800-82 / RMF
overlays. OT-1 covers the checklist: bring in the client's spreadsheet, work
it, attach evidence, then hand back the same spreadsheet with the answers
filled in, plus a POA&M and a printable report. Design and later phases are in
[OT-DESIGN.md](OT-DESIGN.md); the decision record is [ADR 0007](adr/0007-ot-module-portable-ddil.md).

## What it never does
- It never connects to, scans or writes to a control system. OT-1 has no
  network code at all apart from serving its own page and API.
- It ships no CCI or control text. Import the list the contract gives you.
- No data leaves the server. AI help is off. The engagement only records
  whether AI is allowed (OT-3 will use it).

## Where it runs

| | Inside Talon | On its own (on-prem / DDIL) |
|---|---|---|
| Start | `OT_ENABLED=on` in `deploy/env/<env>.env` | `docker compose -f deploy/ot/docker-compose.yml up -d --build`, or `cd backend` then `uvicorn ot_app:app --port 8090` |
| Page | `http://core:8098/ot.html` (staging); there's an **OT** button in Talon's top bar | `http://<host>:8090/` |
| Data | `/app/data/ot/` in the Talon data volume (`ot.db` + `evidence/`) | `talon-ot-data` volume, or `backend/data/ot/` |
| Talon DB | never touched | not present |

Prod has `OT_ENABLED` off (the compose default) until the v0.6.0 release turns it on.

## First run
1. Put a setup code in `deploy/secrets.env` so nobody else on the network can
   claim the first admin: `OT_SETUP_CODE=<something only you know>`. Then
   redeploy. (Optional, but do it on any shared network.)
2. Open the page. It asks you to create the first **admin** account (password
   at least 12 characters, plus the setup code if you set one).
3. Under **Admin → Users**, add the other people:
   - **Admin**: everything, including users, deletes and the audit log.
   - **Assessor**: create and edit engagements, systems, checklists and evidence.
   - **Viewer**: read and export only.

Sessions last 12 hours. After 8 wrong passwords in 15 minutes, logins for that
username pause. Disabling a user or resetting their password ends their sessions.

## Working an assessment
1. **Engagement**: one per site or contract. Set the **marking** (for example
   `CUI`). It appears at the top and bottom of every page and in the header and
   footer of every exported sheet.
2. **System**: one per control system (HVAC/BAS, electrical, fire alarm,
   UMCS…). Record the design phase and the **C-I-A impact**. UFC 4-010-06 has
   the System Owner set the impact with the AO's concurrence, so record who did
   it in **Impact set by**.
3. **Import spreadsheet** (`.xlsx`, `.xlsm` or `.csv`, up to 15 MB, 5,000 rows,
   60 columns):
   - Talon finds the header row and guesses the columns from the headings, in
     English and Japanese (CCI, Control, 要件, 実施状況, 備考…).
   - Check the mapping. The highlighted columns are the mapped ones.
   - Answers are normalised: Yes/No/Partial/N/A, Compliant, ○ × △, 適合/不適合,
     実施済み, 対象外 and so on. Anything Talon doesn't recognise becomes
     *Not assessed*, so nothing is silently marked as passing.
   - Only values are read. Formulas come in as their last calculated value,
     macros are ignored, and control characters are stripped.
   - Every original cell is kept and shown under **Original spreadsheet row** on each item.
4. **Assess**: open an item, set its status and severity, then write the
   finding, remediation, owner and due date. **Prev/Next** walks the filtered list.
5. **Evidence**: attach photos, screenshots, PDFs, configs, logs or packet
   captures, up to 25 MB each.
   - Each file is stored by its SHA-256, and the hash goes into the export.
   - Downloads are re-hashed. A file that no longer matches its hash is refused.
   - Only images are shown in the page. Everything else downloads.
6. **Deliver**:
   - **Export spreadsheet** gives one workbook with:
     - a **Summary** sheet;
     - one sheet per system in the client's own layout (title rows, headings,
       column order), with the current answers filled in and Talon's columns
       added on the right (status, finding, remediation, owner, severity,
       due date, evidence count and hashes, last update);
     - a **POA&M** sheet listing every *Not implemented* and *Partial* item.
   - A changed answer is written in the sheet's own vocabulary (if they used △,
     you get △).
   - Cells that start with `= + - @` are written as text, so nothing in the
     export runs as a formula when the client opens it.
   - **Report** is a printable summary plus open items by severity. Use
     **Print / save as PDF**.

Everything an account does is in **Admin → Audit log**: logins, failed logins,
every field change (from → to), imports, evidence added or removed, and exports.

## Running offline (DDIL)
The page uses no CDN, fonts or outside calls. To move it to a disconnected host:
1. Where there is internet, build the image: `docker compose -f deploy/ot/docker-compose.yml build`.
2. Save it: `docker save talon-ot -o talon-ot.tar`.
3. Copy `talon-ot.tar` and the repo's `deploy/ot/` and `frontend/` folders to the site.
4. On the host: `docker load -i talon-ot.tar`, then `docker compose -f deploy/ot/docker-compose.yml up -d`.

By default it listens on `127.0.0.1:8090` only. To serve other machines on the
site LAN, set `OT_BIND=0.0.0.0` (and use a setup code). There is no TLS in
OT-1, so put it behind the site's reverse proxy, or keep it on one laptop.
Use full-disk encryption on any laptop that holds an engagement.

Without Docker: Python 3.12, `pip install -r backend/requirements.txt`, then from
`backend/` run `uvicorn ot_app:app --host 127.0.0.1 --port 8090`.

## Backups
Back up the whole OT data folder (`ot.db` and `evidence/`) together. Inside
Talon it is in the data volume, so `deploy/backup-db.sh` does **not** cover it
yet. Copy `/app/data/ot` from the container until OT-5 adds the signed
engagement bundle.

## Limits in OT-1
- No asset inventory (OT-2), no AI drafting (OT-3), no sensor (OT-4), and no
  field↔HQ merge (OT-5).
- The session token is held in the browser tab's session storage. Close the
  tab to log out of a shared machine.
- Re-importing into a system adds rows; it does not merge. To start over,
  delete the system (admin) and import again.
