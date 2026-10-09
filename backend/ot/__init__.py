"""
Talon OT — facility-related control system (FRCS) security assessments.

A self-contained package: its own SQLite database, its own users and audit
log, and a FastAPI router (`ot.api.router`). It plugs into Talon
(`OT_ENABLED=on`) or runs alone (`uvicorn ot_app:app`), offline, for
on-prem and DDIL sites. Design: docs/OT-DESIGN.md, ADR 0007.

Nothing in this package sends anything to a control network or to the
internet.
"""
