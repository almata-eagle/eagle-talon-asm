# ADR 0004 — Rule-based cases, Claude explains (read-only)

- **Status:** accepted
- **Date:** 2026-10-08

## Context
Phase 2 (ADR 0002) adds AI triage. Sending raw logs to an LLM would be costly
and unexplainable, and an LLM deciding what counts as an incident is hard to
audit. Logs are attacker-controlled, so anything that reads them is a
prompt-injection target.

## Decision
1. **Deterministic rules create cases; Claude only explains them.** Every case
   traces to a readable rule (`backend/soc_rules.py`). Claude never decides
   whether something is a finding.
2. **Cases merge** by rule and entity while open, within a 6-hour gap. Evidence
   always covers the case's full lifetime.
3. **Cases live in the Talon SQLite DB** in a new `soc_cases` table, using
   additive migrations only. Eagle Eye shares the DB.
4. **Triage is read-only.** Claude answers through a forced `record_triage` tool
   call with a strict schema, and the result is re-validated. Options are
   suggestions and there is no execution path. That arrives in Phase 4, behind
   human approval (ADR 0002).
5. **Injection defences:** a fenced, escaped, truncated, allowlisted evidence
   block; untrusted-data rules in the system prompt; an `injection_suspected`
   flag surfaced in the UI; schema re-validation; UI escaping.
6. **Cost:** one call per case, re-triage only on growth or escalation (max 3
   automatic), an hourly budget, a cached system prompt, a dedicated `eagle-soc`
   workspace with a spend limit, and kill switches via env.
7. **Model via env** (`SOC_TRIAGE_MODEL`, default `claude-sonnet-5-5`), so it
   can change without code edits.
8. **Prod defaults are off** (`SOC_DETECT`, `SOC_TRIAGE`). Staging turns them on.

## Consequences
- Coverage is limited to what the rules express. New patterns need a new rule,
  plus a test. Feedback (useful/noise) drives tuning.
- Case data (IPs, signatures) is sent to the Claude API for triage. That's fine
  for the home-lab PoC. For customer data, this must be covered in the MSSP
  agreement and the APPI review.
- The detection loop runs inside the API process (single worker). If the API
  ever runs multiple workers, move it to its own service.
