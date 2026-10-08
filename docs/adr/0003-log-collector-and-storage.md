# ADR 0003 — Vector collector, NDJSON hot store on Core, gzip archive on the NAS

- **Status:** accepted
- **Date:** 2026-10-08

## Context
Phase 1 (ADR 0002) needs FortiGate and Suricata logs collected on core, kept
searchable for investigations, and archived long-term on the Synology. The
NAS also holds the corporate `finance` share. Core already runs Wazuh, but
Phase 1 must not depend on its internals, and Talon has to be able to read
the data directly.

## Decision
1. **Vector 0.58** (pinned image) is the single collector. It's one container
   per host, shared by Talon staging and prod. It runs as `eddy`, not root. It
   joins the group that owns `eve.json` only when the file isn't world-readable,
   and it never joins `root`.
2. **One flat event format (schema 1)** for every source, with the original
   fields kept under `raw`. It's documented in `docs/SOC-COLLECTOR.md` and
   covered by Vector unit tests.
3. **Hot store = hourly NDJSON files on Core's NVMe**, 30 days. There's no
   database server to run: Talon will query the files directly (DuckDB reads
   NDJSON natively). Revisit when volume outgrows that, or when multi-tenant
   MSSP use starts.
4. **Archive = hourly gzip NDJSON on the NAS `logs` share**, 400 days, written by
   the dedicated `talon-logs` DSM user. The `finance` share is never used, and
   preflight fails if the mount points at it.
5. **NAS outages don't stall the hot path.** The archive sink has a 5 GB disk
   buffer that drops the newest events when full.
6. **No environment-variable substitution inside Vector.** Ports are written
   in `vector.yaml` (5514/udp syslog, 127.0.0.1:8686 health). Vector 0.58+
   disables substitution by default, and we keep that.
7. **Preflight before every deploy.** `soc/preflight.sh` is read-only and its
   output is safe to paste. `deploy-collector.sh` refuses on any FAIL and ends
   with a real self-test event.

## Consequences
- Syslog over UDP is unauthenticated, and any LAN host could spoof it. UFW
  admits 5514/udp only from the FortiGate's address on the LAN interface.
  Investigations must treat log content as untrusted (ADR 0002 §4).
- Hot-store queries scan files, which is fine for a home lab. A large customer
  would need an indexed store (OpenSearch/ClickHouse); the schema is what we keep.
- Retention decides by the date in folder names (UTC), never by file times.
