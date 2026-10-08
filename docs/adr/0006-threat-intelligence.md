# ADR 0006 — Threat intelligence: local matching against public feeds first

- **Status:** accepted
- **Date:** 2026-10-09

## Context
Cases and the dashboard can only say what an address *did* on our network,
not what the rest of the world knows about it. A known botnet server reached
from inside the LAN should stand out immediately, and a mass scanner should
fade into the background. The product also has to be sellable: feeds must
allow commercial use, and client addresses must not leak to third parties.

Options:
1. **Download public lists and match locally.**
2. **Query lookup services per IP**, such as AbuseIPDB, GreyNoise or
   VirusTotal. That gives richer answers, but it sends our traffic's addresses
   to a third party, is rate-limited, and VirusTotal's free tier forbids
   commercial use.
3. **A full threat-intel platform** such as MISP or OpenCTI next to Talon. It's
   powerful, but it's another large system to run, and it's overkill until
   there are several clients.

## Decision
1. **Option 1 now.** `backend/soc_intel.py` downloads feeds into two new
   SQLite tables, `ti_indicators` and `ti_feeds` (additive). It matches IPs and
   networks in memory. **No address ever leaves Core.**
2. **Feeds** (each can be switched off with `SOC_INTEL_FEEDS`):
   - abuse.ch Feodo Tracker (CC0);
   - Spamhaus DROP v4/v6 (free incl. commercial, with credit; one download a
     day, so only prod fetches it);
   - the Tor exit list;
   - blocklist.de (commercial terms unstated: review before selling);
   - ThreatFox (needs a free abuse.ch key).
3. **Feed content is untrusted.** Only values that parse as IP addresses or
   networks are kept, plus a short tag limited to a safe character set. An
   empty or broken download never wipes the previous list.
4. **Categories drive behaviour:**
   - *malicious*: botnet C2, malware, hijacked networks;
   - *suspicious*: reported attackers;
   - *info*: Tor exits.

   A new rule, `intel_match`, opens a case only for *allowed* traffic: critical
   for outbound to a malicious address, high for inbound from one, medium for
   inbound from a reported attacker, low for inbound from Tor. Blocked traffic
   from listed addresses is normal internet noise, so it is labelled but opens
   nothing.
5. **Claude gets the hits as evidence** (`threat_intel` in `<case_evidence>`).
   It is told to treat them as supporting data, not proof.
6. **Later, through the same table:** keyed lookups (AbuseIPDB, GreyNoise)
   only for addresses already in a case and cached; STIX/TAXII import for
   premium feeds (Blackwired) and client-supplied feeds; and cross-client
   sightings once tenants exist.

## Consequences
- Coverage is limited to what public lists know, and lists contain stale and
  shared addresses (CDNs, cloud IPs). That's why only *allowed* traffic opens
  cases, and why Claude is told the hits aren't proof.
- Two environments on one host share the feeds' rate limits; staging
  leaves Spamhaus out.
- The licence of every feed must be re-checked before the product is sold;
  `docs/SOC-INTEL.md` tracks it.
