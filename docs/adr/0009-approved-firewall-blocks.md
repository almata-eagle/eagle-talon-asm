# ADR 0009 — Response: time-limited FortiGate blocks, only on human approval

- **Status:** accepted
- **Date:** 2026-10-10
- **Amends:** ADR 0002 and ADR 0004 ("no actions yet"). This is the first, and only, action.

## Context
Talon detects, explains and now alerts, but nothing stops an attacker. A buyer
asks "what happens next?", and today the answer is "you log in to the
FortiGate yourself". Phase 1 of the sellable checklist calls for one response
action, safe enough to trust: block a hostile address for a while, with a
person deciding.

Options:
1. **Talon edits an address group that the operator's own deny policies use.**
   Talon never writes policies.
2. **Talon writes firewall policies itself.** That's more flexible, but a bug or
   a stolen token could open the network as easily as close it.
3. **FortiGate's external "threat feed" connector**, where the FortiGate pulls a
   list from Talon. That's good for bulk lists, but it refreshes on the
   FortiGate's schedule (minutes) and gives no per-block approval or undo trail.
4. **Fully automatic blocking**, with no person in the loop. Rejected: a spoofed
   or attacker-shaped log could make Talon cut off something that matters.

## Decision
1. **Option 1** (`backend/soc_response.py`).
   - A block adds an address object `talon-<ip>` (`talon-<env>-<ip>` outside prod)
     to the address group `SOC_FGT_BLOCK_GROUP` (default `TALON-BLOCK`). Undo or
     expiry removes the object again.
   - The FortiGate's deny policies refer to that group. The operator creates
     them once, by hand (docs/SOC-RESPONSE.md).
2. **A person approves every block** in the case view, with:
   - a name;
   - the approval code `SOC_RESPONSE_APPROVAL_CODE` (secrets.env). Five wrong codes lock it for 15 minutes.
   The code stands in for logins until Talon has them. Undo also needs the code.
3. **Claude never chooses.**
   - Triage options stay suggestions; no code path executes them.
   - The address to block must come from the case's own evidence (entity,
     sources, targets, samples) and is re-validated on the server.
4. **What can't be blocked:**
   - non-IPv4 addresses (for now);
   - private, loopback, link-local, multicast, reserved and documentation ranges;
   - CGNAT/Tailscale (100.64.0.0/10);
   - anything in `SOC_RESPONSE_PROTECT` (your own public IPs, DNS resolvers, partners);
   - any address listed in Known devices.
5. **Every block expires** after 1 h, 24 h, 7 d or 30 d. There is no permanent block.
   - A loop removes expired blocks every minute and retries any removal that fails.
   - Limits: `SOC_RESPONSE_MAX_ACTIVE` (200) active blocks, and
     `SOC_RESPONSE_MAX_PER_HOUR` (20) new blocks an hour.
6. **Modes:** `SOC_RESPONSE_MODE=off|dryrun|live`.
   - Compose default `off` (prod).
   - Staging starts in `dryrun`: approvals are recorded and nothing changes.
   - `live` only after the FortiGate check passes.
7. **Least privilege on the FortiGate.**
   - A REST API admin whose profile can only read and write firewall addresses
     (no policies, no system), trusted only from Core's address.
   - Its token lives in secrets.env.
   - TLS is checked against the FortiGate certificate's pinned SHA-256
     fingerprint (`SOC_FGT_FINGERPRINT`) or a CA file. It is never left unverified.
8. **Audit:**
   - Table `soc_actions` holds one row per block: who, when, why, the case, expiry, how it ended.
   - Table `soc_action_log` holds every step.
   - The FortiGate object's comment names the Talon action, case and approver.
   - Blocks, failures and undos are sent as alerts.
9. **A failed change is rolled back.** If adding to the group fails, the new
   address object is deleted, and the action is recorded as `failed`.

## Consequences
- **Kill switch:** `SOC_RESPONSE_MODE=off` and redeploy. No new blocks can be
  made, but existing ones still expire on time: the expiry loop runs in every
  mode, because removing a block is always safe. To clear the FortiGate at once,
  use **Blocks → Undo**, or remove the `talon-*` members by hand.
- **Prod and staging share one FortiGate.** They use separate object prefixes and
  only ever remove their own objects.
- **Not covered yet:** IPv6, blocking traffic to the FortiGate itself (a local-in
  policy is optional, see the guide), UniFi client isolation, and logins.
  Logins replace the approval code in the "Logins, tenants" phase.
