# SOC response: approved FortiGate blocks

From a case, you can block a hostile address on the FortiGate for a fixed time.
Talon only does it after you approve it with the approval code, and it removes
the block by itself when the time is up. The decision record is
[ADR 0009](adr/0009-approved-firewall-blocks.md).

## How it works
1. Open a case. **Response** lists the outside addresses from that case's
   evidence, each with its threat-intel badge.
2. Click **Block…** on one. Choose how long (1 h, 24 h, 7 d or 30 d), type your
   name and the approval code, and check the reason. The form says exactly what
   will change on the FortiGate.
3. **Approve and block.**
   - Talon adds the address object `talon-<ip>` to the group `TALON-BLOCK`.
   - Your deny policies on that group then drop the traffic.
   - You get an alert saying it's done.
4. The block ends on its own at the chosen time. **Undo** ends it sooner (it
   also needs the code).
5. **Blocks** in the Cases toolbar lists every block (active, expired, undone,
   failed) and has **Check FortiGate connection**.

Some addresses are never offered for blocking:
- your own network and devices;
- Tailscale and other CGNAT addresses;
- anything on your protected list (your own public IPs, DNS resolvers, partners);
- any address named in Known devices.

Claude's suggested options are only advice. Talon never acts on them by itself.

## Modes
| `SOC_RESPONSE_MODE` | What happens |
|---|---|
| `off` (prod default) | No blocking. Existing blocks still expire on time. |
| `dryrun` (staging default) | Approvals are recorded and alerted. The FortiGate is not touched. Use it to practise. |
| `live` | Approved blocks change the FortiGate. |

## One-time FortiGate setup
You do this once, by hand. Talon never creates or edits policies.

1. **A placeholder and the block group.** FortiOS doesn't allow an empty group,
   so the group starts with a harmless placeholder: 192.0.2.255 is a
   documentation address that never appears on the internet.
   - *Policy & Objects → Addresses → Create new → Address*: name `talon-placeholder`,
     type Subnet, `192.0.2.255/32`.
   - *Create new → Address group*: name `TALON-BLOCK`, member `talon-placeholder`.
2. **Two deny policies that use the group, at the top of the policy list.**
   - *Policy & Objects → Firewall Policy → Create new*: name `Talon block out`.
     Incoming = your LAN interfaces, Outgoing = your WAN interface. Source `all`,
     Destination `TALON-BLOCK`, Service `ALL`, Action **DENY**, Log violation traffic on.
   - Create a second one, `Talon block in`. Incoming = WAN, Outgoing = LAN,
     Source `TALON-BLOCK`, Destination `all`, Action **DENY**, logging on.
   - Drag both above every other policy.
   - Optional: to also block traffic to the FortiGate itself (SSL VPN, admin
     login), add a local-in policy on the WAN interface with source `TALON-BLOCK`
     and action deny (CLI below).
3. **A limited admin profile.** *System → Admin Profiles → Create new*: name
   `talon-block`.
   - Everything **None**, except *Firewall → Custom → Address: Read/Write*.
   - Policy, Service, Schedule and all other groups stay **None**.
4. **A REST API admin.** *System → Administrators → Create new → REST API Admin*:
   name `talon`, profile `talon-block`, PKI off.
   - **Trusted hosts:** Core's LAN address only (`<core-ip>/32`).
   - Copy the API key it shows. It is shown only once.
5. **On Core, put the settings in the checkout's `deploy/secrets.env`:**
   - `SOC_FGT_HOST=<fortigate-ip>:<admin-https-port>`
   - `SOC_FGT_TOKEN=<api key>`
   - `SOC_FGT_FINGERPRINT=<sha256 fingerprint>` (see below)
   - `SOC_RESPONSE_APPROVAL_CODE=<a phrase you'll remember, not your password>`
   - `SOC_RESPONSE_PROTECT=<your public IP>, 1.1.1.1, 8.8.8.8` (comma-separated IPs or networks)
6. **Get the fingerprint** of the FortiGate's admin certificate, from Core:
   `openssl s_client -connect <fortigate-ip>:<port> </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256`
   Copy the part after `=`. Talon refuses to connect if the certificate changes.
   If you replace the certificate, update the fingerprint.
7. Redeploy. In Talon, go to **Cases → Blocks → Check FortiGate connection**. It
   should say the group has 1 member (the placeholder).
8. Switch staging from `dryrun` to `live` (`deploy/env/staging.env`), redeploy,
   and do one test block and undo on a harmless address that appears in a case.

The same steps from the FortiGate CLI (replace `wan1`, `internal` and the IP):
```
config firewall address
    edit "talon-placeholder"
        set subnet 192.0.2.255 255.255.255.255
        set comment "Keeps TALON-BLOCK non-empty (documentation address)"
    next
end
config firewall addrgrp
    edit "TALON-BLOCK"
        set member "talon-placeholder"
        set comment "Managed by Eagle Talon: do not add members by hand"
    next
end
config firewall local-in-policy
    edit 0
        set intf "wan1"
        set srcaddr "TALON-BLOCK"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action deny
    next
end
config system accprofile
    edit "talon-block"
        set fwgrp custom
        config fwgrp-permission
            set address read-write
        end
    next
end
config system api-user
    edit "talon"
        set accprofile "talon-block"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <core-ip> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key talon
```
Create the two deny policies in the GUI, so they're easy to place at the top.

## Settings
| Variable | Default | Meaning |
|---|---|---|
| `SOC_RESPONSE_MODE` | `off` | `off`, `dryrun` or `live` |
| `SOC_RESPONSE_APPROVAL_CODE` | — (secrets.env) | Needed to approve or undo a block. Five wrong tries lock it for 15 minutes |
| `SOC_RESPONSE_PROTECT` | — (secrets.env) | IPs or networks that can never be blocked |
| `SOC_RESPONSE_MAX_ACTIVE` | `200` | Most blocks active at once |
| `SOC_RESPONSE_MAX_PER_HOUR` | `20` | Most new blocks per hour |
| `SOC_FGT_HOST` | — (secrets.env) | FortiGate address and admin HTTPS port, e.g. `192.168.10.1:443` |
| `SOC_FGT_TOKEN` | — (secrets.env) | REST API admin key |
| `SOC_FGT_FINGERPRINT` | — (secrets.env) | SHA-256 fingerprint of the FortiGate's certificate (preferred) |
| `SOC_FGT_CA_FILE` | — | Or: a CA file to verify the certificate |
| `SOC_FGT_VDOM` | `root` | VDOM |
| `SOC_FGT_BLOCK_GROUP` | `TALON-BLOCK` | The address group the deny policies use |

Prod names its objects `talon-<ip>`; staging names them `talon-staging-<ip>`.
Both can share the one group, and each only removes its own objects.

## Kill switch
- Set `SOC_RESPONSE_MODE=off` and redeploy. No new blocks can be made, and
  existing ones still expire on time.
- To clear everything at once, use **Undo** on each line in **Blocks**, or delete
  the `talon-*` members from the group on the FortiGate.
- To cut Talon off completely, disable the `talon` REST API admin on the FortiGate.

## API
- `GET /api/soc/response`: mode, readiness, limits, active count.
- `POST /api/soc/response/check`: read-only test that reads the block group.
- `GET /api/soc/response/actions?status=`: every block, newest first.
- `GET /api/soc/cases/{id}/response`: addresses in the case that can be blocked, plus that case's blocks.
- `POST /api/soc/cases/{id}/block` `{ip, duration, approver, code, reason}`: approve and block.
- `POST /api/soc/response/actions/{id}/undo` `{by, code}`: remove a block.
