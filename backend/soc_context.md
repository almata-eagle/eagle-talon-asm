# Network context for Claude triage (trusted, written by the operator)

Edit this file to describe the environment; it is sent with every triage.
Keep it short and factual. No passwords or keys.

- Owner: Almata K.K., a small Tokyo cybersecurity company. This is the
  owner's home lab, used as a proof of concept for a managed SOC service.
- Internet: NTT Hikari → FortiGate 60F (FortiOS 7.4), the router and firewall.
  The FortiGate's WAN address is the only public IP.
- LAN: 192.168.10.0/24. Gateway/FortiGate: 192.168.10.1.
  - 192.168.10.109 "Core": Debian server running Docker (Eagle Talon, Wazuh,
    Grafana/Prometheus, the SOC log collector) and a Tailscale subnet router.
  - 192.168.10.111: Synology NAS (file shares, backups).
  - Other addresses: laptops/phones, an "Edge" server, a Kali laptop used for
    authorised security testing, and a TP-Link access point.
- Switching: UniFi USW-Lite-8-PoE. A lab VLAN (30) is being set up.
- Remote access: Tailscale only (100.64.0.0/10). No port forwards are
  intended to be open from the internet; any allowed inbound connection to an
  internal host is unexpected unless explained here.
- Expected noise: constant blocked scans/probes from the internet; the
  FortiGate itself talking to FortiGuard services (updates, DNS over TLS).
