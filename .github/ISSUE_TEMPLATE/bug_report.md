---
name: Bug Report
about: Create a report to help us improve Lanforge
title: '[BUG] '
labels: ['bug']
assignees: ''
---

**Describe the Bug**
A clear and concise description of what the bug is.

**Affected Subsystem**
- [ ] DHCP (v4 / v6)
- [ ] IPv6 Router Advertisements (RA / SLAAC)
- [ ] DNS Resolver / Adblocker
- [ ] Firewall / NAT / Port Forwarding
- [ ] PPPoE WAN Client
- [ ] Traffic Shaping (SQM / CAKE)
- [ ] Discovery / WoL / TFTP
- [ ] WebUI / HTTP API
- [ ] CLI (`lanforge`)

**Environment Details**
- **Hardware / Architecture**: (e.g., x86_64 Mini PC, Raspberry Pi 4, NanoPi R4S)
- **Linux Distribution & Kernel**: (e.g., Fedora Server 41, Linux 6.12)
- **Lanforge Version / Commit**: (e.g., `lanforge --version` or git commit SHA)
- **Network Interfaces**: (e.g., `eth0` LAN, `ppp0` WAN, VLANs)

**To Reproduce**
Steps to reproduce the behavior:
1. Configure `...`
2. Run command `...`
3. Observe error `...`

**Expected Behavior**
A clear and concise description of what you expected to happen.

**Relevant Logs / Diagnostic Output**
```text
# Output from: journalctl -u lanforge -n 50 --no-pager
# Or: lanforge status
```

**Additional Context**
Add any other context about the problem here.
