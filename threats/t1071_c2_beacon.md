# T1071.001 — C2 Beaconing over HTTPS

An infected internal host is periodically calling home to attacker
infrastructure — the "beacon" pattern characteristic of Cobalt Strike,
Sliver, Mythic, Brute Ratel, and most modern post-exploitation frameworks.
The hallmarks are *regularity* (consistent interval, often with jitter),
*small payload sizes* (the beacon polls, it doesn't exfiltrate), and a
*singular destination* (one C2 IP, not a CDN).

A naive "outbound to suspicious IP" rule will be drowned in noise from
content delivery networks, software telemetry, and OS update checks. The
Architect must reason about *statistical regularity over a time window*,
not just volume.

Characteristics to detect:

- One internal `src_ip` makes ≥ 10 outbound `cs:network` connections to a
  single external `dest_ip` over a 1-hour window
- Each connection's `bytes_out` is small (< 5 KB) — beacons poll, they
  do not exfiltrate at this stage
- The inter-connection interval is *suspiciously regular* — standard
  deviation of gaps ≤ 30 seconds (most operator profiles use 30s–5min
  intervals with 10–20% jitter)
- `dest_port` is typically 443 (HTTPS) but can be 80, 53, or any TCP port
  the operator configured

MITRE ATT&CK:
- T1071.001 — Application Layer Protocol: Web Protocols
- T1573 — Encrypted Channel
- T1095 — Non-Application Layer Protocol (when not HTTP/HTTPS)
- T1029 — Scheduled Transfer (the interval is *itself* the indicator)

Data sources needed: `cs:network` (src_ip, dest_ip, dest_port, bytes_out,
_time, protocol).

References:
- https://attack.mitre.org/techniques/T1071/001/
- https://www.mandiant.com/resources/blog/defining-cobalt-strike-components
- https://research.splunk.com/network/cobalt_strike_named_pipes/
