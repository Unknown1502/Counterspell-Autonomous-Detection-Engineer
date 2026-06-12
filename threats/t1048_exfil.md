# T1048 — Exfiltration Over Alternative Protocol

An adversary has established a foothold on an internal workstation and is exfiltrating
sensitive data to an external IP address using large HTTP or DNS transfers on
non-standard ports. The transfers are designed to blend in with legitimate traffic but
are characterized by:

- A single internal IP sending unusually large volumes of outbound data (>500MB)
  within a short window (< 2 hours)
- Destination on a non-standard port (not 80 or 443)
- Multiple large transfers to the same external IP in quick succession

MITRE ATT&CK: T1048 — Exfiltration Over Alternative Protocol
Data sources needed: network telemetry (bytes_out, dest_port, src_ip, dest_ip)
