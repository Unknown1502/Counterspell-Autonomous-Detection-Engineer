# T1110 — Brute Force

An adversary is performing a credential brute-force attack against internal
authentication systems. Characteristics:

- A single source IP generating many failed authentication attempts (>15 failures)
  within a 10-minute window
- Attempts targeting a single user account or rotating across multiple accounts
- Followed by a successful authentication from the same source IP within 30 minutes

MITRE ATT&CK: T1110 — Brute Force
Data sources needed: authentication logs (action, src_ip, user, _time)
