# T1078 — Impossible Travel: Authenticated Sessions from Disparate Geographies

A user account is authenticating successfully from two source IPs whose
geographic distance, divided by elapsed time, exceeds plausible human
travel speed (e.g., London → São Paulo in 20 minutes). This is the
canonical indicator of account compromise — either credential theft
followed by attacker use, or active session-token relay (Adversary-in-
the-Middle phishing via Evilginx and similar).

The detection must reason about *pairs* of auth events for the same user,
not single events. The synthetic data does not include a `country` field
on purpose — this forces the Architect to infer geography from IP
patterns (internal `10.0.x.x` vs external IPs, and within external IPs,
diversity in the first octet as a coarse proxy for distinct regions).

Characteristics to detect:

- Same `user` value appears in two or more successful `cs:auth` events
  (`action=success`)
- Within a 30-minute window
- From `src_ip` values that are clearly distinct (different /16 subnets
  is a usable proxy; first-octet difference is even stronger)
- At least one of the IPs is external (not in `10.0.0.0/8`,
  `172.16.0.0/12`, or `192.168.0.0/16`)
- Exclude service accounts and shared kiosk users (configurable via the
  Architect's `false_positive_notes`)

MITRE ATT&CK:
- T1078 — Valid Accounts
- T1078.004 — Cloud Accounts (most common context for impossible travel)
- T1110 — Brute Force (the common predecessor)
- T1539 — Steal Web Session Cookie (the AiTM variant)

Data sources needed: `cs:auth` (user, src_ip, action, app, _time, host).

References:
- https://attack.mitre.org/techniques/T1078/
- https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks
- https://attack.mitre.org/techniques/T1539/
