# T1486 — Ransomware Detonation Burst (encryption + double-extortion exfil)

A ransomware payload has executed on an endpoint and entered its
encryption/exfiltration phase. The highest-signal indicators are
*temporally clustered process spawning* (the encryptor binary, shadow-copy
deletion utilities, service-stop commands all fire within seconds) and
*outbound volume to attacker infrastructure* (modern double-extortion
ransomware exfiltrates before encrypting to retain leverage even if the
victim has working backups).

This is a time-critical detection — minutes between detection and
disconnection determine the blast radius. The challenge for the Architect
is distinguishing this from legitimate bulk operations (Veeam / Acronis
backups, MSP-orchestrated patch runs, system imaging, large software
compilations) that produce superficially similar process bursts.

Characteristics to detect:

- One `host` spawns ≥ 20 distinct child processes within a 60-second
  window in `cs:process`
- AND any of these high-signal `cmdline` patterns:
  - `vssadmin delete shadows`
  - `wmic shadowcopy delete`
  - `bcdedit /set {default} recoveryenabled No`
  - `wbadmin delete catalog`
  - `cipher /w:` against multiple drive letters
- OR the same `host` shows outbound `cs:network` to a single external
  `dest_ip` with cumulative `bytes_out > 50 MB` in the same 60-second
  window (the double-extortion exfiltration leg)
- Parent process is *not* a known backup or remote-management tool —
  exclude `Veeam`, `Acronis`, `wbengine.exe`, ConnectWise, Datto,
  Kaseya RMM agents

MITRE ATT&CK:
- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery
- T1489 — Service Stop
- T1041 — Exfiltration Over C2 Channel (the double-extortion leg)

Data sources needed: `cs:process` (process_name, parent_process, cmdline,
user, host, _time) and `cs:network` (src_ip, dest_ip, bytes_out, _time).

References:
- https://attack.mitre.org/techniques/T1486/
- https://www.cisa.gov/stopransomware
- https://www.mandiant.com/resources/blog/ransomware-protection-and-containment-strategies
