# T1003.001 — LSASS Memory Credential Dumping

An attacker is reading the memory of `lsass.exe` — the Local Security
Authority Subsystem Service — to extract cached credentials, NTLM hashes,
and Kerberos tickets. This is the single most common credential-access
technique in real-world intrusions; it is performed by Mimikatz, ProcDump,
`comsvcs.dll`'s MiniDump export, Cobalt Strike's `hashdump`, and dozens
of custom-built tools.

Detection requires watching for processes that *access* LSASS rather than
*are* LSASS. The high-signal indicators are unusual parent processes
spawning known dumping utilities, or `rundll32.exe` invoking
`comsvcs.dll`'s MiniDump ordinal (#24) — a classic "no extra binary
needed" technique.

Characteristics to detect:

- `cs:process` event where `cmdline` contains any of:
  `lsass`, `comsvcs.dll, MiniDump`, `procdump -ma lsass`,
  `sekurlsa::`, `mimikatz`, `lsadump::`
- OR `process_name` is `procdump.exe` and `cmdline` references `lsass`
- OR `process_name` is `rundll32.exe` and `cmdline` contains
  `comsvcs.dll, #24` or `comsvcs.dll, MiniDump`
- Parent process is *not* a legitimate sysadmin tool — exclude
  signed Sysinternals binaries with known parents, EDR agents
- Bonus signal: the dumping process is followed by an outbound
  `cs:network` event from the same `host` within 5 minutes
  (operator collecting the dump)

MITRE ATT&CK:
- T1003.001 — OS Credential Dumping: LSASS Memory
- T1003 — OS Credential Dumping (parent)
- T1059 — Command and Scripting Interpreter (when PowerShell variant)

Data sources needed: `cs:process` (process_name, parent_process, cmdline,
user, host, _time).

References:
- https://attack.mitre.org/techniques/T1003/001/
- https://research.splunk.com/endpoint/credential_dumping_via_comsvcs_dll/
- https://github.com/gentilkiwi/mimikatz
