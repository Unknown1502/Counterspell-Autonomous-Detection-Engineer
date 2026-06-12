# T1059.001 — Encoded PowerShell Command Execution

An attacker is invoking PowerShell with `-EncodedCommand` (or `-enc`) and a
base64-encoded payload — a well-known Living-off-the-Land technique used by
Cobalt Strike, Empire, Sliver, and most commodity malware to evade naive
command-line monitoring.

Encoded commands are not inherently malicious — admin scripts and Microsoft
deployment frameworks use them — but the COMBINATION of an encoded payload,
an interactive user host, and an unusual parent process is a high-signal
indicator. The detection must distinguish legitimate automation from suspect
invocations without drowning in benign DSC/SCCM noise.

Characteristics to detect:

- `cs:process` event where `process_name` is `powershell.exe` or `pwsh.exe`
- `cmdline` contains `-EncodedCommand`, `-enc`, or `-e ` followed by a long
  base64 string (≥ 50 characters of `A-Za-z0-9+/=`)
- Parent process is **not** a known automation tool — exclude
  `taskeng.exe`, `services.exe`, SCCM agents (`ccmexec.exe`),
  `winrm`, `chocolatey.exe`
- Bonus signal: same `host` shows outbound `cs:network` activity within
  60 seconds of the PowerShell event (the callback)

MITRE ATT&CK:
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027 — Obfuscated Files or Information
- T1140 — Deobfuscate/Decode Files or Information

Data sources needed: `cs:process` (process_name, parent_process, cmdline,
user, host, _time). Optional: `cs:network` for the post-execution callback
correlation.

References:
- https://attack.mitre.org/techniques/T1059/001/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a
- https://github.com/PowerShellMafia/PowerSploit
