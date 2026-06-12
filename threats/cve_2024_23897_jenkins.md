# CVE-2024-23897 — Jenkins CLI Arbitrary File Read (post-exploitation)

A critical vulnerability in Jenkins' built-in CLI command parser
(versions ≤ 2.441 and LTS ≤ 2.426.2) allows an unauthenticated attacker
to read arbitrary files on the Jenkins controller by abusing the
`expandAtFiles` feature with crafted CLI arguments. Active exploitation
began within days of the January 2024 disclosure; the file-read primitive
is commonly chained into full RCE via exfiltration of Jenkins SSH keys,
`secrets.key`, agent join secrets, and stored credentials.

This detection focuses on observable post-exploitation indicators in the
Counterspell data model — the process invocations Jenkins generates while
serving these CLI requests, and the suspicious authentication patterns
that follow successful credential theft.

Characteristics to detect:

- `cs:process` events from a Jenkins controller host (`host` matches
  `jenkins*`, `build*`, or known build-server hostnames) where
  `process_name=java` and `cmdline` contains `jenkins-cli` or
  `-jar cli` referencing arguments starting with `@`
- Followed within 5 minutes by EITHER:
  - A `cs:auth` event from a *new* `src_ip` succeeding as a service
    account (e.g., `svc_jenkins`, `svc_build`, `svc_deploy`); OR
  - A `cs:network` event from the Jenkins host outbound to an external
    `dest_ip` with `bytes_out > 100 KB` (likely exfil of stolen keys)
- Optional: a spike in failed `cs:auth` events as the attacker tries
  stolen credentials against downstream systems

MITRE ATT&CK:
- T1190 — Exploit Public-Facing Application
- T1078 — Valid Accounts (post-credential-theft)
- T1083 — File and Directory Discovery
- T1552.001 — Unsecured Credentials: Credentials In Files

Data sources needed: `cs:process` (Jenkins host activity), `cs:auth`
(post-exploitation logins), and `cs:network` (exfiltration leg).

References:
- https://nvd.nist.gov/vuln/detail/CVE-2024-23897
- https://www.jenkins.io/security/advisory/2024-01-24/
- https://github.com/h4x0r-dz/CVE-2024-23897
