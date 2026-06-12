Counterspell — autonomous detection engineer for Splunk
========================================================

This app exposes Counterspell inside Splunk:

  • Custom search command:  | counterspell threat="<path-or-url>"
  • Dashboard:              Apps -> Counterspell -> Counterspell Console

Prerequisites
-------------
The custom command is a thin wrapper around the Counterspell Python runtime.
The runtime must be installed and reachable from $SPLUNK_HOME/bin/python3:

  1. pip install -r requirements.txt   (from the Counterspell repo root)
  2. Set COUNTERSPELL_HOME to the repo root, OR install the package:
       pip install -e /path/to/counterspell

  3. Provide credentials via environment variables on the splunkd process
     (SPLUNK_TOKEN, SPLUNK_HEC_TOKEN, MCP_TOKEN, LLM_BASE_URL, LLM_API_KEY).
     The easiest path is exporting them in $SPLUNK_HOME/etc/splunk-launch.conf.

Usage
-----
From the search bar:

    | counterspell threat="threats/t1048_exfil.md"
    | counterspell threat_text="An attacker is performing brute force..."
    | counterspell threat="threats/t1110_bruteforce.md" auto_approve=true

The command streams progress rows (one per stage) and ends with a summary
row containing the deployed saved-search name and the FP curve.

Safety
------
The default mode requires human approval before any saved search is written.
Pass auto_approve=true only in trusted automation contexts.
