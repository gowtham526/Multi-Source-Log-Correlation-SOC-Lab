# Lessons Learned

Real problems hit while building this lab, and what each one taught me.

## 1. A literal `Z` is not a timezone (events 5.5 hours early)
**Symptom:** a lag check (`_indextime - _time`) showed ~385 minutes instead of about a minute.
**Cause:** `TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ` treats `Z` as a plain character. Splunk assumed local time (IST), so every event was placed 5h30m early.
**Fix:** `TZ = UTC` in props.conf, then restart Splunk.
**Takeaway:** always sanity-check timestamps. Wrong timestamps would have broken the "failures THEN success" ordering that this whole detection depends on.

## 2. Scheduled tasks stopped silently on battery
**Symptom:** no new events; task `LastTaskResult` was `0x8007042B`.
**Cause:** tasks refuse to start on battery by default, and the laptop was unplugged.
**Fix:** `New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries`.
**Takeaway:** a log pipeline that dies quietly is worse than none, because it looks like "no attacks". The state file meant nothing was lost and the export caught up.

## 3. Forwarder could not reach Splunk (bridged Wi-Fi)
**Symptom:** `blocked_seconds` warnings, 0 events, "unreachable network".
**Cause:** the host IP changed on a phone hotspot, and the VM lost its DHCP lease.
**Fix:** added a second VirtualBox **Host-only** adapter with static addresses (host 192.168.56.1, VM 192.168.56.10), pointed outputs.conf at it, and allowed inbound 9997 in the firewall.
**Takeaway:** troubleshoot in layers: IP, route, port, then service. Pinning a lab network beats chasing DHCP.

## 4. One export attempt only logged one failure
**Symptom:** 3 identical `net use` attempts produced one 4625.
**Fix:** a different wrong password each attempt produced 5 events.
**Takeaway:** know how the log source behaves before building a threshold on it.

## 5. Duplicates and a clean export design
The first Sysmon export re-wrote events and created duplicates (thousands of repeated events). The rewrite uses `EventRecordID` plus a state file, and a `stats count by RecordId | where count>1` check returns nothing.

## 6. Username must be normalized to correlate
Security logs `labuser`; Sysmon logs `GOWTHAM\labuser`. A shared `user` field (lowercased, domain stripped) is what lets one search group both sources. A Microsoft-account login also appears as an email address, so such values had to be filtered out of evidence.

## 7. Detection tuning notes
- Several Sysmon rules fired on normal activity (Windows Update, Edge updater, my own network tests).
- The `-enc` rule also matched a wrapper command line, so tuning would be needed in production.
- Stronger design: correlate on `LogonId` (verified identical between 4624 and Sysmon Event 1 here).

## 8. Know your license
Splunk Free has no alerting. I found this only when the Alert option was missing. Saved a Report and documented the intended alert in `savedsearches.conf`, and said so in the README instead of implying it was deployed.