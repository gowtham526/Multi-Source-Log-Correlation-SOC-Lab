# Multi-Source Log Correlation - Mini SOC Lab

Correlating **Windows Security** and **Sysmon** logs in **Splunk** to detect a brute-force-then-compromise sequence that neither log source can prove alone.

> **Scope, stated honestly:** this is a *simulated* attack in my own lab VM, built to validate detection logic. It is not a real intrusion. A renamed copy of `cmd.exe` (`C:\Tools\WINWORD.EXE`) stands in for Word, so the "Office spawns PowerShell" rule could be tested without an actual macro.

## Why correlate?

| Source alone | What it shows | What it cannot tell you |
|---|---|---|
| Security log | 5 failed logons, then a success | Whether the attacker *did* anything |
| Sysmon | Encoded hidden PowerShell, a Run key, a `.tk` DNS lookup | Whether the account was just guessed |
| **Both, same user, in order** | Brute force -> access -> execution in ~1.3 minutes | - |

## Architecture

```
Windows 11 VM (victim)                                   Windows host
 Security log (4624/4625/4720) -> export_security.ps1 --+
 Sysmon log (1,3,10,11,13,22) -> export_sysmon_kv.ps1 --+-> Universal Forwarder
        (scheduled every minute, SYSTEM)                          |  TCP 9997 (Host-only 192.168.56.0/24)
                                                                  v
                                           Splunk Enterprise, index=sysmon_lab
                                           sourcetypes: winsec_export, sysmon_kv
                                                                  |
                                           correlation search -> saved Report
```

- Exports use `EventRecordID` plus a state file, so each event is written exactly once (no duplicates).
- Timestamps are ISO UTC; Splunk is told `TZ = UTC` (see lessons learned).
- Sysmon rules come from my [EDR lab config](https://github.com/gowtham526/Endpoint-Detection-and-Response-Lab).

## Simulated attack and timeline

All times UTC. (Splunk screenshots show IST, UTC+5:30.) The exact commands are in [docs/attack-simulation.md](docs/attack-simulation.md).

| Time (UTC) | Source | Event | Meaning |
|---|---|---|---|
| 10:05:19 | Security 4720 | Account `labuser` created by `katre` | Target account set up |
| 10:15:25 - 10:15:53 | Security 4625 x5 | LogonType 3, NtLmSsp, Status 0xc000006d / SubStatus 0xc000006a | Wrong-password guesses (`net use`, a different password each time) |
| 10:16:44 | Security 4624 | LogonType 2 (`seclogo`), LogonId `0x2eb25b4` | Successful logon after the failures |
| 10:17:13 | Sysmon 1 | `WINWORD.EXE` (parent `cmd.exe`) | Stand-in for Word, rule SOC_Process_Hunter |
| 10:17:13 | Sysmon 1 | `powershell.exe -nop -w hidden -enc ...`, parent `WINWORD.EXE` | Office-spawns-PowerShell, hidden and encoded |
| 10:17:13 | Sysmon 13 | `...\Run\SOCLabPersist` -> `C:\Tools\WINWORD.EXE` | Persistence, rule SOC_Persistence_Hunter |
| 10:17:15 | Sysmon 22 | DNS query `test.tk` | Suspicious-TLD lookup, rule SOC_DNS_Hunter |

The encoded payload decodes to `whoami`, a harmless stand-in.

Two independent keys link the sources:
1. **Username**, normalized into one `user` field (Security `TargetUserName` and Sysmon `User` after the backslash). The search uses this.
2. **LogonId**: the 4624 `TargetLogonId` equals the Sysmon `LogonId` on the process events (`0x2eb25b4`). This is a stronger key and a planned upgrade; the search does not use it yet.

## Detection logic

The correlation search ([detection/correlation-searches.spl](detection/correlation-searches.spl)) fires per user when ALL of these hold:

- at least 5 failed logons (4625)
- at least 1 successful logon (4624) **after** the last failure
- Sysmon activity **after** the successful logon
- Sysmon activity starts within 15 minutes of the last failure

Result on the lab data: `labuser`, 5 failures, 1 success, 4 Sysmon events, 3 rules fired, 1.3 min from last failure to first activity.

| File | Purpose |
|---|---|
| `detection/correlation-searches.spl` | Correlation search, timeline, lag check, duplicate check |
| `detection/savedsearches.conf` | Intended alert definition (**not deployed**, see limitations) |
| `detection/brute-force-then-execution.sigma.yml` | Vendor-neutral Sigma correlation (**untested**, see limitations) |

## MITRE ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Brute Force | T1110 | 5 x 4625 within 30 s |
| Valid Accounts | T1078 | 4624 for the same account after the failures |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Hidden, encoded PowerShell |
| Registry Run Keys / Startup Folder | T1547.001 | Sysmon 13 on `...\CurrentVersion\Run` |
| Application Layer Protocol: DNS | T1071.004 | Query to `test.tk` |

## Evidence

| # | Screenshot | Shows |
|---|---|---|
| 1 | `evidence/01-both-sources-indexed.png` | Both sourcetypes indexed in one index |
| 2 | `evidence/02-timestamp-fix.png` | 385-minute ingest lag (old events) vs ~1 minute after the fix |
| 3 | `evidence/03-attack-timeline.png` | The 11-event `labuser` story across both sources |
| 4 | `evidence/04-correlation-result.png` | Saved correlation Report returning `labuser` |
| 5 | `evidence/05-splunk-free-license.png` | Free license group, the reason there is no alert |
| 6 | `evidence/06-shared-user-field.png` | The normalized `user` field across both sources |
| 7 | `evidence/07-vm-environment-and-account.png` | Windows 11 Pro VM (`gowtham`) and the `labuser` target account |
| 8 | `evidence/08-vm-security-events.png` | Native Security log on the VM: 4720, 5 x 4625, 4624 |
| 9 | `evidence/09-vm-sysmon-events.png` | Native Sysmon log on the VM: Events 1, 1, 13, 22 for `labuser` |
| 10 | `evidence/10-vm-to-host-forwarding.png` | VM Host-only address 192.168.56.10 and established forwarder connection to 192.168.56.1:9997 |

Screenshots 7 to 9 were taken on the VM after the run, from its own event logs. They are not a live recording. VM-local times are IST (UTC+5:30).

## Limitations

- **No real alert.** Splunk Free has no alerting, so the search is a saved **Report**. `savedsearches.conf` documents the intended 5-minute scheduled alert but was never run.
- **Sigma rule is untested.** I wrote it to document the logic; I did not compile it with a backend. The SPL is the verified implementation.
- **Simulated attack, single run.** One lab account, one scenario. False-positive rates on real traffic are unknown.
- **Correlates on username**, so a shared or generic account name could cause false matches. LogonId would be tighter.
- Old events from the timestamp bug remain in the index (excluded by using recent time ranges).

## Repo layout

```
scripts/     export_security.ps1, export_sysmon_kv.ps1
configs/     props.conf, inputs.conf, outputs.conf, scheduled-tasks-and-audit.ps1
detection/   correlation-searches.spl, savedsearches.conf, brute-force-then-execution.sigma.yml
evidence/    screenshots
docs/        attack-simulation.md, lessons-learned.md
```

## Lessons learned

See [docs/lessons-learned.md](docs/lessons-learned.md): the timezone bug, silent scheduled-task failures, network instability, and Sysmon false positives.

## License

MIT