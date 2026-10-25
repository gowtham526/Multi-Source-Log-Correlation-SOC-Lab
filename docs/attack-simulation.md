# Attack Simulation (Lab Only)

All steps were run on my own Windows 11 Pro VM (`gowtham`), which has Sysmon installed. The "attacker" and "victim" are both me. Do not run this on a machine you do not own.

The steps come from the PowerShell history on the VM. Steps 5 to 7 ran inside a separate `labuser` command window, which has no PowerShell history, so those commands are **reconstructed from the Sysmon Event 1 / 13 / 22 records** that they generated.

## 1. Create the target account
```
net user labuser "<lab-password>" /add
```
Security Event **4720** (account created).

## 2. Brute-force simulation (5 failed logons)
```
1..5 | ForEach-Object { net use \\localhost\IPC$ /user:labuser "WrongPass$_" 2>&1 | Out-Null; Start-Sleep -Seconds 2 }
```
A different wrong password each time. Windows deduplicated three identical attempts into one event in my first try, so the password changes per attempt. Result: five Security Event **4625** (LogonType 3, NtLmSsp, SubStatus 0xc000006a = wrong password).

## 3. Successful logon
```
runas /user:labuser cmd.exe
```
Entering the correct password. Result: Security Event **4624**, LogonType 2.

## 4. A stand-in for Microsoft Word
```
Copy-Item "C:\Windows\System32\cmd.exe" "C:\Tools\WINWORD.EXE"
```
A renamed copy of `cmd.exe`, so "Office spawns PowerShell" can be tested without a real macro.

## 5. Encoded, hidden PowerShell (reconstructed from Sysmon Event 1)
```
C:\Tools\WINWORD.EXE /c powershell -nop -w hidden -enc dwBoAG8AYQBtAGkA
```
The encoded string is Base64 of UTF-16LE text and decodes to `whoami`. Sysmon logs two Event 1 records: `WINWORD.EXE` with parent `cmd.exe`, then `powershell.exe` with parent `WINWORD.EXE`.

## 6. Persistence (reconstructed from Sysmon Event 13)
A `reg.exe` write to `HKU\<labuser SID>\Software\Microsoft\Windows\CurrentVersion\Run`, value `SOCLabPersist`, data `C:\Tools\WINWORD.EXE`.

## 7. Suspicious-TLD DNS lookup (reconstructed from Sysmon Event 22)
A DNS lookup of `test.tk`. Sysmon recorded the process as `<unknown process>`.

## Practice runs
Before the final run I practised with a second account, `labtest`. Those events (24 October, and 25 October 01:06 local) are in the index too, but they do not trigger the detection. They have failures but no later success and no Sysmon activity.

## Cleanup
Delete `labuser` and its profile, which also removes the Run key.