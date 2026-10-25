# Scheduled tasks on the VM (run once in an elevated PowerShell)
schtasks /create /tn "SecExport" /sc minute /mo 1 /ru SYSTEM /f /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\export_security.ps1"
schtasks /create /tn "SysmonKV"  /sc minute /mo 1 /ru SYSTEM /f /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\export_sysmon_kv.ps1"

# Laptop-on-battery fix. By default scheduled tasks refuse to start on battery
# (result 0x8007042B) and silently stop exporting.
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Set-ScheduledTask -TaskName "SecExport" -Settings $s
Set-ScheduledTask -TaskName "SysmonKV"  -Settings $s

# Audit policy so Security events exist at all
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
