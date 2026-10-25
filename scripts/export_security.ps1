# export_security.ps1 - exports Windows Security events 4624/4625/4720 as key="value" lines.
# Uses EventRecordID + a state file so each event is exported exactly once.
$dir   = "C:\SecExport"
$out   = Join-Path $dir "security_events.log"
$state = Join-Path $dir "last_record.txt"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$last = 0
if (Test-Path $state) { $last = [int64](Get-Content $state -Raw) }

$ids = "EventID=4624 or EventID=4625 or EventID=4720"
if ($last -eq 0) {
    # first run: last 24 hours only
    $xpath = "*[System[($ids) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
} else {
    $xpath = "*[System[($ids) and EventRecordID>$last]]"
}

$events = Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue |
          Sort-Object RecordId

$keys = 'TargetUserName','TargetDomainName','TargetLogonId','LogonType','IpAddress',
        'WorkstationName','Status','SubStatus','SubjectUserName','LogonProcessName'
$max = $last

foreach ($e in $events) {
    if ($e.RecordId -gt $max) { $max = $e.RecordId }
    $xml = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    # drop noisy 4624 logons for machine/system accounts
    if ($e.Id -eq 4624) {
        $u = $d['TargetUserName']
        if ($u -match '\$$' -or ($u -in 'SYSTEM','LOCAL SERVICE','NETWORK SERVICE') -or
            $u -like 'DWM-*' -or $u -like 'UMFD-*') { continue }
    }

    # UTC ISO timestamp; Splunk reads it with TZ = UTC
    $ts = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd\THH:mm:ss.fff\Z',
          [Globalization.CultureInfo]::InvariantCulture)
    $line = "$ts EventID=$($e.Id) RecordId=$($e.RecordId)"
    foreach ($k in $keys) {
        if ($d[$k] -and $d[$k] -ne '-') {
            $v = ([string]$d[$k]) -replace '"', "'"
            $line += " $k=`"$v`""
        }
    }
    Add-Content -Path $out -Value $line -Encoding ASCII
}
Set-Content -Path $state -Value $max
