# export_sysmon_kv.ps1 - exports Sysmon events 1,3,10,11,13,22 as key="value" lines.
$dir   = "C:\SysmonExport"
$out   = Join-Path $dir "sysmon_kv.log"
$state = Join-Path $dir "sysmon_kv_last.txt"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$last = 0
if (Test-Path $state) { $last = [int64](Get-Content $state -Raw) }

$ids = "EventID=1 or EventID=3 or EventID=10 or EventID=11 or EventID=13 or EventID=22"
if ($last -eq 0) {
    $xpath = "*[System[($ids) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
} else {
    $xpath = "*[System[($ids) and EventRecordID>$last]]"
}

$events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath $xpath -ErrorAction SilentlyContinue |
          Sort-Object RecordId

$keys = 'RuleName','ProcessId','Image','CommandLine','ParentImage','ParentCommandLine',
        'User','LogonId','IntegrityLevel','Hashes','DestinationIp','DestinationPort',
        'Initiated','SourceImage','TargetImage','GrantedAccess','TargetFilename',
        'TargetObject','Details','QueryName','QueryResults'
$max = $last

foreach ($e in $events) {
    if ($e.RecordId -gt $max) { $max = $e.RecordId }
    $xml = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    $ts = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd\THH:mm:ss.fff\Z',
          [Globalization.CultureInfo]::InvariantCulture)
    $line = "$ts EventID=$($e.Id) RecordId=$($e.RecordId)"
    foreach ($k in $keys) {
        if ($d[$k] -and $d[$k] -ne '-') {
            # quotes -> ', CR/LF -> space, so each event stays on one line
            $v = ([string]$d[$k]) -replace '"', "'" -replace "[\r\n]+", ' '
            $line += " $k=`"$v`""
        }
    }
    Add-Content -Path $out -Value $line -Encoding ASCII
}
Set-Content -Path $state -Value $max
