# End-to-end checks: runs the real collector against this machine's own event logs, with prepared history files in
# temporary output folders (the project's output folder is never touched). No elevation needed.
# Run: powershell -File tests/Test-Collector.ps1   (and pwsh -File ... ) - expect "0 failure(s)". Takes a minute or two.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$collector = Join-Path $repo 'Collect-BootData.ps1'
$exe = (Get-Process -Id $PID).Path                  # the same PowerShell (5.1 or 7) this test runs in
$utf8 = New-Object System.Text.UTF8Encoding($false)
$fail = 0
function Check($name, $cond) { if ($cond) { "  ok   $name" } else { "  FAIL $name"; $script:fail++ } }
function New-Dir { $d = Join-Path $env:TEMP ('bvcol-' + [guid]::NewGuid().ToString('N')); $null = New-Item -ItemType Directory -Force $d; $d }
function Save-Json($path, $obj) { [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $obj -Depth 32 -Compress), $utf8) }
function Read-Json($path) { [IO.File]::ReadAllText($path, $utf8) | ConvertFrom-Json }
function Invoke-Collector { param([string[]]$Arguments) $out = & $exe -NoProfile -ExecutionPolicy Bypass -File $collector @Arguments 2>&1; [pscustomobject]@{ code = $LASTEXITCODE; out = @($out | ForEach-Object { "$_" }) } }
function Get-EpochMs($d) { ([DateTimeOffset]$d).ToUnixTimeMilliseconds() }
function New-Boot($id) { [pscustomobject]@{ id = $id; bootStartMs = $id; shutdownMs = $null; logon = $null; policy = $null; winlogon = @(); issues = @(); phases = @(); totals = $null } }

$k12 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12 } -MaxEvents 2)
$cur = Get-EpochMs $k12[0].TimeCreated
$uptimeH = ((Get-Date) - $k12[0].TimeCreated).TotalHours

"Boot already running at the incremental cutoff (review 1, finding 3)"
if ($uptimeH -lt 0.1) { "  skip (needs a few minutes of uptime)" }
else {
    $d = New-Dir
    $b = New-Boot $cur
    $b.logon = [pscustomobject]@{ auth = [pscustomobject]@{ name = ''; startMs = $cur + 20000; endMs = $cur + 20500; durMs = 500; status = 0 }; user = [pscustomobject]@{ name = 'HISTORY-USER' }; sessions = @(); sessionCount = 0; tasks = @() }
    $boots = @($b, [pscustomobject]@{ id = 'garbage'; bootStartMs = 'x' })
    if ($k12.Count -gt 1) { $boots += New-Boot (Get-EpochMs $k12[1].TimeCreated) }
    # the previous run "collected" two days and 10 s after this boot started, so this run's window starts 10 s into the
    # boot: its start (event 12) is outside the window, its sign-in events are inside
    $cutMs = $cur + 10000
    Save-Json (Join-Path $d 'history.json') ([pscustomobject]@{ schema = 3; tool = 'BootView'; collectedMs = $cutMs + 2 * 86400000; fieldsSeen = [pscustomobject]@{ 'Fake/1' = @('X') }; boots = $boots })
    $profAfter = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-User Profile Service/Operational'; Id = 1; StartTime = [DateTimeOffset]::FromUnixTimeMilliseconds($cutMs).LocalDateTime } -ErrorAction SilentlyContinue).Count
    $r = Invoke-Collector @('-NoReport', '-OutputDir', $d)
    $h = Read-Json (Join-Path $d 'history.json'); $l = Read-Json (Join-Path $d 'latest.json')
    $rec = @($h.boots | Where-Object { $_.id -eq $cur })[0]
    Check 'run succeeded' ($r.code -eq 0)
    Check 'the running boot was re-read, not skipped (latest.json has it)' (@($l.boots | Where-Object { $_.id -eq $cur }).Count -eq 1)
    Check 'summary counts it as re-read, not new' ($r.out[-1] -match ' 0 new, 1 re-read;')
    Check "history's primary sign-in and user kept" ($rec.logon.auth.startMs -eq $cur + 20000 -and $rec.logon.user.name -eq 'HISTORY-USER')
    Check 'earlier boot kept, malformed record dropped' (@($h.boots).Count -eq ($boots.Count - 1) -and -not @($h.boots | Where-Object { $_.id -eq 'garbage' }).Count)
    Check 'malformed record reported in the log' ((Get-Content (Join-Path $d 'BootView.log') -Raw) -match 'Skipped 1 malformed')
    Check 'sign-ins after the cutoff reached the running boot (not dropped)' ($profAfter -eq 0 -or @($rec.logon.sessions).Count -ge 1)
    Check 'fieldsSeen from earlier runs kept' ($h.fieldsSeen.'Fake/1' -contains 'X')
    Check 'no temp file left behind' (-not @(Get-ChildItem $d -Filter '*.tmp').Count)
    Remove-Item -Recurse -Force $d
}

"Another device's history is not relabelled (review 1, finding 4)"
$d = New-Dir
$foreignId = Get-EpochMs ([datetime]'2020-01-01T08:00:00Z')
Save-Json (Join-Path $d 'history.json') ([pscustomobject]@{ schema = 3; tool = 'BootView'; collectedMs = $foreignId + 3600000
        device = [pscustomobject]@{ name = 'OTHER-PC'; deviceId = '00000000-0000-0000-0000-000000000000'; serial = 'NOT-THIS-ONE' }; boots = @(New-Boot $foreignId) })
$r = Invoke-Collector @('-NoReport', '-Days', '3', '-OutputDir', $d)
$h = Read-Json (Join-Path $d 'history.json')
Check 'run succeeded' ($r.code -eq 0)
Check "foreign boots not merged into this device's history" (-not @($h.boots | Where-Object { $_.id -eq $foreignId }).Count -and $h.device.name -eq $env:COMPUTERNAME)
Check 'foreign history moved aside, not deleted' (@(Get-ChildItem $d -Filter 'history.foreign-OTHER-PC-*.json').Count -eq 1)
# the same device (identity from the run just made) is accepted and runs incrementally
$r2 = Invoke-Collector @('-NoReport', '-Days', '3', '-OutputDir', $d)
Check 'own history accepted on the next run' ($r2.code -eq 0 -and @(Get-ChildItem $d -Filter 'history.foreign-*.json').Count -eq 1 -and (Get-Content (Join-Path $d 'BootView.log') -Raw) -match 'incremental')
Remove-Item -Recurse -Force $d

"-ReportOnly -Anonymize scrubs the report (review 1, finding 1)"
$d = New-Dir
$b = New-Boot $cur
$b.logon = [pscustomobject]@{ user = [pscustomobject]@{ name = 'CONTOSO\zedtest'; sid = 'S-1-5-21-5-6-7-1009' }; sessions = @([pscustomobject]@{ user = 'CONTOSO\zedtest'; sid = 'S-1-5-21-5-6-7-1009'; startMs = $cur + 1 }) }
$b.issues = @([pscustomobject]@{ t = $cur + 5; id = 7000; source = 'Service'; text = 'C:\Users\Zed Tester\a.exe failed for zedtest' })
Save-Json (Join-Path $d 'history.json') ([pscustomobject]@{ schema = 3; tool = 'BootView'; collectedMs = $cur; device = [pscustomobject]@{ name = 'PC' }; boots = @($b) })
$before = [IO.File]::ReadAllText((Join-Path $d 'history.json'), $utf8)
$r = Invoke-Collector @('-ReportOnly', '-OutputDir', $d)
$plain = [IO.File]::ReadAllText((Join-Path $d 'BootView-Report.html'), $utf8)
$r = Invoke-Collector @('-ReportOnly', '-Anonymize', '-OutputDir', $d)
$anon = [IO.File]::ReadAllText((Join-Path $d 'BootView-Report.html'), $utf8)
$anon = (($anon -split 'id="bootview-data" type="application/json">', 2)[1] -split '</script>', 2)[0]     # the embedded data only
Check 'without -Anonymize the report has the names (sanity)' ($plain -match 'zedtest')
Check 'with -Anonymize: no names, profile folders or SIDs in the report' ($r.code -eq 0 -and $anon -notmatch '(?i)zedtest|zed tester' -and $anon -notmatch 'S-1-5-21' -and $anon -match 'user-[0-9a-f]{12}')
Check 'history.json on disk left as it was' ([IO.File]::ReadAllText((Join-Path $d 'history.json'), $utf8) -eq $before)
Remove-Item -Recurse -Force $d

"-Anonymize on real collected history (privacy + run time)"
$real = Join-Path $repo 'output\history.json'
if (-not (Test-Path $real)) { '  skip (no output\history.json)' }
else {
    $d = New-Dir
    Copy-Item $real (Join-Path $d 'history.json')
    $rh = Read-Json $real
    $names = @($rh.boots | ForEach-Object { if ($_.logon -and $_.logon.user) { $_.logon.user.name } } | Where-Object { $_ -and $_ -notmatch '^user-[0-9a-f]{12}$' } | Sort-Object -Unique)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Collector @('-Anonymize', '-OutputDir', $d)
    $sw.Stop()
    $txt = [IO.File]::ReadAllText((Join-Path $d 'history.json'), $utf8) + [IO.File]::ReadAllText((Join-Path $d 'BootView-Report.html'), $utf8)
    $left = @($names | ForEach-Object { ($_ -split '\\')[-1] } | Where-Object { $_.Length -ge 3 -and $txt -match ('(?i)(?<![\w-])' + [regex]::Escape($_) + '(?![\w-])') })
    "  ($(@($rh.boots).Count) boots in history, $($names.Count) clear account name(s); anonymised run took $([math]::Round($sw.Elapsed.TotalSeconds, 1)) s)"
    Check 'run succeeded' ($r.code -eq 0)
    Check 'no account name, account SID or profile folder name left (history + report)' ($left.Count -eq 0 -and $txt -notmatch 'S-1-5-21-\d' -and $txt -notmatch '(?i)[\\/]+Users[\\/]+(?!~|Public|Default)[^\\/~"]')
    Remove-Item -Recurse -Force $d
}

"PS $($PSVersionTable.PSVersion): $fail failure(s)"
if ($fail) { exit 1 }
