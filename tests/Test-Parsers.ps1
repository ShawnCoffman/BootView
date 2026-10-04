# Synthetic test for the parsers that need elevation or an Intune-managed device, plus the report / history plumbing.
# Field names follow the providers' manifests.
# Run: powershell -File tests/Test-Parsers.ps1   (and pwsh -File ... ) - expect "0 failure(s)".
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'read by the dot-sourced collector functions')]
param([string]$Script = (Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) 'Collect-BootData.ps1'))
$ErrorActionPreference = 'Stop'
# load the collector's functions + constants (everything before "main") without running it
$ast = [Management.Automation.Language.Parser]::ParseFile($Script, [ref]$null, [ref]$null)
$mainLine = ($ast.Extent.Text -split "`n" | Select-String -SimpleMatch '# ================================================================= main').LineNumber
$WindowMinutes = 15; $ScriptRoot = Split-Path $Script
$OutputDir = Join-Path $env:TEMP ('bvtest-out-' + [guid]::NewGuid().ToString('N')); $null = New-Item -ItemType Directory -Force $OutputDir
foreach ($st in $ast.EndBlock.Statements) {
    if ($st.Extent.StartLineNumber -ge $mainLine) { break }
    if ($st -is [Management.Automation.Language.FunctionDefinitionAst] -or $st -is [Management.Automation.Language.AssignmentStatementAst]) {
        if ($st.Extent.Text -match '^\$(ScriptRoot|OutputDir)') { continue }; . ([scriptblock]::Create($st.Extent.Text))
    }
}
$fail = 0
function Check($name, $cond) { if ($cond) { "  ok   $name" } else { "  FAIL $name"; $script:fail++ } }
function Ev($id, $t, $d, $act) { [pscustomobject]@{ Id = $id; T = [long]$t; Rec = [long]$t; Act = $act; Uid = $null; D = $d; Msg = $null; A = $null } }

$b0 = 1791119237089
"Group Policy (manifest field names)"
$a = '{11111111-2222-3333-4444-555555555555}'; $u = '{66666666-2222-3333-4444-555555555555}'
$gp = @(
    Ev 4000 ($b0 + 9000) @{ PolicyActivityId = $a; PrincipalSamName = 'CONTOSO\PC1$'; IsMachine = '1'; IsBackgroundProcessing = 'false'; IsAsyncProcessing = 'false'; ReasonForSyncProcessing = '2' } $a
    Ev 5326 ($b0 + 9100) @{ DCDiscoveryTimeInMilliSeconds = '312'; ErrorCode = '0' } $a
    Ev 5308 ($b0 + 9110) @{ DCName = '\\DC01.contoso.com'; DCIPAddress = '10.0.0.1' } $a
    Ev 5314 ($b0 + 9200) @{ BandwidthInkbps = '120000'; IsSlowLink = 'false'; ThresholdInkbps = '500' } $a
    Ev 5017 ($b0 + 9300) @{ OperationElaspedTimeInMilliSeconds = '47'; ErrorCode = '0'; OperationDescription = 'Making LDAP calls to connect and bind to Active Directory.'; Parameter = 'DC01.contoso.com' } $a
    Ev 5126 ($b0 + 9400) @{ NumberOfGPOsDownloaded = '3'; NumberOfGPOsApplicable = '3'; GPODownloadTimeElapsedInMilliseconds = '141' } $a
    Ev 5312 ($b0 + 9410) @{ DescriptionString = "Default Domain Policy`nWorkstations"; GPOInfoList = '<GPO ID="{31B2F340}"><Name>Default Domain Policy</Name></GPO><GPO ID="{AB}"><Name>Workstations</Name></GPO>' } $a
    Ev 5313 ($b0 + 9420) @{ DescriptionString = 'Old Kiosk'; GPOInfoList = '<GPO ID="{CD}"><Name>Old Kiosk</Name></GPO>' } $a
    Ev 4016 ($b0 + 9500) @{ CSEExtensionId = '{35378EAC}'; CSEExtensionName = 'Registry'; IsGPOListChanged = 'false'; ApplicableGPOList = '<GPO ID="{31B2F340}"><Name>Default Domain Policy</Name></GPO>' } $a
    Ev 5016 ($b0 + 9800) @{ CSEElaspedTimeInMilliSeconds = '300'; ErrorCode = '0'; CSEExtensionName = 'Registry'; CSEExtensionId = '{35378EAC}' } $a
    Ev 4016 ($b0 + 9810) @{ CSEExtensionId = '{C6DC5466}'; CSEExtensionName = 'Software Installation'; IsGPOListChanged = 'true'; ApplicableGPOList = 'Workstations' } $a
    Ev 7016 ($b0 + 15810) @{ CSEElaspedTimeInMilliSeconds = '6000'; ErrorCode = '1274'; CSEExtensionName = 'Software Installation'; CSEExtensionId = '{C6DC5466}' } $a
    Ev 8000 ($b0 + 16000) @{ PolicyElaspedTimeInSeconds = '7'; ErrorCode = '0'; PrincipalSamName = 'CONTOSO\PC1$'; IsMachine = '1'; IsConnectivityFailure = 'false' } $a
    Ev 4001 ($b0 + 30000) @{ PolicyActivityId = $u; PrincipalSamName = 'CONTOSO\alice'; IsMachine = '0'; IsBackgroundProcessing = 'false'; IsAsyncProcessing = 'true' } $u
    Ev 4016 ($b0 + 30100) @{ CSEExtensionId = '{5794DAFD}'; CSEExtensionName = 'Scripts'; ApplicableGPOList = 'Logon Scripts' } $u
    Ev 6016 ($b0 + 32100) @{ CSEElaspedTimeInMilliSeconds = '2000'; ErrorCode = '0'; CSEExtensionName = 'Scripts'; CSEExtensionId = '{5794DAFD}' } $u
    Ev 8001 ($b0 + 32500) @{ PolicyElaspedTimeInSeconds = '2'; ErrorCode = '0'; PrincipalSamName = 'CONTOSO\alice'; IsMachine = '0' } $u
)
$sys = @(Ev 1502 ($b0 + 16010) @{ ProcessingTimeInMilliseconds = '7015'; ProcessingMode = '0'; DCName = '\\DC01'; NumberOfGroupPolicyObjects = '3' } $null)
$p = Build-Policy $gp $sys
Check 'two runs' (@($p.runs).Count -eq 2)
Check 'machine run is boot trigger' ($p.runs[0].scope -eq 'machine' -and $p.runs[0].trigger -eq 'boot')
Check 'user run is logon trigger' ($p.runs[1].scope -eq 'user' -and $p.runs[1].trigger -eq 'logon')
Check 'machine total 7000 ms from timestamps' ($p.machine.totalMs -eq 7000)
Check 'machine blocking (sync)' ($p.machine.blocking -eq $true)
Check 'user not blocking (async)' ($p.user.blocking -eq $false)
Check 'CSE ms parsed (misspelled field)' (($p.runs[0].extensions | Where-Object name -eq 'Registry').ms -eq 300)
Check 'CSE error result' (($p.runs[0].extensions | Where-Object name -eq 'Software Installation').result -eq 'error')
Check 'CSE warning result' ($p.runs[1].extensions[0].result -eq 'warning')
Check 'CSE GPO list from XML' (($p.runs[0].extensions | Where-Object name -eq 'Registry').gpos[0] -eq 'Default Domain Policy')
Check 'applied GPOs' ((@($p.runs[0].gpos) -join ',') -eq 'Default Domain Policy,Workstations')
Check 'filtered GPOs' ($p.runs[0].filteredGpos[0] -eq 'Old Kiosk')
Check 'DC discovery ms' ($p.runs[0].dcDiscoveryMs -eq 312)
Check 'LDAP call ms' ($p.runs[0].calls[0].ms -eq 47)
Check 'GPO list download ms' ($p.runs[0].gpoListMs -eq 141)
Check 'system 1502 parsed' ($p.system[0].ms -eq 7015 -and $p.system[0].scope -eq 'machine' -and $p.system[0].gpos -eq 3)
Check 'principal kept as-is without -Anonymize' ($p.runs[1].principal -eq 'CONTOSO\alice')

"Group Policy failures on a localised OS (scope from the event's SID, not the message text)"
$sysF = @(
    (Ev 1058 ($b0 + 9000) @{ ErrorDescription = 'Zugriff verweigert'; ErrorCode = '5' } $null)
    (Ev 1058 ($b0 + 31000) @{ ErrorDescription = 'Zugriff verweigert'; ErrorCode = '5' } $null)
)
$sysF[0].Uid = 'S-1-5-18'; $sysF[1].Uid = 'S-1-5-21-1-2-3-1001'
$pf2 = Build-Policy @() $sysF
Check 'SYSTEM failure = machine, user-SID failure = user' ($pf2.system[0].scope -eq 'machine' -and $pf2.system[1].scope -eq 'user' -and -not $pf2.system[0].ok)

"Diagnostics-Performance (manifest field names)"
$perfRows = @(
    Ev 100 ($b0 + 180000) @{ BootStartTime = '2026-10-04T13:07:16.5000000Z'; BootEndTime = '2026-10-04T13:08:30.1230000Z'; BootTime = '40123'; MainPathBootTime = '20111'; BootPostBootTime = '20012'; UserLogonWaitDuration = '3000'; BootPNPInitStartTimeMS = '400'; BootPNPInitDuration = '900'; BootIsDegradation = 'true' } $null
    Ev 103 ($b0 + 180000) @{ StartTime = '2026-10-04T13:07:16.5000000Z'; Name = 'svc.exe'; FriendlyName = 'Slow Service'; TotalTime = '5000'; DegradationTime = '4000'; Path = 'C:\x\svc.exe' } $null
    Ev 107 ($b0 + 180000) @{ StartTime = '2026-10-04T13:07:16.5000000Z'; Name = 'Group Policy'; TotalTime = '9000'; DegradationTime = '6000' } $null
    Ev 109 ($b0 + 180000) @{ StartTime = '2026-10-04T13:07:16.5000000Z'; Name = 'disk.sys'; FriendlyName = 'NVMe'; TotalTime = '800'; DegradationTime = '500' } $null
)
foreach ($r in $perfRows) { if ($r.Id -eq 100) { $r.A = (ConvertFrom-IsoTime $r.D['BootStartTime']) + 5000 } }
Get-NearestAnchor $perfRows @(100) @(101, 102, 103, 104, 105, 106, 107, 108, 109, 110)
$bk = Split-ByBoot $perfRows @([long]$b0, [long]($b0 + 120000))
Check '100 attributed to its boot, not the later one' ($bk[0].Count -eq 4)
$pf = Build-Perf $bk[0] $b0
Check 'perf headline fields' ($pf.bootTimeMs -eq 40123 -and $pf.mainPathMs -eq 20111 -and $pf.logonWaitMs -eq 3000)
Check 'perf offset (trace zero vs event 12)' ($pf.offsetMs -eq -589)
Check 'perf boolean flags' ($pf.flags['BootIsDegradation'] -eq $true)
$dg = @(Build-Degraders $bk[0] @(101, 102, 103, 104, 105, 106, 107, 108, 109, 110))
Check 'degrader kinds (107 = machine policy, 109 = device)' (($dg | Where-Object kind -eq 'machine policy').degradationMs -eq 6000 -and ($dg | Where-Object kind -eq 'device').name -eq 'NVMe')

"Winlogon + derived phases"
$wl = @(
    Ev 811 ($b0 + 8000) @{ Event = '0'; SubscriberName = 'GPClient' } $null; Ev 812 ($b0 + 16100) @{ Event = '0'; SubscriberName = 'GPClient' } $null
    Ev 811 ($b0 + 16100) @{ Event = '0'; SubscriberName = 'TermSrv' } $null; Ev 812 ($b0 + 16200) @{ Event = '0'; SubscriberName = 'TermSrv' } $null
    Ev 1 ($b0 + 20000) @{} $null; Ev 2 ($b0 + 20500) @{ Win32Status = '0' } $null
    Ev 811 ($b0 + 21000) @{ Event = '2'; SubscriberName = 'Profiles' } $null; Ev 812 ($b0 + 23000) @{ Event = '2'; SubscriberName = 'Profiles' } $null
    Ev 811 ($b0 + 23000) @{ Event = '2'; SubscriberName = 'GPClient' } $null; Ev 812 ($b0 + 26000) @{ Event = '2'; SubscriberName = 'GPClient' } $null
)
$prof = @(Ev 1 ($b0 + 21000) @{ Session = '1' } $null; Ev 2 ($b0 + 23000) @{ Session = '1' } $null)
$shell = @(Ev 62170 ($b0 + 26500) @{ TaskName = 'AllLogonTasks' } $null; Ev 62171 ($b0 + 30000) @{ TaskName = 'AllLogonTasks' } $null)
$boot = [pscustomobject]@{ id = $b0; bootStartMs = $b0; firmware = [pscustomobject]@{ firmwareMs = 9000; loaderMs = 1000 }; perf = $pf
    policy = $p; winlogon = @(Build-Winlogon $wl); logon = (Build-Logon -Shell $shell -ProfRows $prof -Auth $wl); network = $null; mdm = $null; phases = @(); totals = $null }
$d = Add-Derived $boot
$keys = ($d.phases | ForEach-Object { "$($_.key)=$($_.durMs)" }) -join ' '
"  phases: $keys"
Check 'winlogon event names' (($boot.winlogon | Where-Object subscriber -eq 'Profiles').eventName -eq 'Logon')
Check 'machine policy blocking = GPClient Startup (8.1 s)' ($d.totals.machinePolicyMs -eq 8100)
Check 'user policy blocking = GPClient Logon (3 s)' ($d.totals.userPolicyMs -eq 3000)
Check 'sign-in wait from Winlogon startup end' ($d.totals.signInWaitMs -eq 3800)
Check 'core boot to sign-in screen' ($d.totals.coreBootMs -eq 16200)
Check 'ready excl. wait' ($d.totals.readyExclWaitMs -eq 26200)
Check 'power-on to ready' ($d.totals.powerOnToReadyMs -eq 36200)
Check 'phase sum = power-on to ready + wait' ((($d.phases | Measure-Object durMs -Sum).Sum) -eq 40000)

"Multiple sign-ins per boot (shared device)"
$prof2 = @(Ev 1 ($b0 + 21000) @{} $null; Ev 2 ($b0 + 23000) @{} $null; Ev 1 ($b0 + 90000) @{} $null; Ev 2 ($b0 + 91500) @{} $null)
$prof2[0].Uid = 'S-1-5-21-1-2-3-1001'; $prof2[1].Uid = 'S-1-5-21-1-2-3-1001'; $prof2[2].Uid = 'S-1-5-21-1-2-3-1002'; $prof2[3].Uid = 'S-1-5-21-1-2-3-1002'
$lg2 = Build-Logon -Shell @() -ProfRows $prof2 -Auth @()
Check 'two sessions, first one is the primary profile' ($lg2.sessionCount -eq 2 -and $lg2.sessions[1].durMs -eq 1500 -and $lg2.profile.durMs -eq 2000)
Check 'session SID kept without -Anonymize' ($lg2.sessions[0].sid -eq 'S-1-5-21-1-2-3-1001' -and $lg2.user.sid -eq 'S-1-5-21-1-2-3-1001')

"-Anonymize"
$Anonymize = $true
$lg3 = Build-Logon -Shell @() -ProfRows $prof2 -Auth @()
Check 'no SIDs when anonymised' ($null -eq $lg3.sessions[0].sid -and $null -eq $lg3.user.sid)
$h1 = Protect-Name 'CONTOSO\Alice'
Check 'name hash is stable, case-insensitive and distinct' ($h1 -eq (Protect-Name 'contoso\alice') -and $h1 -like 'user-????????????' -and $h1 -ne (Protect-Name 'CONTOSO\Bob'))
Check 'hashing twice is a no-op' ((Protect-Name $h1) -eq $h1)
Check 'profile folder scrubbed from text' ((Limit-Text 'C:\Users\alice\AppData\Local\x.exe /q') -eq 'C:\Users\~\AppData\Local\x.exe /q')
$sr = Build-ShutdownReason @(Ev 1074 ($b0 + 5000) @{ param1 = 'C:\Windows\explorer.exe (PC1)'; param7 = 'CONTOSO\alice' } $null)
Check 'shutdown requester hashed' ($sr.user -like 'user-*' -and $sr.process -eq 'C:\Windows\explorer.exe')
$oldRec = [pscustomobject]@{ logon = [pscustomobject]@{ user = [pscustomobject]@{ name = 'CONTOSO\bob'; sid = 'S-1-5-21-9' }; sessions = @(); startupApps = @([pscustomobject]@{ command = 'C:\Users\bob\run.exe' }) }
    policy = [pscustomobject]@{ runs = @([pscustomobject]@{ principal = 'CONTOSO\bob' }) }; shutdownReason = $null; degraders = @() }
Protect-Boot $oldRec
Check 'earlier history records scrubbed too' ($oldRec.logon.user.name -like 'user-*' -and $null -eq $oldRec.logon.user.sid -and $oldRec.logon.startupApps[0].command -eq 'C:\Users\~\run.exe' -and $oldRec.policy.runs[0].principal -like 'user-*')
$Anonymize = $false
Check 'names untouched again without -Anonymize' ((Protect-Name 'CONTOSO\Alice') -eq 'CONTOSO\Alice')

"MDM (Sync 208/209, Admin 813/814/404)"
$mdm = @(
    Ev 208 ($b0 + 60000) @{ Message1 = 'ENR-1'; Message2 = 'MS DM Server' } $null
    Ev 813 ($b0 + 61000) @{ Message1 = 'AllowRealtimeMonitoring'; Message2 = 'Defender'; Message4 = 'device'; HexInt1 = '0x1' } $null
    Ev 814 ($b0 + 61500) @{ Message1 = 'HomePages'; Message2 = 'Browser'; Message4 = 'S-1-12-1'; Message5 = 'https://contoso' } $null
    Ev 404 ($b0 + 62000) @{ Message3 = './Device/Vendor/MSFT/Policy'; Message5 = 'Config/X'; HexInt1 = '0x82B00006' } $null
    Ev 209 ($b0 + 64000) @{ HRESULT = '0x0' } $null
    Ev 813 ($b0 + 200000) @{ Message1 = 'X'; Message2 = 'Update'; Message4 = 'device'; HexInt1 = '0x2' } $null
)
$m = Build-Mdm $mdm
Check 'one session 4 s ok' (@($m.sessions).Count -eq 1 -and $m.sessions[0].durMs -eq 4000 -and $m.sessions[0].ok)
Check 'policy values/scope' ($m.policies[0].value -eq '1' -and $m.policies[1].scope -eq 'user' -and $m.policies[1].value -eq 'https://contoso')
Check 'two bursts' (@($m.bursts).Count -eq 2 -and $m.bursts[0].count -eq 2)
Check 'error text' ($m.errors[0].text -like '*Policy Config/X' -and $m.errors[0].result -eq '0x82B00006')

"IME logs (CMTrace format)"
$tmp = Join-Path $env:TEMP ('bvtest' + [guid]::NewGuid().ToString('N')); $logs = Join-Path $tmp 'Microsoft\IntuneManagementExtension\Logs'
$null = New-Item -ItemType Directory -Force $logs
$dt = [DateTimeOffset]::FromUnixTimeMilliseconds($b0 + 70000).LocalDateTime
function L($sec, $msg, $thread = 7, $type = 1) { $t = $dt.AddSeconds($sec); '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="IntuneManagementExtension" context="" type="{3}" thread="{4}" file="">' -f $msg, $t.ToString('HH:mm:ss.fffffff'), $t.ToString('M-d-yyyy'), $type, $thread }
@(
    (L 0 '[PowerShell] Processing policy with id = 0c8f6a2e-1111-2222-3333-444455556666 for user 6b9b0000-1111-2222-3333-444455556666')
    (L 3 "[PowerShell] multi`nline message")
    (L 9 '[PowerShell] User Id = 6b9b, Policy id = 0c8f, policy result = Success')
    (L 2 "[Win32App] ExecManager: processing targeted app (name='7-Zip', id='aaaaaaaa-1111-2222-3333-444455556666') with intent=3" 9)
    (L 40 '[Win32App] download failed' 9 3)
) -join "`r`n" | Set-Content -Encoding UTF8 (Join-Path $logs 'IntuneManagementExtension.log')
$savedProgramData = $env:ProgramData
$env:ProgramData = $tmp
$rows = @(Read-ImeLogs -Since ([datetime]::Now.AddDays(-3650)))
$ime = Build-Ime $rows
$env:ProgramData = $savedProgramData
Remove-Item -Recurse -Force $tmp
Check 'parsed 5 lines incl. multi-line' ($rows.Count -eq 5)
Check 'line times are local -> epoch' ($rows[0].T -eq $b0 + 70000)
$sc = $ime.units | Where-Object kind -eq 'script'; $wa = $ime.units | Where-Object kind -eq 'win32app'
Check 'script unit 9 s, result Success' ($sc.durMs -eq 9000 -and $sc.result -eq 'Success')
Check 'win32 app unit named, 38 s, 1 error' ($wa.name -eq '7-Zip' -and $wa.durMs -eq 38000 -and $wa.errors -eq 1)
Check 'error summary' ($ime.errors[0].text -eq '[Win32App] download failed')

"History round trip and merge (5.1 serialises empty pipelines as {})"
$back = (ConvertTo-Json -InputObject $boot -Depth 32 -Compress) | ConvertFrom-Json
Repair-EmptyObjects $back
Check 'nulls survive the round trip' ($null -eq $back.network -and $null -eq $back.mdm -and $null -eq $back.logon.user.name)
$fresh = [pscustomobject]@{ id = $b0; bootStartMs = $b0; firmware = $null; perf = $null; policy = $null; winlogon = @()
    logon = [pscustomobject]@{ auth = $null; profile = $null; allTasks = $null; tasks = @() }; network = $null; mdm = $null; phases = @(); totals = $null }
$mg = Merge-Boot $fresh $back
Check 'empty sections filled from history' ($mg.firmware.firmwareMs -eq 9000 -and @($mg.winlogon).Count -gt 0 -and $mg.policy.machine.totalMs -eq 7000)
Check 'logon merged one level deep' ($mg.logon.allTasks.durMs -eq 3500 -and $mg.logon.auth.durMs -eq 500 -and $mg.logon.sessionCount -eq 1)
$md = Add-Derived $mg
Check 'derived totals rebuilt after the merge' ($md.totals.powerOnToReadyMs -eq 36200 -and $md.totals.machinePolicyMs -eq 8100)

"Report embedding (PowerShell 7's ConvertTo-Json does not escape '<')"
$rp = Write-Report (ConvertTo-Json -Compress -InputObject @{ boots = @(@{ cmd = '</script><img src=x onerror=alert(1)><!--' }) })
$html = [IO.File]::ReadAllText($rp)
Check 'data cannot close the script block' (([regex]::Matches($html, '(?i)</script')).Count -eq 2 -and -not $html.Contains('<img src=x') -and -not $html.Contains('<!--'))
$embedded = (($html -split 'id="bootview-data" type="application/json">', 2)[1] -split '</script>', 2)[0]
Check 'embedded JSON still parses to the same text' (($embedded | ConvertFrom-Json).boots[0].cmd -eq '</script><img src=x onerror=alert(1)><!--')
Check 'report written atomically (no temp file left behind)' (-not (Test-Path "$rp.tmp"))
Write-FileAtomic (Join-Path $OutputDir 'a.json') '{"v":1}'
Write-FileAtomic (Join-Path $OutputDir 'a.json') '{"v":2}'
Check 'atomic write replaces an existing file' (([IO.File]::ReadAllText((Join-Path $OutputDir 'a.json'))) -eq '{"v":2}')
Remove-Item -Recurse -Force $OutputDir

"PS $($PSVersionTable.PSVersion): $fail failure(s)"
if ($fail) { exit 1 }
