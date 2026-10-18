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
Check 'atomic write leaves no temp files' (@(Get-ChildItem $OutputDir -Filter '*.tmp').Count -eq 0)
# the run lock relies on a second exclusive open throwing an IOException that "catch [IO.IOException]" sees
$lk = [IO.File]::Open((Join-Path $OutputDir 'x.lock'), 'OpenOrCreate', 'ReadWrite', 'None'); $caught = $false
try { $null = [IO.File]::Open((Join-Path $OutputDir 'x.lock'), 'OpenOrCreate', 'ReadWrite', 'None') } catch [IO.IOException] { $caught = $true } finally { $lk.Dispose() }
Check 'second exclusive open of the lock file is caught as IOException' $caught

"-Anonymize: complete scrubbing (review 1, finding 1)"
$Anonymize = $true; $script:KnownNames = @{}; $script:KnownNamesRx = $null
Check 'a clear name that merely starts with user- is still hashed' ((Protect-Name 'user-alice') -ne 'user-alice' -and (Protect-Name 'user-alice') -match '^user-[0-9a-f]{12}$')
Check 'profile folder with a space' ((Protect-Path 'C:\Users\Alice Smith\App.exe') -eq 'C:\Users\~\App.exe')
Check 'profile folder at the end, arguments kept' ((Protect-Path 'C:\Users\alice /q') -eq 'C:\Users\~ /q' -and (Protect-Path '"C:\Users\Bob Jones\x.exe" /f /q') -eq '"C:\Users\~\x.exe" /f /q')
Check 'forward slashes and quotes' ((Protect-Path "'C:/Users/carol/a.ps1'") -eq "'C:/Users/~/a.ps1'")
Check 'no profile folder: text unchanged' ((Protect-Path 'C:\Windows\System32\svchost.exe -k netsvcs') -eq 'C:\Windows\System32\svchost.exe -k netsvcs')
$old2 = [pscustomobject]@{
    id = $b0; bootStartMs = $b0
    logon = [pscustomobject]@{ user = [pscustomobject]@{ name = 'CONTOSO\bob'; sid = 'S-1-5-21-9-8-7-1104' }; sessions = @([pscustomobject]@{ user = 'CONTOSO\bob'; sid = 'S-1-5-21-9-8-7-1104'; startMs = 1 }); startupApps = @() }
    policy = [pscustomobject]@{ runs = @([pscustomobject]@{ principal = 'CONTOSO\bob'; errors = @('Access denied for CONTOSO\bob') }); system = @([pscustomobject]@{ error = 'The processing of Group Policy failed for user bob.' }) }
    shutdownReason = [pscustomobject]@{ process = 'C:\Users\Alice Smith\AppData\tool.exe'; comment = 'restart requested by bob@contoso.com'; user = 'CONTOSO\bob' }
    issues = @([pscustomobject]@{ text = 'C:\Users\Alice\app.exe failed for S-1-5-21-9-8-7-1104' })
    mdm = [pscustomobject]@{ errors = @([pscustomobject]@{ text = 'Token for bob@contoso.com expired' }); policies = @([pscustomobject]@{ value = '\\server\home\bob' }) }
    degraders = @()
}
Register-BootNames $old2
Protect-Boot $old2
$j = ConvertTo-Json -InputObject $old2 -Depth 10 -Compress
Check 'old issue text: profile folder and SID scrubbed' ($old2.issues[0].text -eq 'C:\Users\~\app.exe failed for S-~')
Check 'shutdown process / comment scrubbed (path with space, UPN hashed)' ($old2.shutdownReason.process -eq 'C:\Users\~\AppData\tool.exe' -and $old2.shutdownReason.comment -match '^restart requested by user-[0-9a-f]{12}$')
Check 'known account name scrubbed from free text (DOMAIN\name and bare name)' ($old2.policy.runs[0].errors[0] -eq ('Access denied for ' + (Protect-Name 'CONTOSO\bob')) -and $old2.policy.system[0].error -notmatch '\bbob\b')
Check 'bare and qualified name map to the same hash' ($old2.policy.system[0].error -like ('*' + (Protect-Name 'CONTOSO\bob') + '*'))
Check 'no clear name, SID or UPN left anywhere in the record' ($j -notmatch '(?i)\bbob\b|alice|S-1-5-21|contoso\.com' -and $null -eq $old2.logon.sessions[0].sid -and $null -eq $old2.logon.user.sid)
Check 'scrubbing twice is a no-op' ((ConvertTo-Json -InputObject $(Protect-Boot $old2; $old2) -Depth 10 -Compress) -eq $j)
$Anonymize = $false; $script:KnownNames = @{}; $script:KnownNamesRx = $null

"History merge keeps partial re-reads (review 1, finding 2)"
$runA = [pscustomobject]@{ activityId = 'a'; scope = 'machine'; trigger = 'boot'; startMs = $b0 + 9000; endMs = $b0 + 16000; totalMs = 7000; complete = $true; errorCode = 0; blocking = $true; extensions = @() }
$runB = [pscustomobject]@{ activityId = 'b'; scope = 'user'; trigger = 'logon'; startMs = $b0 + 30000; endMs = $b0 + 32500; totalMs = 2500; complete = $true; errorCode = 0; blocking = $false; extensions = @() }
$runBpartial = [pscustomobject]@{ activityId = 'b'; scope = 'user'; trigger = 'logon'; startMs = $b0 + 31000; endMs = $b0 + 32500; totalMs = 1500; complete = $false; errorCode = $null; blocking = $false; extensions = @() }
$tA = [pscustomobject]@{ name = 'TaskA'; startMs = $b0 + 27000; endMs = $b0 + 28000; durMs = 1000 }
$tB = [pscustomobject]@{ name = 'TaskB'; startMs = $b0 + 27500; endMs = $b0 + 29500; durMs = 2000 }
$sess = { param($s) [pscustomobject]@{ sid = $null; user = 'u'; session = 1; startMs = $s; endMs = $s + 100; durMs = 100 } }
$oldB = [pscustomobject]@{ id = $b0; bootStartMs = $b0; winlogon = @(); issues = @([pscustomobject]@{ t = $b0 + 1; id = 7000; text = 'x' })
    policy = [pscustomobject]@{ machine = $null; user = $null; runs = @($runA, $runB); system = @() }
    logon = [pscustomobject]@{ auth = [pscustomobject]@{ startMs = $b0 + 20000; endMs = $b0 + 20500; durMs = 500 }; tasks = @($tA, $tB); sessions = @((& $sess ($b0 + 21000)), (& $sess ($b0 + 90000))); sessionCount = 2; failedAuth = 2 }
    mdm = [pscustomobject]@{ sessions = @(); policyCount = 300; policies = @([pscustomobject]@{ t = $b0 + 5; op = 'set'; policy = 'P1'; area = 'A'; scope = 'device' }); errors = @(); bursts = @(); areas = @([pscustomobject]@{ name = 'A'; count = 300 }) }
    phases = @(); totals = $null }
$newB = [pscustomobject]@{ id = $b0; bootStartMs = $b0; winlogon = @(); issues = @([pscustomobject]@{ t = $b0 + 2; id = 7001; text = 'y' })
    policy = [pscustomobject]@{ machine = $null; user = $null; runs = @($runBpartial); system = @() }
    logon = [pscustomobject]@{ auth = $null; tasks = @($tB); sessions = @((& $sess ($b0 + 90000))); sessionCount = 1; failedAuth = 0 }
    mdm = [pscustomobject]@{ sessions = @(); policyCount = 1; policies = @([pscustomobject]@{ t = $b0 + 6; op = 'set'; policy = 'P2'; area = 'A'; scope = 'device' }); errors = @(); bursts = @(); areas = @([pscustomobject]@{ name = 'A'; count = 1 }) }
    phases = @(); totals = $null }
$mb = Merge-Boot $newB $oldB
Check 'policy runs: old [a,b] + new [b] keeps both' ((@($mb.policy.runs | ForEach-Object activityId) -join ',') -eq 'a,b')
Check 'a complete record beats a partial re-read of it' ((@($mb.policy.runs) | Where-Object activityId -eq 'b').complete -eq $true)
Check 'policy summaries rebuilt from the merged runs' ($mb.policy.machine.totalMs -eq 7000 -and $mb.policy.user.totalMs -eq 2500)
Check 'logon tasks unioned' (@($mb.logon.tasks).Count -eq 2)
Check 'sessions unioned and sessionCount recomputed' (@($mb.logon.sessions).Count -eq 2 -and $mb.logon.sessionCount -eq 2)
Check 'auth filled from history' ($mb.logon.auth.durMs -eq 500)
Check 'counts keep the larger value' ($mb.logon.failedAuth -eq 2 -and $mb.mdm.policyCount -eq 300)
Check 'MDM settings and issues unioned' (@($mb.mdm.policies).Count -eq 2 -and @($mb.issues).Count -eq 2 -and @($mb.mdm.areas)[0].count -eq 300)
$capOld = [pscustomobject]@{ id = $b0; bootStartMs = $b0; logon = [pscustomobject]@{ tasks = @(1..40 | ForEach-Object { [pscustomobject]@{ name = "T$_"; startMs = $b0 + $_; endMs = $b0 + $_ + $_; durMs = $_ } }) } }
$capNew = [pscustomobject]@{ id = $b0; bootStartMs = $b0; logon = [pscustomobject]@{ tasks = @([pscustomobject]@{ name = 'Tbig'; startMs = $b0 + 1; endMs = $b0 + 99999; durMs = 99998 }) } }
$cm = Merge-Boot $capNew $capOld
Check 'cap applied after merging, longest kept' (@($cm.logon.tasks).Count -eq $TopTasks -and $cm.logon.tasks[0].name -eq 'Tbig')
$one = Merge-Boot ([pscustomobject]@{ id = $b0; bootStartMs = $b0; logon = [pscustomobject]@{ tasks = @($tA) } }) ([pscustomobject]@{ id = $b0; bootStartMs = $b0; logon = [pscustomobject]@{ tasks = @($tA) } })
Check 'merging the same record twice does not duplicate it (and a 1-item list stays a list)' (@($one.logon.tasks).Count -eq 1 -and $one.logon.tasks -is [array])

"Boot already running at the cutoff (review 1, finding 3)"
# rows after the cutoff (a later sign-in, the shutdown) land in the carried-over boot's bucket instead of being dropped
$carryRows = @((Ev 13 ($b0 + 500000) @{} $null), (Ev 1074 ($b0 + 499000) @{ param1 = 'C:\Windows\system32\shutdown.exe (PC1)' } $null), (Ev 12 ($b0 + 600000) @{} $null))
$bk2 = Split-ByBoot $carryRows @([long]$b0, [long]($b0 + 600000))
Check 'shutdown events after the cutoff go to the boot that was running' ($bk2[0].Count -eq 2 -and $bk2[1].Count -eq 1)
$hist = [pscustomobject]@{ id = $b0; bootStartMs = $b0; shutdownMs = $null; shutdownReason = $null; kernelStartMs = $b0 - 500
    logon = [pscustomobject]@{ auth = [pscustomobject]@{ startMs = $b0 + 20000; endMs = $b0 + 20500; durMs = 500 }; user = [pscustomobject]@{ name = 'primary' }; sessions = @((& $sess ($b0 + 21000))); sessionCount = 1 } }
$part = [pscustomobject]@{ id = $b0; bootStartMs = $b0; shutdownMs = $b0 + 500000; shutdownReason = [pscustomobject]@{ process = 'shutdown.exe' }; kernelStartMs = $null
    logon = [pscustomobject]@{ auth = [pscustomobject]@{ startMs = $b0 + 90000; endMs = $b0 + 90500; durMs = 500 }; user = [pscustomobject]@{ name = 'later' }; sessions = @((& $sess ($b0 + 90000))); sessionCount = 1 } }
$cb = Merge-Boot $hist $part        # the collector passes history first for a carried-over boot
Check 'carried-over boot keeps its primary sign-in and user' ($cb.logon.auth.startMs -eq $b0 + 20000 -and $cb.logon.user.name -eq 'primary' -and $cb.kernelStartMs -eq $b0 - 500)
Check 'carried-over boot gains its shutdown and the later session' ($cb.shutdownMs -eq $b0 + 500000 -and $cb.shutdownReason.process -eq 'shutdown.exe' -and $cb.logon.sessionCount -eq 2)

"Device identity (review 1, finding 4)"
$me = @{ name = 'PC1'; deviceId = 'g1'; serial = 's1' }
Check 'same MachineGuid + serial = same device, even renamed' (Test-SameDevice ([pscustomobject]@{ name = 'PC1-OLD'; deviceId = 'g1'; serial = 's1' }) $me)
Check 'same name, other MachineGuid = another device' (-not (Test-SameDevice ([pscustomobject]@{ name = 'PC1'; deviceId = 'g2'; serial = 's1' }) $me))
Check 'cloned MachineGuid, other serial = another device' (-not (Test-SameDevice ([pscustomobject]@{ name = 'PC1'; deviceId = 'g1'; serial = 's9' }) $me))
Check 'no IDs saved: falls back to the name' ((Test-SameDevice ([pscustomobject]@{ name = 'PC1' }) $me) -and -not (Test-SameDevice ([pscustomobject]@{ name = 'PC2' }) $me))
Check 'boot record shape check' ((Test-BootRecord ([pscustomobject]@{ id = [long]$b0; bootStartMs = [long]$b0 })) -and -not (Test-BootRecord ([pscustomobject]@{ id = 'x'; bootStartMs = [long]$b0 })) -and -not (Test-BootRecord ([pscustomobject]@{ id = 5; bootStartMs = 5 })))

"Unknown sign-in wait stays unknown (review 1, finding 5)"
$nw = [pscustomobject]@{ id = $b0; bootStartMs = $b0; firmware = [pscustomobject]@{ firmwareMs = 9000; loaderMs = 1000 }; perf = $null; policy = $null; winlogon = @(); network = $null; mdm = $null
    logon = [pscustomobject]@{ auth = [pscustomobject]@{ startMs = $b0 + 10000; endMs = $b0 + 10500; durMs = 500 }; profile = $null; allTasks = [pscustomobject]@{ startMs = $b0 + 11000; endMs = $b0 + 14000; durMs = 3000 } }; phases = @(); totals = $null }
$nd = Add-Derived $nw
Check 'no sign-in-screen evidence: wait, core boot and wait-excluded totals are unknown' ($null -eq $nd.totals.signInWaitMs -and $null -eq $nd.totals.coreBootMs -and $null -eq $nd.totals.readyExclWaitMs -and $null -eq $nd.totals.powerOnToReadyMs)
Check '... while measured values stay' ($nd.totals.readyMs -eq 14000 -and $nd.totals.toSignInMs -eq 10000 -and $nd.totals.signInToReadyMs -eq 4000)
$al = [pscustomobject]@{ id = $b0; bootStartMs = $b0; firmware = $null; perf = $null; policy = $null; network = $null; mdm = $null
    winlogon = @([pscustomobject]@{ event = 0; subscriber = 'TermSrv'; startMs = $b0 + 5000; endMs = $b0 + 10000; durMs = 5000 })
    logon = [pscustomobject]@{ auth = [pscustomobject]@{ startMs = $b0 + 10000; endMs = $b0 + 10500; durMs = 500 }; profile = $null; allTasks = [pscustomobject]@{ startMs = $b0 + 11000; endMs = $b0 + 14000; durMs = 3000 } }; phases = @(); totals = $null }
$ad = Add-Derived $al
Check 'auto sign-in (screen ready = authentication): wait is a measured 0' ($ad.totals.signInWaitMs -eq 0 -and $ad.totals.readyExclWaitMs -eq 14000 -and $ad.totals.coreBootMs -eq 10000)

"Sessions are not combined (review 1, finding 7)"
$uA = 'S-1-5-21-1-2-3-1001'; $uB = 'S-1-5-21-1-2-3-1002'
function EvU($id, $t, $d, $uid) { $e = Ev $id $t $d $null; $e.Uid = $uid; $e }
$auth7 = @((Ev 1 ($b0 + 20000) @{} $null), (Ev 2 ($b0 + 20500) @{ Win32Status = '0' } $null))
$prof7 = @((EvU 1 ($b0 + 21000) @{ Session = '1' } $uA), (EvU 1 ($b0 + 22000) @{ Session = '2' } $uB), (EvU 2 ($b0 + 22500) @{ Session = '2' } $uB), (EvU 2 ($b0 + 23000) @{ Session = '1' } $uA))
$shell7 = @((EvU 62170 ($b0 + 23100) @{ TaskName = 'AllLogonTasks' } $uB), (EvU 62170 ($b0 + 24000) @{ TaskName = 'AllLogonTasks' } $uA),
    (EvU 62171 ($b0 + 26000) @{ TaskName = 'AllLogonTasks' } $uB), (EvU 62171 ($b0 + 30000) @{ TaskName = 'AllLogonTasks' } $uA))
$lg7 = Build-Logon -Shell $shell7 -ProfRows $prof7 -Auth $auth7
Check 'overlapping sessions: profile paired per user + session' ($lg7.profile.durMs -eq 2000 -and @($lg7.sessions).Count -eq 2 -and ($lg7.sessions | Where-Object { $_.session -eq 2 }).durMs -eq 500)
Check "overlapping sessions: primary logon tasks are the primary user's" ($lg7.allTasks.startMs -eq $b0 + 24000 -and $lg7.allTasks.durMs -eq 6000)
Check 'pairs carry no SIDs into the record' (-not ($lg7.allTasks.PSObject.Properties['uid']) -and -not ($lg7.profile.PSObject.Properties['uid']))
$auth7b = @((Ev 1 ($b0 + 20000) @{} $null), (Ev 2 ($b0 + 20500) @{ Win32Status = '0' } $null), (Ev 1 ($b0 + 90000) @{} $null), (Ev 2 ($b0 + 90400) @{ Win32Status = '0' } $null))
$prof7b = @((EvU 1 ($b0 + 21000) @{ Session = '1' } $uA), (EvU 2 ($b0 + 23000) @{ Session = '1' } $uA), (EvU 1 ($b0 + 90500) @{ Session = '3' } $uA), (EvU 2 ($b0 + 91000) @{ Session = '3' } $uA))
$shell7b = @((EvU 62170 ($b0 + 91500) @{ TaskName = 'AllLogonTasks' } $uA), (EvU 62171 ($b0 + 95000) @{ TaskName = 'AllLogonTasks' } $uA))
$lg7b = Build-Logon -Shell $shell7b -ProfRows $prof7b -Auth $auth7b
Check "first session's tasks missing: the second session's are not borrowed" ($null -eq $lg7b.allTasks -and $lg7b.auth.startMs -eq $b0 + 20000 -and $lg7b.profile.startMs -eq $b0 + 21000)

"IME partial read (review 1, additional)"
$tmp2 = Join-Path $env:TEMP ('bvtest' + [guid]::NewGuid().ToString('N')); $logs2 = Join-Path $tmp2 'Microsoft\IntuneManagementExtension\Logs'
$null = New-Item -ItemType Directory -Force $logs2
(L 0 '[PowerShell] Processing policy with id = 0c8f6a2e-1111-2222-3333-444455556666 for user x') | Set-Content -Encoding UTF8 (Join-Path $logs2 'IntuneManagementExtension.log')
(L 1 'x') | Set-Content -Encoding UTF8 (Join-Path $logs2 'AgentExecutor.log')
$held = [IO.File]::Open((Join-Path $logs2 'AgentExecutor.log'), 'Open', 'Read', 'None')
$env:ProgramData = $tmp2
try { $null = @(Read-ImeLogs -Since ([datetime]::Now.AddDays(-3650))) } finally { $env:ProgramData = $savedProgramData; $held.Dispose() }
Remove-Item -Recurse -Force $tmp2
Check 'one unreadable IME log = partial, not ok' ($script:Sources['Intune Management Extension'].status -eq 'partial' -and $script:Sources['Intune Management Extension'].message -like '1 of 2*')
Remove-Item -Recurse -Force $OutputDir

"PS $($PSVersionTable.PSVersion): $fail failure(s)"
if ($fail) { exit 1 }
