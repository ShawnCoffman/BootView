<#
.SYNOPSIS
    BootView collector: turns the boot / policy / sign-in timing Windows already records into per-boot JSON and an HTML report.

.DESCRIPTION
    Reads existing event logs and log files (nothing is installed or enabled) and builds one record per boot,
    from power-on to a usable desktop, plus the policy and management work that runs around it:

      System                                    Kernel-General 12/13   boot start / shutdown
                                                Kernel-Boot 20/27/30/32  previous shutdown status, boot type,
                                                                       firmware (POST) + boot-loader time, BitLocker PIN wait
                                                GroupPolicy 1500-1503, 10xx  policy result + total time (readable without admin)
                                                User32 1074            who / what started the shutdown or restart
                                                Service Control Manager 70xx  services that failed or timed out
                                                Kernel-Power 41, EventLog 6008  unexpected shutdowns
      Winlogon/Operational                      1 / 2                  authentication start / stop
                                                811 / 812              every Winlogon subscriber (GPClient, Profiles, ...) start / finish:
                                                                       what actually blocked startup and sign-in
      User Profile Service/Operational          1 / 2, 67              profile load start / finish, profile type
      Shell-Core/Operational                    62170 / 62171          every logon task, start / finish
                                                9648/9649, 9652/9653   shell phases;  9703/9704 RunOnce
                                                9705-9708, 62408/62409 startup apps (Run keys, packaged startup tasks)
      NetworkProfile/Operational                10000                  network connected (policy and Intune wait for it)
      AAD/Operational                           1097/1098/1104/108x    Entra ID token errors around sign-in
      DeviceManagement-Enterprise-Diagnostics   Sync 208/209           Intune (MDM) sync sessions
                                                Admin 813-819          every MDM policy setting applied
                                                Admin 404/454/821/1924 MDM policy / app failures
      Diagnostics-Performance/Operational  (*)  100                    Windows' own boot trace (kernel, PnP, sessions, sign-in wait, ...)
                                                101-110                what degraded boot (apps, drivers, services, devices, policy, ...)
                                                200-203                shutdown trace and what slowed it
      GroupPolicy/Operational              (*)  4000-4007 / 8000-8007  every policy run (boot, logon, background, ...)
                                                4016 / 5016/6016/7016  every client-side extension, with its GPO list
                                                5017/7017, 5126, 5257, 5326, 5314, 5312/5313  LDAP/SMB calls, download,
                                                                       DC discovery, link speed, applied / filtered GPOs
      Intune Management Extension logs     (*)  %ProgramData%\Microsoft\IntuneManagementExtension\Logs
                                                PowerShell scripts, remediations, Win32 apps (best-effort parsing)

      (*) Readable only from an elevated session (or as SYSTEM, e.g. through Intune). Without elevation the collector
          still runs and records those sources as "denied" so the report can say what is missing.

    Results are merged into history.json, so the record outlives event-log rollover. Times are Unix epoch
    milliseconds (UTC); durations are milliseconds.

    Compatible with Windows PowerShell 5.1 and PowerShell 7. Intune runs remediation / platform scripts in 32-bit
    Windows PowerShell 5.1 by default and without parameters: the collector relaunches itself as 64-bit, and when it
    runs as SYSTEM its default output folder is %ProgramData%\BootView.

.PARAMETER Days
    How far back to read the logs on this run. History from earlier runs is kept regardless.

.PARAMETER WindowMinutes
    How long after boot start, and after sign-in, background activity (policy refreshes, Intune syncs, IME work,
    service failures) is attributed to the boot.

.PARAMETER OutputDir
    Where history.json and BootView-Report.html are written.
    Default: an "output" folder next to this script; %ProgramData%\BootView when running as SYSTEM.

.PARAMETER NoReport
    Write JSON only (e.g. when running as an Intune remediation).

.PARAMETER ReportOnly
    Don't read logs; rebuild the HTML report from the existing history.json (e.g. after editing the viewer).

.PARAMETER Open
    Open the HTML report when finished.

.PARAMETER Anonymize
    Replace account names with a stable per-name hash and drop SIDs; profile folder names inside paths and commands
    become "~", and account names, account SIDs and e-mail addresses inside event messages, errors and comments are
    replaced too. Boots stay comparable without naming anyone. Earlier records in history.json are scrubbed as well;
    with -ReportOnly only the report is scrubbed. The hash is unsalted: this is pseudonymisation - a guessed name can be
    hashed and compared.

.PARAMETER FullRescan
    Re-read the full -Days window instead of only the logs written since the previous run (plus a 2-day overlap).

.OUTPUTS
    history.json (all boots), latest.json (this run's boots only), BootView-Report.html and BootView.log in OutputDir.
    The last line on stdout is a one-line summary ("BootView OK: ..." / "BootView FAILED: ..."), which Intune keeps
    in its script output. Exit code 0 = success, 1 = failure.

.EXAMPLE
    .\Collect-BootData.ps1 -Open

.EXAMPLE
    .\Collect-BootData.ps1 -NoReport -Anonymize     # Intune platform script / remediation detection script
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$Days = 60,
    [ValidateRange(1, 240)][int]$WindowMinutes = 15,
    [string]$OutputDir,
    [switch]$NoReport,
    [switch]$ReportOnly,
    [switch]$Open,
    [switch]$Anonymize,
    [switch]$FullRescan
)

# Intune runs scripts in 32-bit PowerShell by default. A 32-bit process sees the WOW6432Node registry and a
# redirected System32 (no dsregcmd), so relaunch as a native 64-bit process and pass the exit code through.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $native = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $native) {
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Path)
        foreach ($k in $PSBoundParameters.Keys) {
            $v = $PSBoundParameters[$k]
            if ($v -is [switch]) { if ($v.IsPresent) { $relaunch += "-$k" } } else { $relaunch += "-$k"; $relaunch += "$v" }
        }
        & $native @relaunch
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Stop'
# $PSScriptRoot is empty inside param() defaults on Windows PowerShell 5.1, so the default is resolved here
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$IsSystem = $false
try { $IsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18' } catch { }
if (-not $OutputDir) {
    # Intune deletes its script folder after a run, so SYSTEM runs keep their history in ProgramData
    $OutputDir = if ($IsSystem) { Join-Path $env:ProgramData 'BootView' } else { Join-Path $ScriptRoot 'output' }
}
$SchemaVersion = 3        # 3: device.serial / entraDeviceId / intuneDeviceId / tenantId / anonymized, logon.sessions, toolVersion
$ToolVersion = '1.2.0'
$MaxHistoryBoots = 365
$IncrementalOverlapDays = 2   # a later run re-reads this much before its predecessor's collection time
$WindowMs = [long]$WindowMinutes * 60000
$GapFoldMs = 150          # gaps shorter than this are folded into the next phase instead of drawn
$BlockingMinMs = 50       # a Winlogon GPClient notification shorter than this did not really block
$TopTasks = 30; $TopApps = 25; $TopExtensions = 30; $TopDegraders = 20; $TopSubscribers = 40
$TopMdmPolicies = 150; $TopMdmErrors = 30; $TopImeUnits = 60; $TopIssues = 30
$Inv = [Globalization.CultureInfo]::InvariantCulture

$script:Sources = [ordered]@{}
$script:FieldsSeen = @{}
$script:ImeStats = [ordered]@{}
$script:LogPath = $null
$script:AccountCache = @{}

# ---------------------------------------------------------------- logging, anonymisation, safe file writes

function Write-RunLog {
    # Console plus a small rolling log next to history.json, so a failed Intune run can be diagnosed on the device.
    param([string]$Text = '', [string]$Level = 'INFO', [switch]$NoConsole)
    if (-not $NoConsole) {
        switch ($Level) { 'WARN' { Write-Warning $Text } 'ERROR' { Write-Host $Text -ForegroundColor Red } default { Write-Host $Text } }
    }
    if ($script:LogPath -and $Text -ne '') {
        try { [IO.File]::AppendAllText($script:LogPath, ('{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Text) + [Environment]::NewLine) } catch { }
    }
}

function Initialize-Log {
    param([string]$Dir)
    try {
        $null = New-Item -ItemType Directory -Force -Path $Dir
        $path = Join-Path $Dir 'BootView.log'
        if ((Test-Path $path) -and (Get-Item $path).Length -gt 1MB) { Move-Item -LiteralPath $path -Destination "$path.1" -Force }
        $script:LogPath = $path
    } catch { Write-Warning "Cannot write a log in $Dir ($($_.Exception.Message))." }
}

function Write-FileAtomic {
    # Write to a temp file and swap it in, so a run killed mid-write (e.g. an Intune timeout) never leaves a half file.
    param([string]$Path, [string]$Text)
    # a unique temp name per write, so two runs never write into each other's temp file
    $tmp = '{0}.{1}.tmp' -f $Path, [guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

$NameHashRx = [regex]'^user-[0-9a-f]{12}$'

function Protect-Name {
    # -Anonymize: an account name becomes a stable hash ("user-3f9a..."), so boots stay comparable without naming anyone.
    # This is pseudonymisation, not anonymisation: the hash is unsalted, so anyone can hash a candidate name and compare.
    param([string]$Name, [switch]$NoRegister)
    if (-not $Name) { return $null }                     # a [string] parameter turns $null into '' - give the null back
    if (-not $Anonymize -or $NameHashRx.IsMatch($Name)) { return $Name }   # only an exact hash counts as already done
    if (-not $NoRegister) { Register-KnownName $Name }   # so free text that mentions the account is scrubbed as well
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name.Trim().ToLowerInvariant())) } finally { $sha.Dispose() }
    'user-' + [BitConverter]::ToString($h, 0, 6).Replace('-', '').ToLowerInvariant()
}

# C:\Users\<profile folder>: the folder name may contain spaces ("C:\Users\Alice Smith\App.exe"); when no path separator
# follows, it ends at the first space ("C:\Users\alice /q").
$ProfilePathRx = [regex]'(?i)([\\/](?:Users|Documents and Settings)[\\/])(?:[^\\/"'':*?<>|\r\n]*[^\\/"'':*?<>|\s](?=[\\/])|[^\\/"'':*?<>|\s]+)'
$SidRx = [regex]'(?i)\bS-1-(?:5-21|12-1)(?:-\d+){1,}'               # domain / local / Entra account SIDs
$EmailRx = [regex]'(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b'  # UPNs in Entra ID / MDM messages
$script:KnownNames = @{}                                             # lower-case variant -> hash
$script:KnownNamesRx = $null

function Protect-Path {
    # -Anonymize: profile folder names inside paths and commands (C:\Users\<name>\...) become "~".
    param([string]$Text)
    if (-not $Anonymize -or -not $Text) { return $Text }
    $ProfilePathRx.Replace($Text, '$1~')
}

function Register-KnownName {
    # -Anonymize: remember an account name so free text (event messages, errors, comments) that mentions it is scrubbed too.
    param([string]$Name)
    if (-not $Anonymize -or -not $Name -or $NameHashRx.IsMatch($Name)) { return }
    $n = $Name.Trim()
    if ($n -match '^(?i)(NT AUTHORITY|NT SERVICE|BUILTIN|Window Manager|Font Driver Host|IIS APPPOOL)\\' -or $n.EndsWith('$')) { return }
    $hash = Protect-Name $n -NoRegister
    $variants = @($n)
    if ($n -match '^[^\\]+\\(?<u>.+)$') { $variants += $Matches['u'] }   # DOMAIN\user -> also the bare user name
    foreach ($v in $variants) {
        if ($v.Length -lt 3) { continue }                                 # too short to replace safely in free text
        $k = $v.ToLowerInvariant()
        if (-not $script:KnownNames.ContainsKey($k)) { $script:KnownNames[$k] = $hash; $script:KnownNamesRx = $null }
    }
}

function Protect-Text {
    # -Anonymize for free text: profile folders, account SIDs, e-mail addresses / UPNs and every known account name.
    param([string]$Text)
    if (-not $Anonymize -or -not $Text -or $NameHashRx.IsMatch($Text)) { return $Text }
    $t = $ProfilePathRx.Replace($Text, '$1~')
    $t = $SidRx.Replace($t, 'S-~')
    $t = $EmailRx.Replace($t, [Text.RegularExpressions.MatchEvaluator] { param($m) Protect-Name $m.Value -NoRegister })
    if ($script:KnownNames.Count) {
        if (-not $script:KnownNamesRx) {
            # longest first, so "CONTOSO\alice" wins over "alice"
            $alt = ($script:KnownNames.Keys | Sort-Object Length -Descending | ForEach-Object { [regex]::Escape($_) }) -join '|'
            $script:KnownNamesRx = [regex]::new("(?<![\w-])(?:$alt)(?![\w-])", 'IgnoreCase')
        }
        $t = $script:KnownNamesRx.Replace($t, [Text.RegularExpressions.MatchEvaluator] { param($m) $script:KnownNames[$m.Value.ToLowerInvariant()] })
    }
    $t
}

function Resolve-Account {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    if (-not $script:AccountCache.ContainsKey($Sid)) {
        $n = $null
        try { $n = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
        $script:AccountCache[$Sid] = $n
        Register-KnownName $n
    }
    $script:AccountCache[$Sid]
}

function Register-BootNames {
    # -Anonymize: learn the clear account names an earlier, non-anonymised record holds, before they are hashed.
    param($Boot)
    if (-not $Anonymize -or -not $Boot) { return }
    $lg = $Boot.logon
    if ($lg) {
        if ($lg.user) { Register-KnownName $lg.user.name }
        foreach ($s in @($lg.sessions)) { if ($s) { Register-KnownName $s.user } }
    }
    if ($Boot.policy) { foreach ($r in @($Boot.policy.runs)) { if ($r) { Register-KnownName $r.principal } } }
    if ($Boot.shutdownReason) { Register-KnownName $Boot.shutdownReason.user }
}

function Protect-Value {
    # Recursive: every string in the record goes through Protect-Text, every "sid" property is dropped.
    param($Obj)
    if ($Obj -is [pscustomobject]) {
        foreach ($p in @($Obj.PSObject.Properties)) {
            $v = $p.Value
            if ($null -eq $v) { continue }
            if ($p.Name -eq 'sid') { $Obj.($p.Name) = $null }
            elseif ($v -is [string]) { $Obj.($p.Name) = Protect-Text $v }
            elseif ($v -is [array]) {
                for ($i = 0; $i -lt $v.Count; $i++) { if ($v[$i] -is [string]) { $v[$i] = Protect-Text $v[$i] } else { Protect-Value $v[$i] } }
            }
            elseif ($v -is [pscustomobject]) { Protect-Value $v }
        }
    }
    elseif ($Obj -is [array]) { foreach ($x in $Obj) { Protect-Value $x } }
}

function Protect-Boot {
    # -Anonymize, for every record (including earlier, non-anonymised ones): hash the account-name fields, drop SIDs,
    # and scrub every other string (event messages, errors, commands, paths, comments, policy values).
    param($Boot)
    if (-not $Anonymize -or -not $Boot) { return }
    $lg = $Boot.logon
    if ($lg) {
        if ($lg.user -and $lg.user.name) { $lg.user.name = Protect-Name $lg.user.name }
        foreach ($s in @($lg.sessions)) { if ($s -and $s.user) { $s.user = Protect-Name $s.user } }
    }
    if ($Boot.policy) { foreach ($r in @($Boot.policy.runs)) { if ($r -and $r.principal) { $r.principal = Protect-Name $r.principal } } }
    if ($Boot.shutdownReason -and $Boot.shutdownReason.user) { $Boot.shutdownReason.user = Protect-Name $Boot.shutdownReason.user }
    Protect-Value $Boot
}

# ---------------------------------------------------------------- helpers

function ConvertTo-EpochMs {
    param([datetime]$Date)
    ([DateTimeOffset]$Date).ToUnixTimeMilliseconds()
}

function ConvertFrom-IsoTime {
    # Event XML renders SYSTEMTIME / FILETIME fields as ISO-8601 UTC strings, sometimes with 9 fractional digits
    # (more than .NET parses) or invisible direction marks. Returns epoch ms, or $null.
    param([string]$Text)
    if (-not $Text) { return $null }
    $s = $Text.Replace([string][char]0x200E, '').Replace([string][char]0x200F, '')    # invisible direction marks
    $s = [regex]::Replace($s, '(\.\d{7})\d+', '$1')
    $dto = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal
    if ([DateTimeOffset]::TryParse($s, $Inv, $styles, [ref]$dto) -and $dto.Year -ge 2000) { return $dto.ToUnixTimeMilliseconds() }
    $null
}

function ConvertTo-Number {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -match '^0x[0-9a-fA-F]+$') { return [long][Convert]::ToInt64($s.Substring(2), 16) }
    $v = 0.0
    if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, $Inv, [ref]$v)) {
        # whole numbers as [long]: identical JSON from 5.1 and 7 (7 writes doubles as "1.0") and smaller files
        if ($v -eq [math]::Floor($v) -and [math]::Abs($v) -lt 9e15) { return [long]$v }
        return $v
    }
    $null
}

function ConvertTo-Bool {
    param($Value)
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if ($s -eq 'true' -or $s -eq '1') { return $true }
    if ($s -eq 'false' -or $s -eq '0') { return $false }
    $null
}

function Limit-Text {
    param([string]$Text, [int]$Max = 200)
    if (-not $Text) { return $Text }
    $t = Protect-Text (($Text -replace '\s+', ' ').Trim())
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 1) + [char]0x2026 }
    $t
}

function Get-First {
    # First non-empty value of the listed fields in an event row
    param($Row, [string[]]$Names)
    foreach ($n in $Names) { if ($Row.D.ContainsKey($n) -and "$($Row.D[$n])" -ne '') { return $Row.D[$n] } }
    $null
}

function Set-Source {
    param([string]$Label, [string]$Status, [int]$Count, [string]$Message)
    $script:Sources[$Label] = [ordered]@{ status = $Status; events = $Count; message = $Message }
}

function Test-Denied {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    ($ex -is [System.UnauthorizedAccessException]) -or ($ex.InnerException -is [System.UnauthorizedAccessException]) -or
    ($ErrorRecord.FullyQualifiedErrorId -like '*UnauthorizedAccess*') -or ($ex.Message -match 'unauthorized|elevated|access is denied')
}

function Read-Events {
    # Filtered queries against one log (IDs chunked: long ID lists make an invalid XPath query). Never throws:
    # a missing or locked log is recorded in $script:Sources.
    param(
        [string]$Label,
        [string]$LogName,
        [int[]]$Id,
        [datetime]$Since,
        [string]$Provider,
        [switch]$WithMessage
    )
    $events = New-Object System.Collections.Generic.List[object]
    $status = 'ok'; $message = $null
    $chunks = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $Id.Count; $i += 20) { $chunks.Add([int[]]($Id[$i..([math]::Min($i + 19, $Id.Count - 1))])) }
    foreach ($chunk in $chunks) {
        $filter = @{ LogName = $LogName; Id = $chunk; StartTime = $Since }
        if ($Provider) { $filter['ProviderName'] = $Provider }
        try {
            foreach ($e in @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)) { $events.Add($e) }
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }
            if (Test-Denied $_) { $status = 'denied'; $message = 'Requires an elevated session.' }
            elseif ($_.Exception.Message -match 'There is not an event log|could not be found|not found') { $status = 'missing'; $message = $_.Exception.Message }
            else { $status = 'error'; $message = $_.Exception.Message }
            break
        }
    }
    if ($status -eq 'ok' -and $events.Count -eq 0) {
        $status = 'empty'
        # A filtered query on a log we may not read reports "no matches", not "access denied". Probe unfiltered to tell them apart.
        try { $null = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop }
        catch {
            if (Test-Denied $_) { $status = 'denied'; $message = 'Requires an elevated session.' }
            elseif ($_.Exception.Message -match 'There is not an event log') { $status = 'missing'; $message = 'Log not present on this device.' }
        }
    }
    Set-Source $Label $status $events.Count $message

    foreach ($e in $events) {
        $data = @{}
        try {
            $node = ([xml]$e.ToXml()).Event.EventData
            if ($node -and $node.Data) {
                $n = 0
                foreach ($d in @($node.Data)) {
                    $name = $d.GetAttribute('Name')
                    if (-not $name) { $name = "param$n" }          # classic (unnamed) insertion strings
                    $data[$name] = $d.InnerText
                    $n++
                }
            }
        } catch { }
        $msg = $null
        if ($WithMessage) { try { $msg = $e.Message } catch { } }
        $row = [pscustomobject]@{
            Id  = [int]$e.Id
            T   = ConvertTo-EpochMs $e.TimeCreated
            Rec = [long]$e.RecordId
            Act = if ($e.ActivityId) { $e.ActivityId.ToString() } else { $null }
            Uid = if ($e.UserId) { $e.UserId.Value } else { $null }
            D   = $data
            Msg = $msg
            A   = $null           # anchor time for Split-ByBoot when the event time isn't the right one
        }
        $key = "$LogName/$($row.Id)"
        if (-not $script:FieldsSeen.ContainsKey($key)) { $script:FieldsSeen[$key] = @($data.Keys | Sort-Object) }
        $row
    }
}

function Split-ByBoot {
    # Single pass: drop each row into the bucket of the boot whose window contains its anchor (A, else T).
    param($Rows, [long[]]$Starts)
    $buckets = New-Object 'object[]' $Starts.Count
    for ($i = 0; $i -lt $Starts.Count; $i++) { $buckets[$i] = New-Object System.Collections.Generic.List[object] }
    $j = 0
    foreach ($r in ($Rows | Sort-Object { if ($null -ne $_.A) { $_.A } else { $_.T } }, T, Rec)) {
        $t = if ($null -ne $r.A) { $r.A } else { $r.T }
        if ($t -lt $Starts[0]) { continue }
        while ($j + 1 -lt $Starts.Count -and $Starts[$j + 1] -le $t) { $j++ }
        $buckets[$j].Add($r)
    }
    , $buckets
}

function Get-Pairs {
    # Match start/finish events (optionally by a key field or scriptblock) into {name,startMs,endMs,durMs}.
    # -NameField: the name comes from that field instead of the key; -WithUid adds the start event's user SID (uid).
    param($Rows, [int]$StartId, [int]$EndId, $Key, [switch]$KeepStatus, [string]$NameField, [switch]$WithUid)
    $open = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in ($Rows | Sort-Object T, Rec)) {
        if ($r.Id -ne $StartId -and $r.Id -ne $EndId) { continue }
        $k = if ($Key -is [scriptblock]) { [string](& $Key $r) } elseif ($Key) { [string]$r.D[$Key] } else { '' }
        if ($r.Id -eq $StartId) {
            if (-not $open.ContainsKey($k)) { $open[$k] = New-Object System.Collections.Generic.Queue[object] }
            $open[$k].Enqueue($r)
        }
        elseif ($open.ContainsKey($k) -and $open[$k].Count -gt 0) {
            $s = $open[$k].Dequeue()
            $nm = if ($NameField) { [string]$s.D[$NameField] } else { $k }
            $p = [pscustomobject]@{ name = $nm; startMs = $s.T; endMs = $r.T; durMs = ($r.T - $s.T) }
            if ($KeepStatus) { $p | Add-Member -NotePropertyName status -NotePropertyValue (ConvertTo-Number $r.D['Win32Status']) }
            if ($WithUid) { $p | Add-Member -NotePropertyName uid -NotePropertyValue $s.Uid; $p | Add-Member -NotePropertyName row -NotePropertyValue $s }
            $out.Add($p)
        }
    }
    $out.ToArray()      # callers wrap in @() - it enumerates to zero or more pairs
}

function Get-NearestAnchor {
    # Events written in a batch with a "header" event (Diagnostics-Performance 101-110 with 100, 201-203 with 200)
    # take the header's anchor, so they land in the same boot.
    param($Rows, [int[]]$HeaderIds, [int[]]$ChildIds)
    $heads = @($Rows | Where-Object { $HeaderIds -contains $_.Id -and $null -ne $_.A })
    foreach ($r in $Rows | Where-Object { $ChildIds -contains $_.Id }) {
        $best = $null; $bestD = [long]::MaxValue
        foreach ($h in $heads) { $d = [math]::Abs($h.T - $r.T); if ($d -lt $bestD) { $bestD = $d; $best = $h } }
        if ($best -and $bestD -le 120000) { $r.A = $best.A }
        else { $st = ConvertFrom-IsoTime $r.D['StartTime']; if ($st -and $st -le $r.T) { $r.A = $st + 5000 } }
    }
}

function Get-AppName {
    param([string]$Command)
    $c = $Command.Trim().TrimStart('"')
    $m = [regex]::Match($c, '^[^"]+?\.(exe|cmd|bat|com|ps1|vbs|lnk)\b', 'IgnoreCase')
    if (-not $m.Success) { $m = [regex]::Match($c, '^[^"\s]+') }
    $exe = if ($m.Success) { $m.Value } else { $c }
    ($exe -split '[\\/]')[-1]
}

function New-Span {
    param([string]$Name, $Start, $End, $Extra)
    $o = [ordered]@{ name = $Name; startMs = $Start; endMs = $End; durMs = $(if ($null -ne $Start -and $null -ne $End) { $End - $Start } else { $null }) }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    [pscustomobject]$o
}

# ---------------------------------------------------------------- section builders (return $null when nothing found)

function Build-Firmware {
    # Kernel-Boot 30: firmware boot metrics in ms since reset. StartOSImageStart is what Task Manager shows as
    # "Last BIOS time"; from there to ExitBootServices is the Windows Boot Manager + OS loader (incl. a BitLocker PIN).
    param($Rows)
    $fw = $Rows | Where-Object { $_.Id -eq 30 } | Select-Object -First 1
    $bl = $Rows | Where-Object { $_.Id -eq 32 } | Select-Object -First 1
    $st = $Rows | Where-Object { $_.Id -eq 20 } | Select-Object -First 1
    if (-not ($fw -or $bl -or $st)) { return $null }
    $f = [ordered]@{}
    if ($fw) { foreach ($k in ($fw.D.Keys | Sort-Object)) { $n = ConvertTo-Number $fw.D[$k]; if ($null -ne $n) { $f[$k] = $n } } }
    $os = $f['StartOSImageStart']; $ebs = $f['ExitBootServicesExit']
    if ($null -eq $ebs) { $ebs = $f['ExitBootServicesEntry'] }
    [pscustomobject]@{
        firmwareMs        = if ($os -gt 0) { $os } else { $null }
        loaderMs          = if ($os -gt 0 -and $ebs -gt $os) { $ebs - $os } else { $null }
        bitlockerWaitMs   = if ($bl) { ConvertTo-Number $bl.D['BitlockerUserInputTime'] } else { $null }
        lastShutdownGood  = if ($st) { ConvertTo-Bool $st.D['LastShutdownGood'] } else { $null }
        lastBootGood      = if ($st) { ConvertTo-Bool $st.D['LastBootGood'] } else { $null }
        fields            = $f
    }
}

function Build-Perf {
    param($Rows, [long]$BootStartMs)
    $r = $Rows | Where-Object { $_.Id -eq 100 } | Select-Object -First 1
    if (-not $r) { return $null }
    $f = [ordered]@{}; $flags = [ordered]@{}
    foreach ($k in ($r.D.Keys | Sort-Object)) {
        $n = ConvertTo-Number $r.D[$k]
        if ($null -ne $n) { $f[$k] = $n } else { $b = ConvertTo-Bool $r.D[$k]; if ($null -ne $b) { $flags[$k] = $b } }
    }
    $start = ConvertFrom-IsoTime $r.D['BootStartTime']
    [pscustomobject]@{
        eventMs    = $r.T
        startMs    = $start
        endMs      = ConvertFrom-IsoTime $r.D['BootEndTime']
        offsetMs   = if ($start) { $start - $BootStartMs } else { 0 }      # trace zero relative to this boot's zero
        bootTimeMs = $f['BootTime']
        mainPathMs = $f['MainPathBootTime']
        postBootMs = $f['BootPostBootTime']
        logonWaitMs = $f['UserLogonWaitDuration']
        fields     = $f
        flags      = $flags
    }
}

$DegraderKinds = @{
    101 = 'app'; 102 = 'driver'; 103 = 'service'; 104 = 'core system'; 105 = 'prefetch (foreground)'; 106 = 'prefetch (background)'
    107 = 'machine policy'; 108 = 'user policy'; 109 = 'device'; 110 = 'session manager'
    201 = 'app'; 202 = 'device'; 203 = 'service'
}

function Build-Degraders {
    param($Rows, [int[]]$Ids)
    $list = @(foreach ($r in $Rows | Where-Object { $Ids -contains $_.Id }) {
        $name = Get-First $r 'FriendlyName', 'Name', 'FileName', 'ImagePath'
        [pscustomobject]@{
            kind          = $DegraderKinds[$r.Id]
            name          = if ($name) { [string]$name } else { "(event $($r.Id))" }
            file          = [string](Get-First $r 'Name')
            path          = Limit-Text ([string](Get-First $r 'Path')) 200
            version       = [string](Get-First $r 'Version')
            company       = [string](Get-First $r 'CompanyName')
            totalMs       = ConvertTo-Number (Get-First $r 'TotalTime', 'TotalDuration')
            degradationMs = ConvertTo-Number (Get-First $r 'DegradationTime', 'DegradationDuration')
        }
    })
    if ($list.Count -eq 0) { return }
    $list | Sort-Object { if ($null -ne $_.degradationMs) { $_.degradationMs } else { 0 } } -Descending | Select-Object -First $TopDegraders
}

function Build-ShutdownPerf {
    param($Rows)
    $r = $Rows | Where-Object { $_.Id -eq 200 } | Select-Object -First 1
    if (-not $r) { return $null }
    $f = [ordered]@{}
    foreach ($k in ($r.D.Keys | Sort-Object)) { $n = ConvertTo-Number $r.D[$k]; if ($null -ne $n) { $f[$k] = $n } }
    [pscustomobject]@{
        startMs    = ConvertFrom-IsoTime $r.D['ShutdownStartTime']
        totalMs    = $f['ShutdownTime']
        fields     = $f
        degraders  = @(Build-Degraders $Rows @(201, 202, 203))
    }
}

function Get-GpoNames {
    # GPO lists come as "<GPO ID=...><Name>X</Name></GPO>..." (GPOInfoList / ApplicableGPOList) or one name per line.
    param([string]$Text)
    if (-not $Text) { return @() }
    $m = [regex]::Matches($Text, '<Name>(.*?)</Name>', 'Singleline')
    if ($m.Count -gt 0) { return @($m | ForEach-Object { $_.Groups[1].Value.Trim() } | Where-Object { $_ }) }
    @($Text -split "[\r\n]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^(None|\(none\))$' })
}

$GpTriggers = @('boot', 'logon', 'network', 'network', 'manual', 'manual', 'periodic', 'periodic')

function Build-Policy {
    # One entry per Group Policy run, correlated by ActivityId (4000-4007 start .. 8000-8007 end).
    param($Rows, $SystemRows)
    $runs = New-Object System.Collections.Generic.List[object]
    if ($Rows -and @($Rows).Count) {
        foreach ($g in ($Rows | Where-Object { $_.Act } | Group-Object Act)) {
            $ev = @($g.Group | Sort-Object T, Rec)
            $st = $ev | Where-Object { $_.Id -ge 4000 -and $_.Id -le 4007 } | Select-Object -First 1
            $en = $ev | Where-Object { $_.Id -ge 8000 -and $_.Id -le 8007 } | Select-Object -Last 1
            if (-not ($st -or $en)) { continue }
            $code = if ($st) { $st.Id - 4000 } else { $en.Id - 8000 }
            $startMs = if ($st) { $st.T } else { $ev[0].T }
            $endMs = if ($en) { $en.T } else { $ev[-1].T }

            # client-side extensions: 4016 start (with GPO list) .. 5016 ok / 6016 warning / 7016 error
            $cses = New-Object System.Collections.Generic.List[object]
            $openCse = @{}
            foreach ($r in $ev) {
                if ($r.Id -eq 4016) { $openCse[[string]$r.D['CSEExtensionId']] = $r }
                elseif ($r.Id -eq 5016 -or $r.Id -eq 6016 -or $r.Id -eq 7016) {
                    $cid = [string]$r.D['CSEExtensionId']; $s = $openCse[$cid]; $openCse.Remove($cid)
                    $ms = ConvertTo-Number (Get-First $r 'CSEElaspedTimeInMilliSeconds', 'CSEElapsedTimeInMilliSeconds')
                    $cses.Add([pscustomobject]@{
                        name    = [string](Get-First $r 'CSEExtensionName')
                        id      = $cid
                        startMs = if ($s) { $s.T } elseif ($null -ne $ms) { $r.T - $ms } else { $null }
                        endMs   = $r.T
                        ms      = $ms
                        result  = switch ($r.Id) { 5016 { 'ok' } 6016 { 'warning' } default { 'error' } }
                        errorCode = ConvertTo-Number $r.D['ErrorCode']
                        changed = if ($s) { ConvertTo-Bool $s.D['IsGPOListChanged'] } else { $null }
                        gpos    = @(if ($s) { Get-GpoNames ([string](Get-First $s 'ApplicableGPOList', 'DescriptionString')) })   # @(if ..) keeps a 1-item list a list
                    })
                }
            }
            # LDAP / SMB / account calls made during the run
            $calls = @($ev | Where-Object { $_.Id -eq 5017 -or $_.Id -eq 7017 } | ForEach-Object {
                    [pscustomobject]@{
                        name   = Limit-Text ("{0} {1}" -f $_.D['OperationDescription'], $_.D['Parameter']) 160
                        ms     = ConvertTo-Number (Get-First $_ 'OperationElaspedTimeInMilliSeconds', 'OperationElapsedTimeInMilliseconds')
                        failed = ($_.Id -eq 7017)
                        endMs  = $_.T
                    } } | Sort-Object { if ($null -ne $_.ms) { $_.ms } else { 0 } } -Descending | Select-Object -First 15)
            $one = { param($id) $ev | Where-Object { $_.Id -eq $id } | Select-Object -First 1 }
            $dc = & $one 5326; $dcFail = & $one 7326; $dl = & $one 5126; $pdl = & $one 5257; $link = & $one 5314
            $loop = & $one 5311; $mode = & $one 5340; $wl = & $one 5351; $dcn = & $one 5308
            $applied = & $one 5312; $filtered = & $one 5313
            $errors = @($ev | Where-Object { $_.Id -eq 7320 } | ForEach-Object { Limit-Text ("{0} (0x{1:X})" -f $_.D['ErrorDescription'], [long](ConvertTo-Number $_.D['ErrorCode'])) 200 })
            $totalS = if ($en) { ConvertTo-Number (Get-First $en 'PolicyElaspedTimeInSeconds', 'PolicyElapsedTimeInSeconds') } else { $null }
            $async = if ($st) { ConvertTo-Bool $st.D['IsAsyncProcessing'] } else { $null }
            $bg = if ($st) { ConvertTo-Bool $st.D['IsBackgroundProcessing'] } else { $null }

            $runs.Add([pscustomobject]@{
                activityId     = $g.Name
                scope          = if ($code % 2 -eq 0) { 'machine' } else { 'user' }
                trigger        = $GpTriggers[$code]
                principal      = Protect-Name ([string](Get-First $(if ($st) { $st } else { $en }) 'PrincipalSamName'))
                startMs        = $startMs
                endMs          = $endMs
                totalMs        = [long]($endMs - $startMs)
                reportedSec    = $totalS
                complete       = [bool]$en
                errorCode      = if ($en) { ConvertTo-Number $en.D['ErrorCode'] } else { $null }
                connectivityFailure = if ($en) { ConvertTo-Bool $en.D['IsConnectivityFailure'] } else { $null }
                async          = $async
                background     = $bg
                syncReason     = if ($st) { ConvertTo-Number $st.D['ReasonForSyncProcessing'] } else { $null }
                blocking       = ($async -eq $false -and $bg -eq $false)
                dc             = if ($dcn) { [string]$dcn.D['DCName'] } else { $null }
                dcDiscoveryMs  = if ($dc) { ConvertTo-Number $dc.D['DCDiscoveryTimeInMilliSeconds'] } elseif ($dcFail) { ConvertTo-Number $dcFail.D['DCDiscoveryTimeInMilliSeconds'] } else { $null }
                dcDiscoveryFailed = [bool]$dcFail
                gpoListMs      = if ($dl) { ConvertTo-Number $dl.D['GPODownloadTimeElapsedInMilliseconds'] } else { $null }
                gposApplicable = if ($dl) { ConvertTo-Number $dl.D['NumberOfGPOsApplicable'] } else { $null }
                policyDownloadMs = if ($pdl) { ConvertTo-Number $pdl.D['PolicyDownloadTimeElapsedInMilliseconds'] } else { $null }
                bandwidthKbps  = if ($link) { ConvertTo-Number $link.D['BandwidthInkbps'] } else { $null }
                slowLink       = if ($link) { ConvertTo-Bool $link.D['IsSlowLink'] } else { $null }
                loopbackMode   = if ($loop) { ConvertTo-Number $loop.D['PolicyProcessingMode'] } else { $null }
                processingMode = if ($mode) { ConvertTo-Number $mode.D['PolicyApplicationMode'] } else { $null }
                winlogonReturnMs = if ($wl) { ConvertTo-Number $wl.D['WinlogonReturnTimeElapsedInMilliseconds'] } else { $null }
                gpos           = @(if ($applied) { Get-GpoNames ([string](Get-First $applied 'GPOInfoList', 'DescriptionString')) })
                filteredGpos   = @(if ($filtered) { Get-GpoNames ([string](Get-First $filtered 'GPOInfoList', 'DescriptionString')) })
                extensions     = @($cses | Sort-Object { if ($null -ne $_.ms) { $_.ms } else { 0 } } -Descending | Select-Object -First $TopExtensions)
                calls          = $calls
                errors         = $errors
            })
        }
    }

    # System log GP results (1500-1503 success, 10xx failures) - readable without elevation, carry the run's total ms.
    $sys = @(foreach ($r in @($SystemRows | Where-Object { $_ })) {
        # failures (10xx) carry no scope field; the event's user SID tells machine (SYSTEM) from user in any language
        $scope = if ($r.Id -eq 1501 -or $r.Id -eq 1503) { 'user' } elseif ($r.Id -eq 1500 -or $r.Id -eq 1502) { 'machine' }
                 elseif ($r.Uid -and $r.Uid -ne 'S-1-5-18') { 'user' } else { 'machine' }
        [pscustomobject]@{
            id     = $r.Id
            t      = $r.T
            scope  = $scope
            ok     = ($r.Id -ge 1500 -and $r.Id -le 1503)
            ms     = ConvertTo-Number $r.D['ProcessingTimeInMilliseconds']
            mode   = ConvertTo-Number $r.D['ProcessingMode']
            gpos   = ConvertTo-Number $r.D['NumberOfGroupPolicyObjects']
            error  = if ($r.Id -lt 1500 -or $r.Id -gt 1503) { Limit-Text $(if ($r.Msg) { $r.Msg } else { "$($r.D['ErrorDescription'])" }) 220 } else { $null }
        }
    })

    if ($runs.Count -eq 0 -and $sys.Count -eq 0) { return $null }
    $sorted = @($runs | Sort-Object startMs)
    [pscustomobject]@{
        machine = Get-PolicySummary $sorted $sys 'machine'
        user    = Get-PolicySummary $sorted $sys 'user'
        runs    = $sorted
        system  = $sys
    }
}

function Get-PolicySummary {
    # The boot's computer policy (first machine "boot" run) or user policy (first user "logon" run); without the
    # GroupPolicy log, the first System-log result of that scope. Also rebuilt after a history merge.
    param($Runs, $Sys, [string]$Scope)
    $trigger = if ($Scope -eq 'machine') { 'boot' } else { 'logon' }
    $run = @($Runs | Where-Object { $_ -and $_.scope -eq $Scope -and $_.trigger -eq $trigger } | Sort-Object startMs) | Select-Object -First 1
    $s = @($Sys | Where-Object { $_ -and $_.scope -eq $Scope } | Sort-Object t) | Select-Object -First 1
    if (-not $run -and -not $s) { return $null }
    [pscustomobject]@{
        startMs  = if ($run) { $run.startMs } elseif ($s -and $null -ne $s.ms) { $s.t - $s.ms } else { $null }
        endMs    = if ($run) { $run.endMs } elseif ($s) { $s.t } else { $null }
        totalMs  = if ($run) { $run.totalMs } elseif ($s) { $s.ms } else { $null }
        blocking = if ($run) { $run.blocking } else { $null }
        ok       = if ($run) { ($run.errorCode -eq 0) } elseif ($s) { $s.ok } else { $null }
        extensions = @(if ($run) { $run.extensions })
    }
}

$WinlogonEvents = @{ 0 = 'Startup'; 1 = 'Shutdown'; 2 = 'Logon'; 3 = 'Logoff'; 4 = 'StartShell'; 5 = 'PostShell' }

function Build-Winlogon {
    # 811/812: every Winlogon notification subscriber, per notification. Winlogon waits for each, so long ones
    # (GPClient = synchronous Group Policy, Profiles = profile load) are time the user actually waited.
    param($Rows)
    $pairs = @(Get-Pairs $Rows 811 812 { param($r) "$($r.D['Event'])|$($r.D['SubscriberName'])" })
    if ($pairs.Count -eq 0) { return }
    $pairs | ForEach-Object {
        $parts = $_.name -split '\|', 2
        $evn = [int](ConvertTo-Number $parts[0])
        [pscustomobject]@{
            event      = $evn
            eventName  = if ($WinlogonEvents.ContainsKey($evn)) { $WinlogonEvents[$evn] } else { "Notification $evn" }
            subscriber = $parts[1]
            startMs    = $_.startMs
            endMs      = $_.endMs
            durMs      = $_.durMs
        }
    } | Sort-Object startMs, endMs, event, subscriber | Select-Object -First $TopSubscribers
}

function Build-Logon {
    param($Shell, $ProfRows, $Auth)

    # Shell-Core and User Profile Service events carry the signed-in user's SID, so their start / finish events are paired
    # per user (and profile loads per logon session too): overlapping sessions cannot cross-pair. Winlogon's
    # authentication events are logged as SYSTEM, so the primary session is bounded by time instead (see below).
    $span = { param($x) if ($x) { [pscustomobject]@{ name = $x.name; startMs = $x.startMs; endMs = $x.endMs; durMs = $x.durMs } } else { $null } }

    # first *successful* authentication (Win32Status 0) - a mistyped password shouldn't become the logon start
    $authPairs = @(Get-Pairs $Auth 1 2 $null -KeepStatus)
    $okAuth = @($authPairs | Where-Object { $null -eq $_.status -or $_.status -eq 0 } | Sort-Object startMs)
    $failed = @($authPairs | Where-Object { $null -ne $_.status -and $_.status -ne 0 }).Count
    $authP = $okAuth | Select-Object -First 1
    # one record per profile load (= per interactive session): shared and multi-user devices sign in more than once per boot
    $profs = @(Get-Pairs $ProfRows 1 2 { param($r) "$($r.Uid)|$($r.D['Session'])" } -WithUid | Sort-Object startMs, name)

    # The primary session: the first successful sign-in, the profile load that follows it, and that user's logon tasks -
    # all of them before the next sign-in begins, so one session's sign-in is never combined with another's tasks.
    $lo = if ($authP) { [long]$authP.startMs - 5000 } else { [long]::MinValue }
    $profP = $profs | Where-Object { $_.startMs -ge $lo } | Select-Object -First 1
    $pStart = if ($authP) { [long]$authP.startMs } elseif ($profP) { [long]$profP.startMs } else { $null }
    $puid = if ($profP) { $profP.uid } else { $null }
    # Where the primary session's own events stop: another user's tasks are already told apart by their SID, so with a
    # known user only that user's next sign-in counts; without one (no profile events), any next sign-in.
    $later = @(if ($puid) {
        @($profs | Where-Object { $_ -ne $profP -and $_.uid -eq $puid -and $_.startMs -gt $profP.startMs } | ForEach-Object { [long]$_.startMs })
    } else {
        @(@($okAuth | Select-Object -Skip 1 | ForEach-Object { [long]$_.startMs }) +
            @($profs | Where-Object { $profP -and $_ -ne $profP -and $_.startMs -gt $profP.startMs } | ForEach-Object { [long]$_.startMs }))
    })
    $next = if ($later.Count) { [long]($later | Measure-Object -Minimum).Minimum } else { [long]::MaxValue }
    $inPrimary = { param($x) ($null -eq $pStart -or $x.startMs -ge $pStart - 5000) -and $x.startMs -lt $next -and (-not $puid -or -not $x.uid -or $x.uid -eq $puid) }

    $tasks = @(Get-Pairs $Shell 62170 62171 { param($r) "$($r.Uid)|$($r.D['TaskName'])" } -NameField TaskName -WithUid | Where-Object { & $inPrimary $_ })
    $all = & $span ($tasks | Where-Object { $_.name -eq 'AllLogonTasks' } | Sort-Object startMs | Select-Object -First 1)
    $rest = @($tasks | Where-Object { $_.name -ne 'AllLogonTasks' } | Sort-Object @{ e = 'durMs'; Descending = $true }, name | Select-Object -First $TopTasks | ForEach-Object { & $span $_ })
    # An empty pipeline yields "AutomationNull", which Windows PowerShell 5.1 serialises as {} - force a real $null.
    if (-not $authP) { $authP = $null }
    $profOut = & $span $profP
    if (-not $profOut) { $profOut = $null }
    if (-not $all) { $all = $null }

    $sessions = @($profs | ForEach-Object {
            $sid = $_.uid
            [pscustomobject]@{
                sid     = $(if ($Anonymize -or -not $sid) { $null } else { $sid })
                user    = Protect-Name (Resolve-Account $sid)
                session = ConvertTo-Number $_.row.D['Session']
                startMs = $_.startMs; endMs = $_.endMs; durMs = $_.durMs
            }
        })

    $phases = @()
    $phases += @(Get-Pairs $Shell 9648 9649 { param($r) "$($r.Uid)|$($r.D['psz'])" } -NameField psz)
    $phases += @(Get-Pairs $Shell 9652 9653 { param($r) "$($r.Uid)|$($r.D['psz'])" } -NameField psz)
    $phases += @(Get-Pairs $Shell 9703 9704 { param($r) "$($r.Uid)" } | ForEach-Object { $_.name = 'RunOnce commands'; $_ })
    $phases = @($phases | Where-Object { $_ } | Sort-Object startMs, endMs, name)

    $batches = @(Get-Pairs $Shell 9705 9706 { param($r) "$($r.Uid)|$($r.D['KeyName'])" } -NameField KeyName | Sort-Object startMs, name)     # one per Run / RunOnce key processed
    $apps = @(@(Get-Pairs $Shell 9707 9708 { param($r) "$($r.Uid)|$($r.D['Command'])" } -NameField Command | ForEach-Object { $_ | Add-Member -NotePropertyName kind -NotePropertyValue 'run key' -PassThru }) +
        @(Get-Pairs $Shell 62408 62409 { param($r) "$($r.Uid)|$($r.D['Command'])" } -NameField Command | ForEach-Object { $_ | Add-Member -NotePropertyName kind -NotePropertyValue 'packaged' -PassThru }) |
        Where-Object { $_ } | ForEach-Object {
            [pscustomobject]@{ name = (Get-AppName $_.name); kind = $_.kind; command = (Limit-Text $_.name 160); startMs = $_.startMs; endMs = $_.endMs; durMs = $_.durMs }
        } | Sort-Object @{ e = 'durMs'; Descending = $true }, command | Select-Object -First $TopApps)

    # who signed in, and what kind of profile (the primary session's profile events; 67 is logged as SYSTEM, so by time)
    $user = $null
    $p1 = if ($profP) { $profP.row } else { $ProfRows | Where-Object { $_.Id -eq 1 } | Select-Object -First 1 }
    $p67lo = if ($profP) { [long]$profP.startMs } else { [long]::MinValue }
    $p67 = $ProfRows | Where-Object { $_.Id -eq 67 -and $_.T -ge $p67lo -and $_.T -lt $next } | Sort-Object T | Select-Object -First 1
    if ($p1 -or $p67) {
        $name = $null
        if ($p1 -and $p1.Uid) { $name = Resolve-Account $p1.Uid }
        if (-not $name -and $p67 -and $p67.D['LocalPath']) { $name = Split-Path -Leaf $p67.D['LocalPath'] }
        $user = [pscustomobject]@{
            name        = Protect-Name $name
            sid         = if ($p1 -and -not $Anonymize) { $p1.Uid } else { $null }
            logonType   = if ($p67) { [string]$p67.D['LogonType'] } else { $null }
            profileType = if ($p67) { [string]$p67.D['ProfileType'] } else { $null }
        }
    }

    if (-not ($authP -or $profP -or $all -or $rest.Count -or $apps.Count)) { return $null }
    [pscustomobject]@{
        auth           = $authP
        failedAuth     = $failed
        profile        = $profOut
        user           = $user
        allTasks       = $all
        tasks          = $rest
        shellPhases    = $phases
        startupBatches = $batches
        startupApps    = $apps
        sessions       = $sessions
        sessionCount   = $sessions.Count
    }
}

function Build-Network {
    param($Rows)
    if (-not $Rows) { return $null }
    $con = @($Rows | Where-Object { $_.Id -eq 10000 } | Sort-Object T)
    if ($con.Count -eq 0) { return $null }
    $cats = @{ 0 = 'Public'; 1 = 'Private'; 2 = 'Domain' }
    [pscustomobject]@{
        firstConnectedMs = $con[0].T
        connects = @($con | Select-Object -First 5 | ForEach-Object {
                $c = ConvertTo-Number $_.D['Category']
                [pscustomobject]@{ t = $_.T; name = [string]$_.D['Name']; category = $(if ($null -ne $c -and $cats.ContainsKey([int]$c)) { $cats[[int]$c] } else { $null }) }
            })
    }
}

function Build-Mdm {
    # Intune / MDM: OMA-DM sync sessions (208/209), each policy setting applied (813-819) and failures.
    param($Rows)
    if (-not $Rows -or @($Rows).Count -eq 0) { return $null }
    $sorted = @($Rows | Sort-Object T, Rec)

    $sessions = New-Object System.Collections.Generic.List[object]
    $openS = $null
    foreach ($r in $sorted | Where-Object { $_.Id -eq 208 -or $_.Id -eq 209 -or $_.Id -eq 201 }) {
        if ($r.Id -eq 208) {
            if ($openS) { $sessions.Add($openS) }
            $openS = [pscustomobject]@{ startMs = $r.T; endMs = $null; durMs = $null; server = [string]$r.D['Message2']; enrollment = [string]$r.D['Message1']; result = $null; ok = $null }
        }
        elseif ($openS -and $r.Id -eq 209) {
            $hr = Get-First $r 'HRESULT'
            $openS.endMs = $r.T; $openS.durMs = $r.T - $openS.startMs; $openS.result = [string]$hr
            $openS.ok = ($null -eq $hr -or (ConvertTo-Number $hr) -eq 0)
            $sessions.Add($openS); $openS = $null
        }
        elseif ($openS -and $r.Id -eq 201) { $openS.ok = $false; $openS.result = [string](Get-First $r 'HRESULT') }
    }
    if ($openS) { $sessions.Add($openS) }

    $pol = @($sorted | Where-Object { $_.Id -ge 813 -and $_.Id -le 819 -and $_.Id -ne 817 })
    $policies = @($pol | Select-Object -First $TopMdmPolicies | ForEach-Object {
            $r = $_                              # switch rebinds $_
            $u = [string]$r.D['Message4']
            [pscustomobject]@{
                t      = $r.T
                op     = if ($r.Id -eq 819) { 'delete' } else { 'set' }
                policy = [string]$r.D['Message1']
                area   = [string]$r.D['Message2']
                scope  = if (-not $u -or $u -eq 'device' -or $u -eq '(null)') { 'device' } else { 'user' }
                value  = switch ($r.Id) { 813 { [string](ConvertTo-Number $r.D['HexInt1']) } 814 { Limit-Text ([string]$r.D['Message5']) 80 } default { $null } }
            } })
    # bursts: policy writes less than 10 s apart belong to one application pass
    $bursts = New-Object System.Collections.Generic.List[object]
    $cur = $null
    foreach ($p in $pol) {
        if ($cur -and ($p.T - $cur.endMs) -le 10000) { $cur.endMs = $p.T; $cur.count++; $cur.areas[[string]$p.D['Message2']] = 1 + [int]$cur.areas[[string]$p.D['Message2']] }
        else {
            if ($cur) { $bursts.Add($cur) }
            $cur = [pscustomobject]@{ startMs = $p.T; endMs = $p.T; count = 1; areas = @{ ([string]$p.D['Message2']) = 1 } }
        }
    }
    if ($cur) { $bursts.Add($cur) }
    $burstOut = @($bursts | ForEach-Object {
            [pscustomobject]@{ startMs = $_.startMs; endMs = $_.endMs; durMs = $_.endMs - $_.startMs; count = $_.count
                areas = @($_.areas.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { [pscustomobject]@{ name = $_.Key; count = $_.Value } }) }
        })
    $areas = @($pol | Group-Object { [string]$_.D['Message2'] } | ForEach-Object {
            $g = @($_.Group | Sort-Object T)
            [pscustomobject]@{ name = $_.Name; count = $g.Count; firstMs = $g[0].T; lastMs = $g[-1].T; durMs = $g[-1].T - $g[0].T }
        } | Sort-Object count -Descending | Select-Object -First 40)

    $errors = @($sorted | Where-Object { @(404, 454, 821, 1924, 201) -contains $_.Id } | Select-Object -First $TopMdmErrors | ForEach-Object {
            $r = $_                              # switch rebinds $_
            $what = switch ($r.Id) {
                404 { "{0} {1}" -f $r.D['Message3'], $r.D['Message5'] }
                454 { "{0} {1}" -f $r.D['Message3'], $r.D['Message5'] }
                821 { "{0}/{1}" -f $r.D['Message2'], $r.D['Message1'] }
                1924 { "App install failed: {0}" -f $r.D['Message2'] }
                default { 'OMA-DM message failed to send' }
            }
            [pscustomobject]@{ t = $r.T; id = $r.Id; text = Limit-Text $what 200; result = [string](Get-First $r 'HexInt1', 'HRESULT', 'HexInt3') }
        })

    if ($sessions.Count -eq 0 -and $pol.Count -eq 0 -and $errors.Count -eq 0) { return $null }
    [pscustomobject]@{
        sessions     = $sessions.ToArray()       # @(List[object]) throws 'Argument types do not match' here
        policyCount  = $pol.Count
        bursts       = $burstOut
        areas        = $areas
        policies     = $policies
        errors       = $errors
    }
}

function Build-Issues {
    param($Rows)
    if (-not $Rows) { return }
    $src = @{ 7000 = 'Service'; 7001 = 'Service'; 7009 = 'Service'; 7011 = 'Service'; 7022 = 'Service'; 7023 = 'Service'; 7024 = 'Service'
        7026 = 'Driver'; 7031 = 'Service'; 7034 = 'Service'; 7038 = 'Service'; 7043 = 'Service'; 41 = 'Power'; 6008 = 'Power'
        1097 = 'Entra ID'; 1098 = 'Entra ID'; 1104 = 'Entra ID'; 1081 = 'Entra ID'; 1082 = 'Entra ID'; 1088 = 'Entra ID' }
    $list = @($Rows | Sort-Object T, Rec | ForEach-Object {
            $text = if ($_.Msg) { $_.Msg } else { ($_.D.Values | Where-Object { $_ }) -join ' ' }
            [pscustomobject]@{ t = $_.T; id = $_.Id; source = $src[$_.Id]; text = Limit-Text $text 240 }
        } | Select-Object -First $TopIssues)
    if ($list.Count -eq 0) { return }
    $list
}

function Build-ShutdownReason {
    # User32 1074: the last shutdown / restart request in this boot - process, reason, type, user.
    param($Rows)
    $r = $Rows | Where-Object { $_.Id -eq 1074 } | Sort-Object T | Select-Object -Last 1
    if (-not $r) { return $null }
    [pscustomobject]@{
        t       = $r.T
        process = Limit-Text ([regex]::Replace([string]$r.D['param1'], '\s*\([^)]*\)\s*$', '')) 200
        reason  = [string]$r.D['param3']
        code    = [string]$r.D['param4']
        type    = [string]$r.D['param5']
        comment = Limit-Text ([string]$r.D['param6']) 200
        user    = Protect-Name ([string]$r.D['param7'])
    }
}

# ---------------------------------------------------------------- Intune Management Extension (text logs)

# Best-effort: IME log wording is not a documented interface. Each rule marks the start of a unit of work; a unit runs
# until the next start on the same log thread, or a 5-minute silence. Match counts land in sources so a mismatch shows.
$ImeRules = @(
    @{ kind = 'script';   rx = [regex]'Processing policy with id = (?<id>[0-9a-fA-F-]{36})' }
    @{ kind = 'win32app'; rx = [regex]"processing targeted app \(name='(?<name>[^']*)', id='(?<id>[0-9a-fA-F-]{36})'" }
    @{ kind = 'win32app'; rx = [regex]'\[Win32App\]\[V3Processor\] Processing subgraph with app ids: (?<id>[0-9a-fA-F-]{36})' }
    @{ kind = 'checkin';  rx = [regex]'application poller starts'; name = 'Win32 app check-in' }
    @{ kind = 'executor'; rx = [regex]'AgentExecutor gets invoked'; name = 'Script run (AgentExecutor)' }
)
$ImeResultRx = [regex]'(?i)(?:\bresult\s*(?:=|:|is)\s*(?<r>[\w.-]+))|(?:exit code is (?<r>-?\d+))'
$CmLineRx = [regex]::new('<!\[LOG\[(?<m>.*?)\]LOG\]!><time="(?<t>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)(?<z>[+-]\d+)?"\s+date="(?<d>\d{1,2}-\d{1,2}-\d{4})"\s+component="(?<c>[^"]*)"[^>]*?type="(?<y>\d)"[^>]*?thread="(?<h>\d+)"', [Text.RegularExpressions.RegexOptions]::Singleline)

function Read-ImeLogs {
    param([datetime]$Since)
    $label = 'Intune Management Extension'
    $dir = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
    if (-not (Test-Path $dir)) { Set-Source $label 'missing' 0 'Not installed (device not Intune-managed, or no scripts / Win32 apps assigned).'; return }
    $files = @()
    try { $files = @(Get-ChildItem -Path $dir -Filter '*.log' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $Since }) }
    catch { if (Test-Denied $_) { Set-Source $label 'denied' 0 'Requires an elevated session.' } else { Set-Source $label 'error' 0 $_.Exception.Message }; return }
    $rows = New-Object System.Collections.Generic.List[object]
    $sinceMs = ConvertTo-EpochMs $Since
    $denied = 0
    foreach ($f in $files) {
        $text = $null
        try {
            # IME keeps its logs open for writing: share ReadWrite or the read fails
            $fs = New-Object IO.FileStream($f.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8, $true); $text = $sr.ReadToEnd(); $sr.Dispose() } finally { $fs.Dispose() }
        } catch { $denied++; continue }
        $kind = [regex]::Replace($f.BaseName, '-\d{8}-\d{6}$', '')
        foreach ($m in $CmLineRx.Matches($text)) {
            $frac = $m.Groups['t'].Value
            if ($frac -notmatch '\.') { $frac += '.0' }
            $parts = $frac -split '\.'
            $frac = $parts[0] + '.' + $parts[1].PadRight(7, '0').Substring(0, 7)
            $dt = [datetime]::MinValue
            if (-not [datetime]::TryParseExact("$($m.Groups['d'].Value) $frac", 'M-d-yyyy H:mm:ss.fffffff', $Inv, [Globalization.DateTimeStyles]::None, [ref]$dt)) { continue }
            if ($m.Groups['z'].Success) {
                # CMTrace bias: UTC = local + bias minutes
                $t = ([DateTimeOffset]::new([datetime]::SpecifyKind($dt.AddMinutes([int]$m.Groups['z'].Value), 'Utc'))).ToUnixTimeMilliseconds()
            } else { $t = ConvertTo-EpochMs ([datetime]::SpecifyKind($dt, 'Local')) }
            if ($t -lt $sinceMs) { continue }
            $rows.Add([pscustomobject]@{ T = $t; F = $kind; Y = [int]$m.Groups['y'].Value; H = $m.Groups['h'].Value; M = $m.Groups['m'].Value.Trim(); Rec = $rows.Count; A = $null })
        }
    }
    # 'partial': some log files could not be read, so the IME detail may be incomplete
    $status = if ($denied -and $denied -eq $files.Count) { 'denied' } elseif ($denied) { 'partial' } elseif ($rows.Count) { 'ok' } else { 'empty' }
    $msg = if ($status -eq 'denied') { 'Requires an elevated session.' } elseif ($status -eq 'partial') { "$denied of $($files.Count) log files could not be read." } else { $null }
    Set-Source $label $status $rows.Count $msg
    $rows
}

function Build-Ime {
    param($Rows)
    if (-not $Rows -or @($Rows).Count -eq 0) { return $null }
    $units = New-Object System.Collections.Generic.List[object]
    $open = @{}
    $close = { param($k) $u = $open[$k]; if ($u) { $u.durMs = $u.endMs - $u.startMs; $units.Add($u); $open.Remove($k) } }
    foreach ($r in ($Rows | Sort-Object T, Rec)) {
        $k = "$($r.F)|$($r.H)"
        $hit = $null; $mm = $null
        foreach ($rule in $ImeRules) { $mm = $rule.rx.Match($r.M); if ($mm.Success) { $hit = $rule; break } }
        if ($hit) {
            $statKey = "$($hit.kind): $($hit.rx.ToString().Substring(0, [math]::Min(40, $hit.rx.ToString().Length)))"
            $script:ImeStats[$statKey] = 1 + [int]$script:ImeStats[$statKey]
            & $close $k
            $id = if ($mm.Groups['id'].Success) { $mm.Groups['id'].Value } else { $null }
            $name = if ($mm.Groups['name'].Success -and $mm.Groups['name'].Value) { $mm.Groups['name'].Value } elseif ($hit.name) { $hit.name } elseif ($id) { $id } else { $hit.kind }
            $kind = if ($hit.kind -eq 'script' -and $r.F -match 'HealthScript') { 'remediation' } else { $hit.kind }
            $open[$k] = [pscustomobject]@{ kind = $kind; name = $name; id = $id; log = $r.F; startMs = $r.T; endMs = $r.T; durMs = 0; result = $null; errors = 0; lines = 1 }
            continue
        }
        $u = $open[$k]
        if (-not $u) { continue }
        if ($r.T - $u.endMs -gt 300000) { & $close $k; continue }
        $u.endMs = $r.T; $u.lines++
        if ($r.Y -eq 3) { $u.errors++ }
        $rm = $ImeResultRx.Match($r.M)
        if ($rm.Success) { $u.result = $rm.Groups['r'].Value }
    }
    foreach ($k in @($open.Keys)) { & $close $k }

    $files = @($Rows | Group-Object F | ForEach-Object {
            $g = @($_.Group | Sort-Object T)
            [pscustomobject]@{ name = $_.Name; firstMs = $g[0].T; lastMs = $g[-1].T; lines = $g.Count; errors = @($g | Where-Object { $_.Y -eq 3 }).Count; warnings = @($g | Where-Object { $_.Y -eq 2 }).Count }
        } | Sort-Object firstMs)
    $errs = @($Rows | Where-Object { $_.Y -eq 3 } | Group-Object { Limit-Text $_.M 200 } | Sort-Object Count -Descending | Select-Object -First 12 | ForEach-Object {
            [pscustomobject]@{ text = $_.Name; count = $_.Count; firstMs = ($_.Group | Measure-Object T -Minimum).Minimum; log = $_.Group[0].F }
        })
    [pscustomobject]@{
        firstMs = ($Rows | Measure-Object T -Minimum).Minimum
        units   = @($units | Sort-Object durMs -Descending | Select-Object -First $TopImeUnits | Sort-Object startMs)
        files   = $files
        errors  = $errs
    }
}

# ---------------------------------------------------------------- derived timeline

function Get-Span {
    # a span only counts when it has both ends (guards against empty {} objects from older data)
    param($X)
    if ($X -and $X.startMs -and $X.endMs -and $X.endMs -ge $X.startMs) { $X } else { $null }
}

function Add-Derived {
    # Rebuilds phases + totals from the (possibly merged) sections, so history merges stay consistent.
    param($Boot)
    $s0 = [long]$Boot.bootStartMs
    $au = Get-Span $Boot.logon.auth; $pr = Get-Span $Boot.logon.profile; $tk = Get-Span $Boot.logon.allTasks
    $wl = @($Boot.winlogon | Where-Object { $_ })

    # What blocked: Winlogon's GPClient subscriber at Startup / Logon is the synchronous Group Policy time.
    $gpStart = $wl | Where-Object { $_.event -eq 0 -and $_.subscriber -eq 'GPClient' } | Select-Object -First 1
    $gpLogon = $wl | Where-Object { $_.event -eq 2 -and $_.subscriber -eq 'GPClient' } | Select-Object -First 1
    $mp = $null; $up = $null
    if ($gpStart -and $gpStart.durMs -ge $BlockingMinMs) { $mp = $gpStart }
    elseif ($Boot.policy.machine -and $Boot.policy.machine.blocking) { $mp = Get-Span $Boot.policy.machine }
    if ($gpLogon -and $gpLogon.durMs -ge $BlockingMinMs) { $up = $gpLogon }
    elseif ($Boot.policy.user -and $Boot.policy.user.blocking) { $up = Get-Span $Boot.policy.user }

    # Sign-in screen ready: when Winlogon finished its Startup notifications; fallback: the boot trace's logon wait.
    $screenReady = $null
    $startup = @($wl | Where-Object { $_.event -eq 0 -and $_.endMs })
    if ($startup.Count) { $screenReady = [long]($startup | Measure-Object endMs -Maximum).Maximum }
    elseif ($au -and $Boot.perf -and $Boot.perf.logonWaitMs -gt 0) { $screenReady = [long]$au.startMs - [long]$Boot.perf.logonWaitMs }
    if ($screenReady -and $au -and $screenReady -gt $au.startMs) { $screenReady = [long]$au.startMs }
    if ($screenReady -and $screenReady -lt $s0) { $screenReady = $null }
    $wait = if ($screenReady -and $au -and $au.startMs -gt $screenReady) { [pscustomobject]@{ startMs = $screenReady; endMs = [long]$au.startMs } } else { $null }

    $cand = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(
            @{ k = 'machinePolicy'; x = $mp;   logon = $false },
            @{ k = 'signInWait';    x = $wait; logon = $false },
            @{ k = 'auth';          x = $au;   logon = $true },
            @{ k = 'profile';       x = $pr;   logon = $true },
            @{ k = 'userPolicy';    x = $up;   logon = $true },
            @{ k = 'logonTasks';    x = $tk;   logon = $true })) {
        if ($c.x -and $c.x.startMs -and $c.x.endMs -and $c.x.endMs -gt $c.x.startMs -and $c.x.startMs -ge $s0) {
            $cand.Add([pscustomobject]@{ k = $c.k; s = [long]$c.x.startMs; e = [long]$c.x.endMs; logon = $c.logon })
        }
    }
    $logonStarts = @($cand | Where-Object { $_.logon } | ForEach-Object { $_.s })
    $phases = New-Object System.Collections.Generic.List[object]
    $fw = $Boot.firmware
    $fwMs = if ($fw -and $fw.firmwareMs -gt 0) { [long]$fw.firmwareMs } else { $null }
    $ldMs = if ($fw -and $fw.loaderMs -gt 0) { [long]$fw.loaderMs } else { $null }
    if ($fwMs) { $phases.Add([pscustomobject]@{ key = 'firmware'; startMs = - ($fwMs + [long]$ldMs); durMs = $fwMs + [long]$ldMs }) }
    $endMs = $null

    if ($cand.Count -gt 0) {
        $logonBegin = if ($logonStarts.Count) { ($logonStarts | Measure-Object -Minimum).Minimum } else { [long]::MaxValue }
        $cursor = $s0
        foreach ($c in ($cand | Sort-Object s)) {
            $s = [math]::Max($c.s, $cursor)
            if ($c.e -le $s) { continue }
            if (($s - $cursor) -ge $GapFoldMs) {
                $gk = if ($cursor -lt $logonBegin) { 'boot' } else { 'other' }
                $phases.Add([pscustomobject]@{ key = $gk; startMs = $cursor - $s0; durMs = $s - $cursor })
                $cursor = $s
            }
            $phases.Add([pscustomobject]@{ key = $c.k; startMs = $cursor - $s0; durMs = $c.e - $cursor })
            $cursor = $c.e
        }
        $endMs = $cursor
    }

    $dur = { param($x) if ($x -and $x.endMs -and $x.startMs) { [long]($x.endMs - $x.startMs) } else { $null } }
    $signInMs = if ($au) { [long]$au.startMs - $s0 } elseif ($pr) { [long]$pr.startMs - $s0 } else { $null }
    # The wait is only known when both ends are: sign-in screen ready and authentication start. Without the first,
    # boot and the user's delay cannot be told apart, so the wait - and every total that excludes it - stays unknown.
    $waitMs = if ($screenReady -and $au) { [math]::Max([long]0, [long]$au.startMs - $screenReady) } else { $null }
    $readyMs = if ($tk -and $endMs) { $endMs - $s0 } else { $null }          # only when AllLogonTasks finished
    $readyExcl = if ($null -ne $readyMs -and $null -ne $waitMs) { $readyMs - $waitMs } else { $null }
    $totals = [pscustomobject]@{
        firmwareMs           = $fwMs
        loaderMs             = $ldMs
        coreBootMs           = if ($screenReady) { $screenReady - $s0 } else { $null }          # to the sign-in screen (measured only)
        signInWaitMs         = $waitMs
        toSignInMs           = $signInMs
        authMs               = & $dur $au
        profileMs            = & $dur $pr
        machinePolicyMs      = & $dur $mp                                                       # time it blocked
        userPolicyMs         = & $dur $up
        machinePolicyTotalMs = if ($Boot.policy.machine -and $null -ne $Boot.policy.machine.totalMs) { $Boot.policy.machine.totalMs } else { $null }
        userPolicyTotalMs    = if ($Boot.policy.user -and $null -ne $Boot.policy.user.totalMs) { $Boot.policy.user.totalMs } else { $null }
        logonTasksMs         = & $dur $tk
        readyMs              = $readyMs
        readyExclWaitMs      = $readyExcl
        signInToReadyMs      = if ($tk -and $endMs -and $null -ne $signInMs) { $endMs - $s0 - $signInMs } else { $null }
        powerOnToReadyMs     = if ($null -ne $readyExcl -and $fwMs) { $readyExcl + $fwMs + [long]$ldMs } else { $null }
        networkMs            = if ($Boot.network -and $Boot.network.firstConnectedMs) { $Boot.network.firstConnectedMs - $s0 } else { $null }
        mdmSessions          = if ($Boot.mdm) { @($Boot.mdm.sessions).Count } else { $null }
        mdmPolicies          = if ($Boot.mdm) { $Boot.mdm.policyCount } else { $null }
    }
    $Boot.phases = $phases.ToArray()
    $Boot.totals = $totals
    $Boot
}

# ---------------------------------------------------------------- history merge

function Repair-EmptyObjects {
    # Windows PowerShell 5.1 serialised some nulls as {} - turn those back into $null (recursive, in place).
    param($Obj)
    if ($Obj -isnot [pscustomobject]) { return }
    foreach ($p in @($Obj.PSObject.Properties)) {
        $v = $p.Value
        if ($v -is [pscustomobject]) {
            if (@($v.PSObject.Properties).Count -eq 0 -and $p.Name -notin 'fields', 'flags') { $Obj.($p.Name) = $null } else { Repair-EmptyObjects $v }
        }
    }
}

function Test-Empty {
    param($Value)
    ($null -eq $Value) -or (($Value -is [array]) -and @($Value).Count -eq 0)
}

# How each list in a boot record is merged with the copy in history: records are matched by identity ("key"), so a
# re-read that sees only part of a boot (log rollover, or a boot that started before this run's window) adds to what an
# earlier run saw instead of replacing it. "post" re-sorts and applies the same cap the collector applies.
$ByStart = { param($x) "$($x.startMs)" }
$MergeSpecs = @{
    'winlogon'               = @{ key = { param($x) "$($x.event)|$($x.subscriber)|$($x.startMs)" }; post = { param($a) $a | Sort-Object startMs, endMs, event, subscriber | Select-Object -First $TopSubscribers } }
    'degraders'              = @{ key = { param($x) "$($x.kind)|$($x.name)" }; post = { param($a) $a | Sort-Object { if ($null -ne $_.degradationMs) { $_.degradationMs } else { 0 } }, name -Descending | Select-Object -First $TopDegraders } }
    'issues'                 = @{ key = { param($x) "$($x.id)|$($x.t)" }; post = { param($a) $a | Sort-Object t, id | Select-Object -First $TopIssues } }
    'logon.tasks'            = @{ key = { param($x) "$($x.name)|$($x.startMs)" }; post = { param($a) $a | Sort-Object @{ e = 'durMs'; Descending = $true }, name | Select-Object -First $TopTasks } }
    'logon.shellPhases'      = @{ key = { param($x) "$($x.name)|$($x.startMs)" }; post = { param($a) $a | Sort-Object startMs, endMs, name } }
    'logon.startupBatches'   = @{ key = { param($x) "$($x.name)|$($x.startMs)" }; post = { param($a) $a | Sort-Object startMs, name } }
    'logon.startupApps'      = @{ key = { param($x) "$($x.command)|$($x.startMs)" }; post = { param($a) $a | Sort-Object @{ e = 'durMs'; Descending = $true }, command | Select-Object -First $TopApps } }
    'logon.sessions'         = @{ key = $ByStart; post = { param($a) $a | Sort-Object startMs } }
    'policy.runs'            = @{ key = { param($x) "$($x.activityId)" }; post = { param($a) $a | Sort-Object startMs } }
    'policy.system'          = @{ key = { param($x) "$($x.id)|$($x.t)" }; post = { param($a) $a | Sort-Object t, id } }
    'network.connects'       = @{ key = { param($x) "$($x.t)" }; post = { param($a) $a | Sort-Object t | Select-Object -First 5 } }
    'mdm.sessions'           = @{ key = $ByStart; post = { param($a) $a | Sort-Object startMs } }
    'mdm.policies'           = @{ key = { param($x) "$($x.t)|$($x.op)|$($x.policy)|$($x.area)|$($x.scope)" }; post = { param($a) $a | Sort-Object t, policy | Select-Object -First $TopMdmPolicies } }
    'mdm.bursts'             = @{ key = $ByStart; post = { param($a) $a | Sort-Object startMs } }
    'mdm.areas'              = @{ key = { param($x) "$($x.name)" }; prefer = 'count'; post = { param($a) $a | Sort-Object @{ e = 'count'; Descending = $true }, name | Select-Object -First 40 } }
    'mdm.errors'             = @{ key = { param($x) "$($x.id)|$($x.t)" }; post = { param($a) $a | Sort-Object t, id | Select-Object -First $TopMdmErrors } }
    'ime.units'              = @{ key = { param($x) "$($x.kind)|$($x.id)|$($x.log)|$($x.startMs)" }; post = { param($a) $a | Sort-Object @{ e = 'durMs'; Descending = $true }, startMs | Select-Object -First $TopImeUnits | Sort-Object startMs } }
    'ime.files'              = @{ key = { param($x) "$($x.name)" }; prefer = 'lines'; post = { param($a) $a | Sort-Object firstMs, name } }
    'ime.errors'             = @{ key = { param($x) "$($x.text)" }; prefer = 'count'; post = { param($a) $a | Sort-Object @{ e = 'count'; Descending = $true }, text | Select-Object -First 12 } }
    'shutdownPerf.degraders' = @{ key = { param($x) "$($x.kind)|$($x.name)" }; post = { param($a) $a | Sort-Object { if ($null -ne $_.degradationMs) { $_.degradationMs } else { 0 } }, name -Descending | Select-Object -First $TopDegraders } }
}
$MergeMax = @('logon.failedAuth', 'mdm.policyCount')          # counts: the larger one saw more
$MergeMin = @('ime.firstMs', 'network.firstConnectedMs')       # first-seen times: the earlier one saw more

function Get-Completeness {
    # how many properties carry a value - a partial re-read of the same record has fewer
    param($X)
    if ($X -isnot [pscustomobject]) { return 0 }
    @($X.PSObject.Properties | Where-Object { -not (Test-Empty $_.Value) -and "$($_.Value)" -ne '' }).Count
}

function Merge-List {
    # Union of two lists by record identity. On a match the more complete record wins (ties: $New).
    param($New, $Old, $Spec)
    $map = [ordered]@{}
    foreach ($x in @($Old)) { if ($null -ne $x) { $map[[string](& $Spec.key $x)] = $x } }
    foreach ($x in @($New)) {
        if ($null -eq $x) { continue }
        $k = [string](& $Spec.key $x)
        if ($map.Contains($k)) {
            $o = $map[$k]
            $keepOld = if ($Spec.prefer) { [double]$o.($Spec.prefer) -gt [double]$x.($Spec.prefer) } else { (Get-Completeness $o) -gt (Get-Completeness $x) }
            if (-not $keepOld) { $map[$k] = $x }
        }
        else { $map[$k] = $x }
    }
    $items = @($map.Values)
    @(& $Spec.post $items)
}

function Merge-Section {
    # Fill properties missing (null / empty) in $New from $Old - one level deep; lists are merged record by record.
    param($New, $Old, [string]$Path)
    if ($null -eq $Old) { return $New }
    if ($null -eq $New) { return $Old }
    if ($New -isnot [pscustomobject] -or $Old -isnot [pscustomobject]) { return $New }
    foreach ($p in $Old.PSObject.Properties) {
        $np = $New.PSObject.Properties[$p.Name]
        $key = "$Path.$($p.Name)"
        $spec = $MergeSpecs[$key]
        if ($np -and $spec -and -not (Test-Empty $np.Value) -and -not (Test-Empty $p.Value)) {
            $New.($p.Name) = @(Merge-List $np.Value $p.Value $spec)
        }
        elseif ($np -and $null -ne $np.Value -and $null -ne $p.Value -and ($key -in $MergeMax -or $key -in $MergeMin)) {
            $a = [double]$np.Value; $b = [double]$p.Value
            if (($key -in $MergeMax -and $b -gt $a) -or ($key -in $MergeMin -and $b -lt $a)) { $New.($p.Name) = $p.Value }
        }
        elseif ((-not $np -or (Test-Empty $np.Value)) -and -not (Test-Empty $p.Value)) {
            if ($np) { $New.($p.Name) = $p.Value } else { $New | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
        }
    }
    $New
}

function Merge-Boot {
    # Keep whatever an earlier run saw that this run no longer can (logs roll over). Derived fields are rebuilt.
    # $New wins where both have a value; for a boot this run saw only part of, the caller passes the history copy as $New.
    param($New, $Old)
    if ($null -eq $Old) { return $New }
    foreach ($p in $Old.PSObject.Properties) {
        if ($p.Name -in 'phases', 'totals') { continue }
        $np = $New.PSObject.Properties[$p.Name]
        if (-not $np) { $New | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value; continue }
        $spec = $MergeSpecs[$p.Name]
        if (Test-Empty $np.Value) { $New.($p.Name) = $p.Value }
        elseif ($spec -and -not (Test-Empty $p.Value)) { $New.($p.Name) = @(Merge-List $np.Value $p.Value $spec) }
        elseif ($np.Value -is [pscustomobject]) { $New.($p.Name) = Merge-Section $np.Value $p.Value $p.Name }
    }
    Update-Merged $New
}

function Update-Merged {
    # Counts and summaries that depend on merged lists are rebuilt from them.
    param($Boot)
    $lg = $Boot.logon
    if ($lg -and $lg.PSObject.Properties['sessions']) {
        $n = @($lg.sessions | Where-Object { $_ }).Count
        if ($lg.PSObject.Properties['sessionCount']) { $lg.sessionCount = $n } else { $lg | Add-Member -NotePropertyName sessionCount -NotePropertyValue $n }
    }
    $m = $Boot.mdm
    if ($m -and $m.PSObject.Properties['policyCount']) {
        $n = @($m.policies | Where-Object { $_ }).Count
        if ($null -eq $m.policyCount -or $n -gt $m.policyCount) { $m.policyCount = $n }
    }
    $po = $Boot.policy
    if ($po -and ((Test-Empty $po.runs) -eq $false -or (Test-Empty $po.system) -eq $false)) {
        foreach ($sc in 'machine', 'user') {
            $s = Get-PolicySummary @($po.runs) @($po.system) $sc
            if ($s) { if ($po.PSObject.Properties[$sc]) { $po.$sc = $s } else { $po | Add-Member -NotePropertyName $sc -NotePropertyValue $s } }
        }
    }
    $Boot
}

# ---------------------------------------------------------------- device

function Get-DeviceInfo {
    # deviceId = MachineGuid (local, stable); entraDeviceId / intuneDeviceId are what Endpoint Analytics and Intune
    # reports key on; serial is what a helpdesk keys on.
    $d = [ordered]@{
        name = $env:COMPUTERNAME; deviceId = $null; serial = $null; entraDeviceId = $null; intuneDeviceId = $null
        manufacturer = $null; model = $null; ramGb = $null; cpu = $null; bios = $null
        os = $null; build = $null; joinType = $null; tenant = $null; tenantId = $null; mdm = $null; ime = $null; fastStartup = $null
        systemDisk = $null; elevated = $false; system = $IsSystem; psVersion = $PSVersionTable.PSVersion.ToString(); windowMinutes = $WindowMinutes
        anonymized = [bool]$Anonymize
    }
    try { $d.elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
    try { $d.deviceId = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid } catch { }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $d.manufacturer = $cs.Manufacturer; $d.model = $cs.Model; $d.ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB)
        $d.joinType = if ($cs.PartOfDomain) { 'Domain' } else { 'Workgroup' }
    } catch { }
    try { $d.cpu = (@(Get-CimInstance Win32_Processor)[0].Name -replace '\s+', ' ').Trim() } catch { }
    try {
        $b = Get-CimInstance Win32_BIOS; $d.bios = ("{0} {1}" -f $b.Manufacturer, $b.SMBIOSBIOSVersion).Trim()
        $sn = "$($b.SerialNumber)".Trim()
        if ($sn -and $sn -notmatch '(?i)to be filled|default string|^0+$|^none$') { $d.serial = $sn }
    } catch { }
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
        $d.os = $os.Caption; $d.build = "$($os.BuildNumber).$ubr"
    } catch { }
    try {
        # stderr is redirected inside cmd.exe on purpose: in Windows PowerShell 5.1 with $ErrorActionPreference = 'Stop',
        # a native command writing to a PowerShell-redirected stderr (2>$null) throws, which would silently lose all of this
        $ds = (& "$env:WINDIR\System32\cmd.exe" /d /c dsregcmd.exe /status '2>nul') -join "`n"
        $aad = $ds -match 'AzureAdJoined\s*:\s*YES'; $dom = $ds -match 'DomainJoined\s*:\s*YES'
        if ($aad -and $dom) { $d.joinType = 'Hybrid joined' } elseif ($aad) { $d.joinType = 'Entra joined' } elseif ($dom) { $d.joinType = 'Domain joined' }
        $m = [regex]::Match($ds, 'TenantName\s*:\s*(.+)'); if ($m.Success -and $m.Groups[1].Value.Trim()) { $d.tenant = $m.Groups[1].Value.Trim() }
        $m = [regex]::Match($ds, 'TenantId\s*:\s*([0-9a-fA-F-]{36})'); if ($m.Success) { $d.tenantId = $m.Groups[1].Value }
        $m = [regex]::Match($ds, '\bDeviceId\s*:\s*([0-9a-fA-F-]{36})'); if ($m.Success) { $d.entraDeviceId = $m.Groups[1].Value }
    } catch { }
    try {
        foreach ($e in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop) {
            $p = Get-ItemProperty $e.PSPath
            if ($p.ProviderID -eq 'MS DM Server') {
                $d.mdm = 'Intune'
                try { $id = (Get-ItemProperty (Join-Path $e.PSPath 'DMClient\MS DM Server') -ErrorAction Stop).EntDMID; if ($id) { $d.intuneDeviceId = [string]$id } } catch { }
                break
            }
            if ($p.ProviderID -and $p.DiscoveryServiceFullURL) { $d.mdm = [string]$p.ProviderID }
        }
    } catch { }
    try {
        $imeExe = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe'
        if (Test-Path $imeExe) { $d.ime = (Get-Item $imeExe).VersionInfo.FileVersion }
    } catch { }
    try { $d.fastStartup = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop).HiberbootEnabled } catch { }
    try {
        $pd = Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | Get-Disk | Get-PhysicalDisk | Select-Object -First 1
        $d.systemDisk = ("{0} {1}" -f $pd.MediaType, $pd.BusType).Trim()
    } catch { }
    $d
}

function Test-SameDevice {
    # Is a saved history from this device? MachineGuid and BIOS serial decide when both sides have them (a renamed device
    # is still the same device, a cloned image with a copied MachineGuid but another serial is not); the computer name
    # is only the fallback for files that carry neither.
    param($Saved, $Current)
    if (-not $Saved) { return $false }
    $strong = $false
    foreach ($k in 'deviceId', 'serial') {
        $a = "$($Saved.$k)"; $b = "$($Current.$k)"
        if ($a -and $b) { if ($a -ne $b) { return $false }; $strong = $true }
    }
    if ($strong) { return $true }
    [bool]($Saved.name -and $Saved.name -eq $Current.name)
}

function Test-BootRecord {
    # Minimal shape check before an earlier record is trusted: valid JSON is not necessarily a BootView boot.
    param($Boot)
    ($Boot -is [pscustomobject]) -and ($Boot.id -is [long] -or $Boot.id -is [int] -or $Boot.id -is [decimal] -or $Boot.id -is [double]) -and
    ($Boot.bootStartMs -is [long] -or $Boot.bootStartMs -is [int] -or $Boot.bootStartMs -is [decimal] -or $Boot.bootStartMs -is [double]) -and
    [long]$Boot.id -eq [long]$Boot.bootStartMs -and [long]$Boot.bootStartMs -gt 946684800000
}

function Write-Report {
    # Embeds the JSON into the viewer template and writes a single self-contained HTML file. Returns its path.
    param([string]$Json)
    $template = Join-Path $ScriptRoot 'viewer\report-template.html'
    if (-not (Test-Path $template)) { Write-RunLog "Report template not found at $template; wrote JSON only." 'WARN'; return $null }
    $html = [IO.File]::ReadAllText($template, (New-Object System.Text.UTF8Encoding($false)))
    # The JSON sits inside a <script> block. "\u003c" is the same character to JSON.parse but cannot close that block
    # or open a comment, which a "</script>" inside a service name or startup command would otherwise do.
    # Windows PowerShell 5.1 escapes "<" in ConvertTo-Json by itself; PowerShell 7 and -ReportOnly do not.
    $safe = $Json.Replace('<', '\u003c')
    $path = Join-Path $OutputDir 'BootView-Report.html'
    Write-FileAtomic $path $html.Replace('__BOOTVIEW_DATA__', $safe)
    $path
}

# ================================================================= main

$exitCode = 0
$runLock = $null
try {
    Initialize-Log $OutputDir
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $historyPath = Join-Path $OutputDir 'history.json'
    $latestPath = Join-Path $OutputDir 'latest.json'

    # One run at a time per output folder: two runs would each read history, merge and write, and one would lose the
    # other's update. The lock is an exclusively opened file, released when this process exits (also when killed).
    $lockPath = Join-Path $OutputDir 'BootView.lock'
    $lockUntil = (Get-Date).AddSeconds(120)
    while (-not $runLock) {
        try { $runLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] {
            $ie = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
            if ($ie -is [IO.DirectoryNotFoundException] -or $ie -is [IO.PathTooLongException]) { throw }     # not a lock held by another run
            if ((Get-Date) -gt $lockUntil) { throw "Another BootView run is still using $OutputDir (waited 120 s)." }
            Start-Sleep -Milliseconds 500
        }
    }

    if ($ReportOnly) {
        if (-not (Test-Path $historyPath)) { throw "No history at $historyPath - run the collector first." }
        $json = [IO.File]::ReadAllText($historyPath, $utf8)
        if ($Anonymize) {
            # -ReportOnly -Anonymize: the report is scrubbed; history.json on disk is left as it is
            $h = $json | ConvertFrom-Json
            $rb = @($h.boots | Where-Object { $_ })
            foreach ($b in $rb) { Repair-EmptyObjects $b; Register-BootNames $b }
            foreach ($b in $rb) { Protect-Boot $b }
            $h.boots = $rb
            if ($h.device) { if ($h.device.PSObject.Properties['anonymized']) { $h.device.anonymized = $true } else { $h.device | Add-Member -NotePropertyName anonymized -NotePropertyValue $true } }
            $json = ConvertTo-Json -InputObject $h -Depth 32 -Compress
        }
        $reportPath = Write-Report $json
        Write-RunLog "Report:   $reportPath"
        if ($Open -and $reportPath) { Start-Process $reportPath }
        $runLock.Dispose(); $runLock = $null
        exit 0
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $device = Get-DeviceInfo

    # Existing history is read first: a later run only needs the logs written since the previous one.
    $old = @{}; $prevCollectedMs = $null; $oldFields = $null; $prevAnonymized = $false
    if (Test-Path $historyPath) {
        $h = $null
        try {
            # read as UTF-8 explicitly: Windows PowerShell 5.1's Get-Content treats BOM-less files as ANSI
            $h = [IO.File]::ReadAllText($historyPath, $utf8) | ConvertFrom-Json
            if ($h -isnot [pscustomobject] -or ($h.tool -and $h.tool -ne 'BootView') -or -not $h.PSObject.Properties['boots']) { throw 'not a BootView history file' }
        }
        catch {
            $bak = '{0}.{1:yyyyMMdd-HHmmss}.bak' -f $historyPath, (Get-Date)
            Write-RunLog "Could not read existing history ($($_.Exception.Message)); keeping it as $bak and starting fresh." 'WARN'
            Move-Item -LiteralPath $historyPath -Destination $bak -Force
            $h = $null
        }
        if ($h -and $h.device -and -not (Test-SameDevice $h.device $device)) {
            # another device's history (a copied or shared output folder): never relabel it as this device
            $q = '{0}.foreign-{1}-{2:yyyyMMdd-HHmmss}.json' -f ($historyPath -replace '\.json$', ''), ($h.device.name -replace '[^\w.-]', '_'), (Get-Date)
            Write-RunLog "history.json belongs to another device ($($h.device.name)); moved it to $q and starting fresh. Use one output folder per device." 'WARN'
            Move-Item -LiteralPath $historyPath -Destination $q -Force
            $h = $null
        }
        if ($h) {
            $bad = 0
            foreach ($b in @($h.boots)) {
                if (-not (Test-BootRecord $b)) { $bad++; continue }
                Repair-EmptyObjects $b
                foreach ($k in 'phases', 'totals') { if (-not $b.PSObject.Properties[$k]) { $b | Add-Member -NotePropertyName $k -NotePropertyValue $null } }
                $old[[string]$b.id] = $b
            }
            if ($bad) { Write-RunLog "Skipped $bad malformed boot record(s) in history.json." 'WARN' }
            if ($h.collectedMs) { $prevCollectedMs = [long]$h.collectedMs }
            $oldFields = $h.fieldsSeen
            $prevAnonymized = ($h.device -and $h.device.anonymized -eq $true)
        }
    }
    foreach ($b in $old.Values) { Register-BootNames $b }          # -Anonymize: learn names from non-anonymised records
    $since = (Get-Date).AddDays(-$Days)
    $incremental = $false
    if (-not $FullRescan -and $prevCollectedMs) {
        $resume = [DateTimeOffset]::FromUnixTimeMilliseconds($prevCollectedMs).LocalDateTime.AddDays(-$IncrementalOverlapDays)
        if ($resume -gt $since) { $since = $resume; $incremental = $true }
    }
    Write-RunLog ('BootView {0} on {1}: reading logs since {2:yyyy-MM-dd HH:mm}{3}; elevated: {4}; PowerShell {5}' -f $ToolVersion, $device.name, $since,
        $(if ($incremental) { ' (incremental; -FullRescan re-reads everything)' } else { '' }), $device.elevated, $device.psVersion)

    $mdmLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider'
    $bootRows  = @(Read-Events -Label 'System: Kernel-General 12/13' -LogName 'System' -Provider 'Microsoft-Windows-Kernel-General' -Id 12, 13 -Since $since)
    $kbRows    = @(Read-Events -Label 'System: Kernel-Boot'          -LogName 'System' -Provider 'Microsoft-Windows-Kernel-Boot' -Id 20, 27, 30, 32 -Since $since)
    $gpSysRows = @(Read-Events -Label 'System: Group Policy'         -LogName 'System' -Provider 'Microsoft-Windows-GroupPolicy' -Id 1006, 1030, 1053, 1054, 1055, 1058, 1085, 1096, 1112, 1125, 1129, 1500, 1501, 1502, 1503 -Since $since -WithMessage)
    $u32Rows   = @(Read-Events -Label 'System: shutdown requests'    -LogName 'System' -Provider 'User32' -Id 1074 -Since $since)
    $scmRows   = @(Read-Events -Label 'System: service failures'     -LogName 'System' -Provider 'Service Control Manager' -Id 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7034, 7038, 7043 -Since $since -WithMessage)
    $pwrRows   = @(Read-Events -Label 'System: Kernel-Power 41'      -LogName 'System' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Since $since -WithMessage)
    $pwrRows  += @(Read-Events -Label 'System: EventLog 6008'        -LogName 'System' -Provider 'EventLog' -Id 6008 -Since $since -WithMessage)
    $authRows  = @(Read-Events -Label 'Winlogon'                     -LogName 'Microsoft-Windows-Winlogon/Operational' -Id 1, 2, 811, 812 -Since $since)
    $profRows  = @(Read-Events -Label 'User Profile Service'         -LogName 'Microsoft-Windows-User Profile Service/Operational' -Id 1, 2, 67 -Since $since)
    $shellRows = @(Read-Events -Label 'Shell-Core'                   -LogName 'Microsoft-Windows-Shell-Core/Operational' -Id 62170, 62171, 9648, 9649, 9652, 9653, 9703, 9704, 9705, 9706, 9707, 9708, 62408, 62409 -Since $since)
    $netRows   = @(Read-Events -Label 'Network'                      -LogName 'Microsoft-Windows-NetworkProfile/Operational' -Id 10000 -Since $since)
    $aadRows   = @(Read-Events -Label 'Entra ID (AAD)'               -LogName 'Microsoft-Windows-AAD/Operational' -Id 1081, 1082, 1088, 1097, 1098, 1104 -Since $since -WithMessage)
    $mdmRows   = @(Read-Events -Label 'Intune MDM: policies'         -LogName "$mdmLog/Admin" -Id 404, 454, 813, 814, 815, 819, 821, 1924 -Since $since)
    $mdmRows  += @(Read-Events -Label 'Intune MDM: sync sessions'    -LogName "$mdmLog/Sync" -Id 201, 208, 209 -Since $since)
    $perfRows  = @(Read-Events -Label 'Diagnostics-Performance'      -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -Id 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 200, 201, 202, 203 -Since $since)
    $gpRows    = @(Read-Events -Label 'Group Policy'                 -LogName 'Microsoft-Windows-GroupPolicy/Operational' -Id 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007, 4016, 5016, 6016, 7016, 5017, 7017, 5126, 5257, 5308, 5311, 5312, 5313, 5314, 5326, 7326, 5340, 5351, 7320, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007 -Since $since)
    $imeRows   = @(Read-ImeLogs -Since $since)
    $imeSrc = $script:Sources['Intune Management Extension']
    if ($script:ImeStats.Count -and $imeSrc) {
        $matched = 'Matched: ' + (($script:ImeStats.GetEnumerator() | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join '; ')
        $imeSrc.message = if ($imeSrc.message) { "$($imeSrc.message) $matched" } else { $matched }
    }

    $starts = @($bootRows | Where-Object { $_.Id -eq 12 } | Sort-Object T | ForEach-Object { [long]$_.T })
    $newStarts = $starts.Count

    # The boot that was already running when this run's window begins: its start (event 12) is older than $since, but
    # its later events (more sign-ins, policy refreshes, its shutdown) are in the window. Without its start they would be
    # dropped, or land in no boot at all. Its start comes from the System log if it is still there, else from history.
    # Only a boot history already knows is updated - a boot seen only in part has no record to complete.
    $sinceMs = ConvertTo-EpochMs $since
    $carry = $null
    try {
        $pe = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12; EndTime = $since } -MaxEvents 1 -ErrorAction Stop
        if ($pe) { $carry = ConvertTo-EpochMs @($pe)[0].TimeCreated }
    } catch { }
    if (-not $carry) {
        $prior = @($old.Values | Where-Object { [long]$_.bootStartMs -lt $sinceMs } | ForEach-Object { [long]$_.bootStartMs } | Sort-Object)
        if ($prior.Count) { $carry = $prior[-1] }
    }
    $carryKnown = $false
    if ($carry -and ($starts.Count -eq 0 -or $carry -lt $starts[0])) {
        $carryKnown = $old.ContainsKey([string]$carry)
        $starts = @([long]$carry) + $starts               # its bucket also keeps its rows away from the next boot
    }
    else { $carry = $null }

    $collected = New-Object System.Collections.Generic.List[object]
    $partialIds = @{}
    if ($newStarts -eq 0 -and -not $carryKnown) {
        if ($old.Count -eq 0) { throw 'No boot events (Kernel-General 12) found in the System log for the requested range.' }
        Write-RunLog 'No boots in the log window; refreshing history and report from earlier runs.'
    }
    else {
        # Diagnostics-Performance writes its boot / shutdown traces minutes later: attribute them by the trace's own start time.
        foreach ($r in $perfRows) {
            if ($r.Id -eq 100) { $a = ConvertFrom-IsoTime $r.D['BootStartTime']; if ($a) { $r.A = $a + 5000 } }        # kernel start precedes event 12
            elseif ($r.Id -eq 200) { $a = ConvertFrom-IsoTime $r.D['ShutdownStartTime']; if ($a) { $r.A = $a } }
        }
        Get-NearestAnchor $perfRows @(100) @(101, 102, 103, 104, 105, 106, 107, 108, 109, 110)
        Get-NearestAnchor $perfRows @(200) @(201, 202, 203)

        $bAuth = Split-ByBoot $authRows $starts;  $bProf = Split-ByBoot $profRows $starts
        $bShell = Split-ByBoot $shellRows $starts; $bPerf = Split-ByBoot $perfRows $starts
        $bGp = Split-ByBoot $gpRows $starts;      $bKb = Split-ByBoot $kbRows $starts
        $bBoot = Split-ByBoot $bootRows $starts;  $bGpSys = Split-ByBoot $gpSysRows $starts
        $bU32 = Split-ByBoot $u32Rows $starts;    $bNet = Split-ByBoot $netRows $starts
        $bMdm = Split-ByBoot $mdmRows $starts;    $bIme = Split-ByBoot $imeRows $starts
        $bIssue = Split-ByBoot (@($scmRows) + @($pwrRows) + @($aadRows)) $starts

        for ($i = 0; $i -lt $starts.Count; $i++) {
            $s0 = $starts[$i]
            $isCarry = ($null -ne $carry -and $s0 -eq $carry)
            if ($isCarry -and -not $carryKnown) { continue }        # rows of a boot history never saw: leave them out
            $shut = $bBoot[$i] | Where-Object { $_.Id -eq 13 } | Select-Object -First 1
            $k12 = $bBoot[$i] | Where-Object { $_.Id -eq 12 } | Select-Object -First 1
            $typ = $bKb[$i] | Where-Object { $_.Id -eq 27 } | Select-Object -First 1
            $logon = Build-Logon -Shell $bShell[$i] -ProfRows $bProf[$i] -Auth $bAuth[$i]

            # background work counts for this boot while it is near boot start or near sign-in. For the carried-over
            # boot, "sign-in" is the primary sign-in history recorded, not whichever later session this run sees first.
            $ls = if ($logon -and $logon.auth) { [long]$logon.auth.startMs } elseif ($logon -and $logon.profile) { [long]$logon.profile.startMs } else { $null }
            if ($isCarry) {
                $ol = $old[[string]$s0].logon
                $ls = if ($ol -and $ol.auth -and $ol.auth.startMs) { [long]$ol.auth.startMs } elseif ($ol -and $ol.profile -and $ol.profile.startMs) { [long]$ol.profile.startMs } else { $null }
                $partialIds[[string]$s0] = 1
            }
            $inWin = { param($t) ($t -le $s0 + $WindowMs) -or ($ls -and $t -ge $ls - 60000 -and $t -le $ls + $WindowMs) }
            $win = { param($rows) @($rows | Where-Object { & $inWin $_.T }) }
            $gpWin = @($bGp[$i] | Where-Object { & $inWin $_.T })
            # keep whole GP runs: if any event of a run is in the window, keep all its events
            $gpActs = @{}; foreach ($r in $gpWin) { if ($r.Act) { $gpActs[$r.Act] = 1 } }
            $gpKeep = @($bGp[$i] | Where-Object { $_.Act -and $gpActs.ContainsKey($_.Act) })

            $boot = [pscustomobject]@{
                id            = $s0
                bootStartMs   = $s0
                kernelStartMs = if ($k12) { ConvertFrom-IsoTime $k12.D['StartTime'] } else { $null }
                shutdownMs    = if ($shut) { $shut.T } else { $null }
                bootType      = if ($typ -and $null -ne (ConvertTo-Number $typ.D['BootType'])) { [int](ConvertTo-Number $typ.D['BootType']) } else { $null }
                firmware      = Build-Firmware $bKb[$i]
                perf          = Build-Perf $bPerf[$i] $s0
                degraders     = @(Build-Degraders $bPerf[$i] @(101, 102, 103, 104, 105, 106, 107, 108, 109, 110))
                shutdownPerf  = Build-ShutdownPerf $bPerf[$i]
                shutdownReason = Build-ShutdownReason $bU32[$i]
                policy        = Build-Policy $gpKeep (& $win $bGpSys[$i])
                winlogon      = @(Build-Winlogon $bAuth[$i])
                logon         = $logon
                network       = Build-Network (& $win $bNet[$i])
                mdm           = Build-Mdm (& $win $bMdm[$i])
                ime           = Build-Ime (& $win $bIme[$i])
                issues        = @(Build-Issues (& $win $bIssue[$i]))
                phases        = @()
                totals        = $null
            }
            foreach ($k in 'firmware', 'perf', 'shutdownPerf', 'shutdownReason', 'policy', 'logon', 'network', 'mdm', 'ime') {
                if (-not $boot.$k) { $boot.$k = $null }      # AutomationNull -> real null (5.1 would serialise {} otherwise)
            }
            $collected.Add($boot)
        }
    }

    # merge with history so the record outlives event-log rollover
    $merged = @{}
    $oldIds = @{}; foreach ($k in $old.Keys) { $oldIds[$k] = 1 }
    foreach ($b in $collected) {
        $key = [string]$b.id
        # a boot this run saw only part of: what history recorded wins, this run adds what is new (sessions, shutdown, ...)
        $merged[$key] = if ($partialIds.ContainsKey($key)) { Merge-Boot $old[$key] $b } else { Merge-Boot $b $old[$key] }
        $old.Remove($key)
    }
    foreach ($key in $old.Keys) {
        $ob = $old[$key]
        foreach ($k in 'firmware', 'winlogon', 'network', 'mdm', 'ime', 'issues', 'shutdownPerf', 'shutdownReason', 'kernelStartMs') {
            if (-not $ob.PSObject.Properties[$k]) { $ob | Add-Member -NotePropertyName $k -NotePropertyValue $null }     # schema-1 boots
        }
        $merged[$key] = $ob                                                         # boots older than this run's window
    }
    $boots = @($merged.Values | Sort-Object bootStartMs)
    if ($boots.Count -gt $MaxHistoryBoots) { $boots = @($boots | Select-Object -Last $MaxHistoryBoots) }     # trim before deriving
    # -Anonymize covers values merged in from older runs too; records an earlier anonymised run wrote and this run did
    # not touch are already scrubbed
    $touched = @{}; foreach ($b in $collected) { $touched[[string]$b.id] = 1 }
    foreach ($b in $boots) { if (-not $prevAnonymized -or $touched.ContainsKey([string]$b.id)) { Protect-Boot $b } }
    $boots = @($boots | ForEach-Object { Add-Derived $_ })

    $collectedMs = ConvertTo-EpochMs (Get-Date)
    $newIds = @{}; foreach ($b in $collected) { $newIds[[string]$b.id] = 1 }
    $newCount = @($collected | Where-Object { -not $oldIds.ContainsKey([string]$_.id) }).Count
    # field names seen by this and earlier runs, so the schema diagnostics outlive log rollover too
    if ($oldFields -is [pscustomobject]) {
        foreach ($p in $oldFields.PSObject.Properties) {
            $script:FieldsSeen[$p.Name] = @(@($p.Value) + @($script:FieldsSeen[$p.Name]) | Where-Object { $_ } | Sort-Object -Unique)
        }
    }
    $payload = {
        param($bootList)
        [pscustomobject]@{
            schema      = $SchemaVersion
            tool        = 'BootView'
            toolVersion = $ToolVersion
            collectedMs = $collectedMs
            device      = $device
            sources     = $script:Sources
            fieldsSeen  = $script:FieldsSeen
            boots       = $bootList
        }
    }
    $json = ConvertTo-Json -InputObject (& $payload $boots) -Depth 32 -Compress
    Write-FileAtomic $historyPath $json
    # latest.json: only the boots seen on this run - small enough to ship to a share or Log Analytics after every run
    $latest = @($boots | Where-Object { $newIds.ContainsKey([string]$_.id) })
    Write-FileAtomic $latestPath (ConvertTo-Json -InputObject (& $payload $latest) -Depth 32 -Compress)

    $reportPath = $null
    if (-not $NoReport) { $reportPath = Write-Report $json }

    # ---------------------------------------------------------------- console summary
    Write-RunLog ''
    Write-RunLog 'Sources:'
    foreach ($k in $script:Sources.Keys) {
        $s = $script:Sources[$k]
        $line = '  {0,-30} {1,-8} {2,6} events' -f $k, $s.status, $s.events
        if ($s.message) { $line += "  - $(Limit-Text $s.message 110)" }
        Write-RunLog $line
    }
    $fmt = { param($ms) if ($null -eq $ms) { '-' } else { '{0:N1}s' -f ($ms / 1000) } }
    Write-RunLog ''
    Write-RunLog 'Recent boots:        type    firmware  to sign-in  wait     sign-in->ready  ready (excl. wait)  GP blocking'
    $boots | Select-Object -Last 10 | ForEach-Object {
        $t = $_.totals
        $type = switch ($_.bootType) { 0 { 'full' } 1 { 'fast' } 2 { 'resume' } default { '?' } }
        $gp = if ($null -ne $t.machinePolicyMs -or $null -ne $t.userPolicyMs) { & $fmt ([long]$t.machinePolicyMs + [long]$t.userPolicyMs) } else { '-' }
        '  {0:yyyy-MM-dd HH:mm}  {1,-6}  {2,8}  {3,10}  {4,7}  {5,14}  {6,18}  {7,11}' -f
        [DateTimeOffset]::FromUnixTimeMilliseconds($_.bootStartMs).LocalDateTime, $type, (& $fmt $t.firmwareMs), (& $fmt $t.coreBootMs), (& $fmt $t.signInWaitMs), (& $fmt $t.signInToReadyMs), (& $fmt $t.readyExclWaitMs), $gp
    } | ForEach-Object { Write-RunLog $_ }

    Write-RunLog ''
    Write-RunLog ("History:  {0}  ({1} boots: {2} new, {3} re-read on this run)" -f $historyPath, $boots.Count, $newCount, ($collected.Count - $newCount))
    Write-RunLog ("Latest:   {0}" -f $latestPath)
    if ($reportPath) { Write-RunLog ("Report:   {0}" -f $reportPath) }
    $deniedCount = @($script:Sources.Values | Where-Object { $_.status -eq 'denied' }).Count
    if (-not $device.elevated -and $deniedCount -gt 0) {
        Write-RunLog 'Some sources need elevation (boot trace, Group Policy detail, Intune Management Extension logs). Re-run from an elevated PowerShell, or as SYSTEM through Intune.' 'WARN'
    }
    $last = $boots[-1]
    $summary = 'BootView OK: {0} boots in history, {1} new, {2} re-read; last boot {3:yyyy-MM-dd HH:mm} ready in {4}; {5} source(s) need elevation; {6:N1}s' -f
        $boots.Count, $newCount, ($collected.Count - $newCount), [DateTimeOffset]::FromUnixTimeMilliseconds($last.bootStartMs).LocalDateTime, (& $fmt $last.totals.readyExclWaitMs), $deniedCount, $sw.Elapsed.TotalSeconds
    Write-RunLog $summary -NoConsole
    Write-Output $summary          # last line of stdout: Intune keeps it in the script / remediation output
    if ($Open -and $reportPath) { Start-Process $reportPath }
}
catch {
    $exitCode = 1
    $msg = 'BootView FAILED: {0} (line {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
    Write-RunLog $msg 'ERROR'
    Write-Output $msg
}
finally { if ($runLock) { $runLock.Dispose() } }
exit $exitCode
