# BootView

Breaks a Windows boot into every step from **power-on to a usable desktop** – firmware, Windows boot, each Group Policy run and extension, Intune (MDM) syncs and settings, Intune Management Extension scripts and apps, sign-in, profile, logon tasks and startup apps – using data Windows **already records**. Nothing is installed or enabled on the device.

Intune / Endpoint Analytics shows totals (core boot, core sign-in). BootView shows what is inside them, per boot and as medians across boots.

```powershell
.\Collect-BootData.ps1 -Open            # read logs, update history, build + open the HTML report
.\Collect-BootData.ps1 -ReportOnly      # rebuild the HTML from history.json (no log access)
.\Collect-BootData.ps1 -NoReport        # JSON only (Intune remediation / platform script)
.\Collect-BootData.ps1 -Anonymize       # hash account names, drop SIDs, hide profile folder names
```

Run it **elevated** (or as SYSTEM) to include the sources marked ★. Requires Windows PowerShell 5.1 or PowerShell 7 (`#Requires -Version 5.1`) and produces identical data on both.

| Option | Default | What |
|---|---|---|
| `-Days` | 60 | How far back to read on a first run. Later runs only read what was written since the previous run (plus a 2-day overlap); `-FullRescan` re-reads the whole window. |
| `-WindowMinutes` | 15 | How long after boot start and after sign-in background work (policy refreshes, Intune syncs, IME, failures) is attributed to the boot. |
| `-OutputDir` | `output\` next to the script; `%ProgramData%\BootView` as SYSTEM | Where the files below are written. |
| `-NoReport` / `-ReportOnly` / `-Open` | | JSON only / HTML only from existing history / open the report. |
| `-Anonymize` | off | Account names become a stable hash (`user-3f9a…`), SIDs are dropped, `C:\Users\<name>\` becomes `C:\Users\~\` in commands and paths. Also scrubs records from earlier, non-anonymised runs. |

## Output

| File | What |
|---|---|
| `history.json` | One record per boot. Merged across runs, so it outlives event-log rollover. Times are Unix epoch ms (UTC), durations are ms. `schema` (3), `toolVersion`, `device` (name, serial, Entra device ID, Intune device ID, tenant ID, …) and `sources` make it safe to collect from many machines. Written atomically (temp file + rename). |
| `latest.json` | Same shape, only the boots seen on this run. Small enough to ship to a share or Log Analytics after every run. |
| `BootView-Report.html` | Single self-contained page (no network, no CDN): stacked timeline per boot, a power-on-to-desktop waterfall for any boot, Group Policy / Intune / IME detail, typical times across boots, table with CSV export (device identity on every row, so exports from many devices concatenate). |
| `BootView.log` | What each run did, rolled over at 1 MB. The last line on stdout is a one-line summary, `BootView OK: …` or `BootView FAILED: …`. |

Exit code is 0 on success and 1 on failure.

## Intune

Deploy `Collect-BootData.ps1` together with the `viewer` folder (or with `-NoReport`, on its own) – no parameters are required. Intune runs scripts in 32-bit PowerShell by default; the collector relaunches itself as 64-bit and passes the exit code through. Running as SYSTEM it writes to `%ProgramData%\BootView` (Intune deletes its own script folder after each run), and the ★ sources are included.

- **Platform script** – runs once per device; good for a first 60-day baseline.
- **Remediation** – use the collector as the *detection* script with `-NoReport` (and `-Anonymize` if required): it collects, exits 0 ("compliant") and the last output line (`BootView OK: 69 boots in history, 1 new; …`) shows in the remediation report per device. Schedule it daily; each run reads only the new logs. A remediation script is not needed; if you supply one, it only runs when the collector exits 1.
- **Signing** – the script is not signed. Tenants that enforce *AllSigned* must sign it (`Set-AuthenticodeSignature`) before upload; the 64-bit relaunch uses `-ExecutionPolicy Bypass`, which such tenants may also block by policy.
- **Troubleshooting** – `%ProgramData%\BootView\BootView.log` on the device, and the Intune Management Extension log for the script output.

## What it measures

| Step / detail | Source | Admin |
|---|---|---|
| Firmware (POST) and boot manager + OS loader, BitLocker PIN wait | System: Kernel-Boot 30, 32 | no |
| Boot start / shutdown, boot type, previous shutdown clean? | Kernel-General 12/13, Kernel-Boot 20/27 | no |
| **What startup and sign-in waited for** – each Winlogon subscriber (GPClient = synchronous Group Policy, Profiles = profile load, …) | Winlogon/Operational 811/812 | no |
| Sign-in screen ready, time waiting for the user, authentication | Winlogon/Operational 1/2, 811/812 | no |
| Profile load, who signed in, profile type; one record per session on shared devices | User Profile Service/Operational 1/2/67 | no |
| Logon tasks, shell phases, RunOnce, startup apps (Run keys + packaged startup tasks) | Shell-Core/Operational | no |
| Group Policy result and total time per run, failures (scope from the event's SID, so it works on any OS language) | System: GroupPolicy 1500–1503, 10xx | no |
| Network connected | NetworkProfile/Operational 10000 | no |
| Intune MDM sync sessions; every MDM setting written; MDM failures | DeviceManagement-Enterprise-Diagnostics-Provider Sync 208/209, Admin 813–819, 404/454/821/1924 | no |
| Shutdown / restart requested by (process, reason, user) | System: User32 1074 | no |
| Services that failed or timed out, drivers that didn't load, unexpected shutdowns, Entra ID token errors | SCM 70xx, Kernel-Power 41, EventLog 6008, AAD/Operational | no |
| ★ Windows' boot trace (PnP, session init, main path, post-boot, sign-in wait) | Diagnostics-Performance 100 | **yes** |
| ★ What slowed boot (apps, drivers, services, devices, machine / user policy, …) and shutdown | Diagnostics-Performance 101–110, 200–203 | **yes** |
| ★ Every Group Policy run (boot, logon, background, network change, manual): each client-side extension with its GPOs and result, applied / filtered GPOs, DC discovery, LDAP/SMB calls, link speed, loopback | GroupPolicy/Operational 4000–4007, 4016, 5016/6016/7016, 5017/7017, 5126, 5257, 5308–5314, 5326, 5351, 7320, 8000–8007 | **yes** |
| ★ Intune Management Extension: PowerShell scripts, remediations, Win32 apps and check-ins, with duration, result and errors | `%ProgramData%\Microsoft\IntuneManagementExtension\Logs` | **yes** |

Background work (policy refreshes, Intune syncs, IME, failures) is attributed to a boot when it happens within `-WindowMinutes` (default 15) of boot start or of sign-in.

## Reading the numbers

- **Power-on → ready** = firmware + loader + Windows start → desktop ready, **excluding** the time the sign-in screen waited for the user. Use the "Sign-in screen wait: Include" toggle to add it back.
- **Windows start → sign-in screen** ends when Winlogon has finished its startup notifications (≈ Endpoint Analytics' core boot). **Sign-in → ready** runs from authentication to `AllLogonTasks` finishing (≈ core sign-in).
- **Computer / user policy (blocking)** is how long Winlogon waited on the GPClient subscriber – the policy time the user actually felt. The *total* processing time (GroupPolicy log or System log) also includes asynchronous / background work.
- Intune MDM settings and IME work run in the background; they show in the waterfall and their own cards but are not part of the stacked boot phases (unless an Enrollment Status Page blocks the desktop).
- Logon tasks, startup apps and shell phases overlap; their durations can add up to more than wall-clock time. Short gaps (< 150 ms) are folded into the next phase.
- "×N typical" compares an item with its median across the boots in view; the **Typical times across boots** card gives median / P90 / worst for every phase, GP extension, Winlogon subscriber, task, app and IME item.
- Event logs roll over (Shell-Core here reached back ~10 days). Boots with no logon-task data are listed in the table but not charted.
- On shared devices the phases follow the first sign-in of the boot; every further session is listed under `logon.sessions`.

## Data and privacy

`history.json` and the report contain, per boot: the signed-in account name and SID, the commands of startup apps (which include profile paths), who requested a shutdown, service and policy names, and Intune policy names and values. No passwords, tokens or document names. The SYSTEM output folder under `%ProgramData%` is readable by every local user, as is anything shipped to a share.

- Use `-Anonymize` where account names must not leave the device. Names are hashed consistently (the same account hashes the same on every run and device), so "the same user signs in slowly every day" is still visible without knowing who.
- The HTML report only ever renders data as text (no `innerHTML`), and the embedded JSON is escaped so a `</script>` inside an event cannot break out of the page. CSV cells can never start a spreadsheet formula.
- Treat the collected files as internal operational data; retention is `history.json`'s 365 most recent boots per device.

## Status

- Verified on real data on this machine: everything marked "no" above except Group Policy (workgroup PC) and Intune MDM (not enrolled), plus a 32-bit → 64-bit relaunch, incremental runs, `-Anonymize`, `-ReportOnly` and the failure path (exit 1).
- ★ sources and Intune MDM are built from the providers' own event manifests (`Get-WinEvent -ListProvider`) and covered by `tests\Test-Parsers.ps1` (run it on both `powershell` and `pwsh`; expect `0 failure(s)`), but not yet seen in a real elevated run on a managed device. The collector records every field name it actually saw (`fieldsSeen` in `history.json`) so any mismatch is easy to spot.
- **IME log parsing is best-effort**: IME log wording isn't a documented interface. The number of lines each recognition rule matched is shown in the `Intune Management Extension` source message – zero matches on a device that runs scripts means the patterns in `$ImeRules` need adjusting.
- Winlogon notification names (Startup, Logon, StartShell, PostShell, Logoff, Shutdown) are inferred from their order on real boots; others show as "Notification N".
- PSScriptAnalyzer: clean with the repo's `PSScriptAnalyzerSettings.psd1`, which lists the four excluded rules and why (best-effort probes with empty catch blocks, Write-Host in a console tool, plural nouns for functions that return collections).

## Fleet

Every file is per-device and versioned. To roll up many devices: deploy the collector through Intune (it runs as SYSTEM, so the ★ sources are included) and ship `%ProgramData%\BootView\latest.json` after each run – or `history.json` once – to a share or Log Analytics. Each file carries the device name, serial, Entra device ID and Intune device ID, so it joins to Endpoint Analytics, Intune and asset data; a multi-device viewer over the collected files is the next step.
