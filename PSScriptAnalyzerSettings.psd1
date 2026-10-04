@{
    # Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingEmptyCatchBlock'                   # every probe (CIM, registry, dsregcmd, SID lookup) is best-effort by design: a missing value is recorded as null
        'PSAvoidUsingWriteHost'                         # console tool; host-only text goes to Write-Host (5.0+ information stream), results go to files and the last stdout line
        'PSUseShouldProcessForStateChangingFunctions'   # Set-Source / New-Span build in-memory records, they change nothing on the system
        'PSUseSingularNouns'                            # Read-Events, Get-Pairs, Build-Degraders ... return collections and are named for what they return
    )
}
