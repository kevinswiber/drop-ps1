@{
    # Rules that fail the build. Informational findings are left to the editor.
    Severity            = @('Error', 'Warning')
    IncludeDefaultRules = $true

    # Nothing excluded yet. Add rule names here with a comment saying why.
    ExcludeRules        = @()

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            # drop.ps1 must parse on Windows PowerShell 5.1 as well as pwsh 7.
            TargetVersions = @('5.1', '7.0')
        }
    }
}
