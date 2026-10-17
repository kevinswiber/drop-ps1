# Pester 5 tests for drop.ps1 and its shims.
#
# Run locally:  Invoke-Pester -Path tests -Output Detailed
#
# Every test launches a real de-elevated child and inspects what it reports,
# so these need a Windows host with pwsh. Windows PowerShell 5.1, cmd.exe and
# Git bash are exercised when present and skipped otherwise.

BeforeDiscovery {
    $script:HasWinPS  = [bool](Get-Command powershell.exe -ErrorAction SilentlyContinue)
    $script:GitBash   = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
    $script:HasBash   = Test-Path $script:GitBash
}

BeforeAll {
    $script:Repo    = Split-Path $PSScriptRoot -Parent
    $script:Drop    = Join-Path $Repo 'bin\drop.ps1'
    $script:DropCmd = Join-Path $Repo 'bin\drop.cmd'
    $script:DropSh  = Join-Path $Repo 'bin\drop'
    $script:GitBash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'

    # Run drop.ps1 as a separate pwsh process so the child's stdout comes back
    # through a pipe (see the README caveat about console handles).
    function Invoke-Drop {
        $out = & pwsh -NoProfile -File $script:Drop @args 2>&1
        [pscustomobject]@{ Output = ($out | Out-String); ExitCode = $LASTEXITCODE }
    }

    # Privileges a Safer NORMALUSER token is allowed to keep.
    $script:HarmlessPrivileges = @(
        'SeChangeNotifyPrivilege', 'SeShutdownPrivilege', 'SeUndockPrivilege',
        'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege'
    )

    # Informational: what the test host itself looks like, so a CI log shows
    # whether the drop started from an elevated token.
    $me = (whoami /groups | Select-String 'BUILTIN\\Administrators|Mandatory Level') -join "`n  "
    Write-Information "Test host token:`n  $me" -InformationAction Continue
}

Describe 'drop.ps1' {
    Context 'PowerShell Gallery metadata' {
        It 'has a valid PSScriptInfo header' {
            $info = Test-ScriptFileInfo -Path $Drop
            $info.Name | Should -Be 'drop'
            $info.Author | Should -Not -BeNullOrEmpty
            $info.Description | Should -Not -BeNullOrEmpty
            $info.ProjectUri | Should -Match '^https://github.com/'
            "$($info.Version)" | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'keeps the shebang as the first line' {
            (Get-Content $Drop -TotalCount 1) | Should -Be '#!/usr/bin/env pwsh'
        }
    }

    Context 'privilege drop' {
        BeforeAll { $script:Groups = (Invoke-Drop whoami /groups).Output }

        It 'marks Administrators as deny-only in the child' {
            $Groups | Should -Match 'BUILTIN\\Administrators\s+Alias\s+S-1-5-32-544\s+Group used for deny only'
        }

        It 'runs the child at Medium integrity' {
            $Groups | Should -Match 'Medium Mandatory Level\s+Label\s+S-1-16-8192'
            $Groups | Should -Not -Match 'High Mandatory Level'
        }

        It 'strips every privilege except the harmless ones' {
            $priv = (Invoke-Drop whoami /priv).Output -split "`r?`n" |
                Where-Object { $_ -match '^(Se\w+Privilege)' } |
                ForEach-Object { $Matches[1] }
            $priv | Should -Not -BeNullOrEmpty
            $priv | Should -BeIn $HarmlessPrivileges
        }

        It 'reports IsInRole(Administrators) as false in the child' {
            $r = Invoke-Drop -c '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")'
            $r.Output.Trim() | Should -Be 'False'
        }
    }

    Context 'exit codes' {
        It 'passes the child exit code through' {
            (Invoke-Drop cmd /c 'exit 42').ExitCode | Should -Be 42
        }

        It 'returns 0 for a successful child' {
            (Invoke-Drop cmd /c 'exit 0').ExitCode | Should -Be 0
        }

        It 'returns 127 when the command cannot be found' {
            $r = Invoke-Drop no-such-command-drop-test
            $r.ExitCode | Should -Be 127
            $r.Output | Should -Match "can't find"
        }

        It 'returns 1 when -c has no argument' {
            (Invoke-Drop -c).ExitCode | Should -Be 1
        }
    }

    Context 'command string and arguments' {
        It 'runs a -c string in the shell' {
            (Invoke-Drop -c '1 + 2').Output.Trim() | Should -Be '3'
        }

        It 'preserves arguments containing spaces and quotes' {
            $r = Invoke-Drop cmd /c 'echo [%1] [%2]' 'two words' 'say "hi"'
            # cmd echoes the raw tokens it received; both must arrive intact.
            $r.Output | Should -Match 'two words'
            $r.Output | Should -Match 'say \\?"hi\\?"'
        }

        It 'passes child flags through untouched' {
            # -NoProfile must reach the child shell, not be eaten by drop.ps1
            $r = Invoke-Drop pwsh -NoProfile -c '$PSVersionTable.PSVersion.Major'
            $r.ExitCode | Should -Be 0
            [int]$r.Output.Trim() | Should -BeGreaterOrEqual 7
        }
    }

    Context 'shell selection' {
        It 'starts pwsh when invoked from pwsh' {
            $out = & pwsh -NoProfile -Command "& '$Drop' -c '[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName'"
            ($out | Out-String).Trim() | Should -Match '\\pwsh\.exe$'
        }

        It 'starts cmd.exe when invoked through drop.cmd' {
            $out = & cmd.exe /c "`"$DropCmd`" -c ver"
            ($out | Out-String) | Should -Match 'Microsoft Windows \[Version'
            $LASTEXITCODE | Should -Be 0
        }

        It 'passes exit codes through drop.cmd' {
            & cmd.exe /c "`"$DropCmd`" -c `"exit 7`"" | Out-Null
            $LASTEXITCODE | Should -Be 7
        }

        It 'starts bash when invoked through the bash shim' -Skip:(-not $HasBash) {
            $posix = $DropSh -replace '\\', '/'
            $bashCmd = '"' + $posix + '" -c ''echo child=$0; exit 5'''
            $out = & $GitBash -c $bashCmd
            ($out | Out-String) | Should -Match 'child=bash'
            $LASTEXITCODE | Should -Be 5
        }

        It 'honours -s to pick a shell explicitly' {
            (Invoke-Drop -s cmd.exe -c ver).Output | Should -Match 'Microsoft Windows \[Version'
        }

        It 'returns 127 for an unknown -s shell' {
            (Invoke-Drop -s no-such-shell -c x).ExitCode | Should -Be 127
        }
    }

    Context 'Windows PowerShell 5.1 host' -Skip:(-not $HasWinPS) {
        It 'drops privileges when hosted by powershell.exe' {
            $out = & powershell.exe -NoProfile -File $Drop whoami /groups 2>&1
            ($out | Out-String) | Should -Match 'BUILTIN\\Administrators\s+Alias\s+S-1-5-32-544\s+Group used for deny only'
            $LASTEXITCODE | Should -Be 0
        }

        It 'can run Windows PowerShell as the child via -s' {
            $out = & powershell.exe -NoProfile -File $Drop -s powershell.exe -c '$PSVersionTable.PSVersion.Major'
            ($out | Out-String).Trim() | Should -Be '5'
        }
    }
}
