#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Task runner for this repo: lint with PSScriptAnalyzer and test with Pester.

.DESCRIPTION
    The PowerShell equivalent of a Makefile. CI calls the same tasks, so a
    local run and a CI run follow the same code path. Missing tools are
    installed into the current user's module scope on first use.

.PARAMETER Task
    Lint, Test, or All (the default).

.EXAMPLE
    .\build.ps1             # lint and test
    .\build.ps1 Lint
    .\build.ps1 Test
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('All', 'Lint', 'Test')]
    [string]$Task = 'All'
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Write-Step([string]$Message) {
    Write-Information "==> $Message" -InformationAction Continue
}

function Install-IfMissing([string]$Name, [version]$MinimumVersion) {
    $have = Get-Module -ListAvailable $Name | Where-Object Version -ge $MinimumVersion
    if (-not $have) {
        Write-Step "Installing $Name >= $MinimumVersion (CurrentUser scope)"
        Install-Module $Name -MinimumVersion $MinimumVersion -Scope CurrentUser -Force -SkipPublisherCheck
    }
}

function Invoke-Lint {
    Install-IfMissing PSScriptAnalyzer 1.21
    Write-Step 'PSScriptAnalyzer'
    $findings = Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    if ($findings) {
        $findings | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 160
        throw "PSScriptAnalyzer reported $($findings.Count) finding(s)"
    }
    Write-Step 'PSScriptAnalyzer: no findings'
}

function Invoke-Test {
    Install-IfMissing Pester 5.5
    Write-Step 'Pester'
    $cfg = New-PesterConfiguration
    $cfg.Run.Path = 'tests'
    $cfg.Run.PassThru = $true
    $cfg.Output.Verbosity = 'Detailed'
    $cfg.TestResult.Enabled = $true
    $cfg.TestResult.OutputPath = 'testResults.xml'
    $result = Invoke-Pester -Configuration $cfg
    if ($result.FailedCount -gt 0) {
        throw "$($result.FailedCount) test(s) failed"
    }
}

try {
    switch ($Task) {
        'Lint' { Invoke-Lint }
        'Test' { Invoke-Test }
        'All'  { Invoke-Lint; Invoke-Test }
    }
}
catch {
    [Console]::Error.WriteLine("build: $_")
    exit 1
}
