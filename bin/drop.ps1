#!/usr/bin/env pwsh

<#PSScriptInfo
.VERSION 1.0.1
.GUID bac66db3-4d59-4e53-9b56-0ae8a98179cc
.AUTHOR Kevin Swiber
.COPYRIGHT (c) 2026 Kevin Swiber. MIT License.
.TAGS Windows Security Privileges Elevation UAC Token Administrator SSH
.LICENSEURI https://github.com/kevinswiber/drop-ps1/blob/main/LICENSE
.PROJECTURI https://github.com/kevinswiber/drop-ps1
.RELEASENOTES https://github.com/kevinswiber/drop-ps1/releases
#>

<#
.SYNOPSIS
    Run a command on Windows without elevated privileges.
.DESCRIPTION
    Drops elevated privileges (Administrators group made deny-only, Medium
    integrity) and runs a command, or an interactive shell when no command is
    given. A PowerShell port of busybox-w32's drop/pdrop applets. Useful over
    SSH, where an administrator account always gets an elevated session.
.LINK
    https://github.com/kevinswiber/drop-ps1
#>

# drop.ps1 - PowerShell port of busybox-w32's drop/pdrop applet.
#
# Usage:  drop [COMMAND [ARG...] | [-s SHELL] -c CMD_STRING [ARG...]]
#
# Install: put this bin directory on PATH. PowerShell runs `drop` as drop.ps1
# directly; drop.cmd is a shim for cmd.exe and `drop` (no extension) is a
# shim for Git bash / MSYS. The shebang lets Git bash run ./drop.ps1 too.
#
# Drops elevated privileges (Administrators group -> deny-only, Medium
# integrity) and runs COMMAND. With no command, runs an interactive shell:
# the one you invoked it from (pwsh, powershell, cmd, bash, ...), or the one
# named by -s. Works from Windows PowerShell 5.1 and pwsh 7.
#
# Note: the child inherits this process's real std handles, so when run
# interactively its output goes straight to the console, not through the
# PowerShell pipeline. To capture it, invoke as `pwsh -File drop.ps1 ...`.
#
# Mirrors miscutils/drop.c: SaferCreateLevel(NORMALUSER) ->
# SaferComputeTokenFromLevel -> SetTokenInformation(Medium) ->
# CreateProcessAsUser with inherited std handles -> wait -> exit code.

$ErrorActionPreference = 'Stop'

# Add-Type'd types live for the whole session and can't be replaced, so the
# class name carries a hash of its source: editing the C# below yields a fresh
# type instead of silently reusing a stale one from an earlier run.
$nativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class DropNative
{
    const uint SAFER_SCOPEID_USER        = 2;
    const uint SAFER_LEVELID_NORMALUSER  = 0x20000;
    const uint SAFER_LEVEL_OPEN          = 1;
    const int  TokenIntegrityLevel       = 25;
    const uint SE_GROUP_INTEGRITY        = 0x20;
    const uint STARTF_USESTDHANDLES      = 0x100;
    const int  STD_INPUT_HANDLE          = -10;
    const int  STD_OUTPUT_HANDLE         = -11;
    const int  STD_ERROR_HANDLE          = -12;
    const uint INFINITE                  = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    delegate bool ConsoleCtrlDelegate(uint ctrlType);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SaferCreateLevel(uint scope, uint level, uint flags, out IntPtr handle, IntPtr reserved);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SaferCloseLevel(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SaferComputeTokenFromLevel(IntPtr level, IntPtr inToken, out IntPtr outToken, uint flags, IntPtr reserved);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int cls, ref TOKEN_MANDATORY_LABEL info, uint len);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUserW(IntPtr token, string app, StringBuilder cmdLine,
        IntPtr procAttrs, IntPtr threadAttrs, bool inherit, uint flags, IntPtr env, string cwd,
        ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate handler, bool add);

    static void Fail(string what)
    {
        int err = Marshal.GetLastWin32Error();
        throw new System.ComponentModel.Win32Exception(err, what + " failed (error " + err + ")");
    }

    // Launch exe with cmdLine under a de-elevated, Medium-integrity token.
    // Returns the child's exit code.
    public static int Run(string exe, string cmdLine)
    {
        IntPtr safer = IntPtr.Zero, token = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        // S-1-16-8192 (Medium mandatory level), same bytes as drop.c
        byte[] medium = { 0x01,0x01,0,0, 0,0,0,0x10, 0,0x20,0,0 };
        GCHandle pin = GCHandle.Alloc(medium, GCHandleType.Pinned);
        // Parent ignores Ctrl+C while waiting; the child shares the console
        // and decides for itself what to do with it.
        ConsoleCtrlDelegate ignore = delegate(uint t) { return true; };
        try
        {
            if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, out safer, IntPtr.Zero))
                Fail("SaferCreateLevel");
            if (!SaferComputeTokenFromLevel(safer, IntPtr.Zero, out token, 0, IntPtr.Zero))
                Fail("SaferComputeTokenFromLevel");

            TOKEN_MANDATORY_LABEL til = new TOKEN_MANDATORY_LABEL();
            til.Label.Sid = pin.AddrOfPinnedObject();
            til.Label.Attributes = SE_GROUP_INTEGRITY;
            if (!SetTokenInformation(token, TokenIntegrityLevel, ref til, (uint)Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL))))
                Fail("SetTokenInformation");

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = (int)STARTF_USESTDHANDLES;
            si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
            si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

            StringBuilder cmd = new StringBuilder(cmdLine);
            if (!CreateProcessAsUserW(token, exe, cmd, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref si, out pi))
                Fail("CreateProcessAsUser");

            SetConsoleCtrlHandler(ignore, true);
            WaitForSingleObject(pi.hProcess, INFINITE);
            uint code;
            if (!GetExitCodeProcess(pi.hProcess, out code)) Fail("GetExitCodeProcess");
            return unchecked((int)code);
        }
        finally
        {
            SetConsoleCtrlHandler(ignore, false);
            GC.KeepAlive(ignore);
            pin.Free();
            if (pi.hThread  != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (token != IntPtr.Zero) CloseHandle(token);
            if (safer != IntPtr.Zero) SaferCloseLevel(safer);
        }
    }
}
'@

$md5  = [System.Security.Cryptography.MD5]::Create()
$hash = -join ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($nativeSource)) | ForEach-Object { $_.ToString('x2') })
$nativeTypeName = "DropNative_$($hash.Substring(0, 12))"
$native = $nativeTypeName -as [type]
if (-not $native) {
    Add-Type -TypeDefinition ($nativeSource -replace 'public static class DropNative\b', "public static class $nativeTypeName")
    $native = $nativeTypeName -as [type]
}

# Quote one argument the way CreateProcess/CommandLineToArgvW expects
# (equivalent of quote_arg in busybox-w32).
function ConvertTo-CommandLineArg([string]$a) {
    if ($a.Length -gt 0 -and $a -notmatch '[\s"]') { return $a }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $a.ToCharArray()) {
        if ($ch -eq '\') { $bs++; continue }
        if ($ch -eq '"') { [void]$sb.Append('\', 2 * $bs + 1); $bs = 0 }
        else             { [void]$sb.Append('\', $bs); $bs = 0 }
        [void]$sb.Append($ch)
    }
    [void]$sb.Append('\', 2 * $bs).Append('"')
    return $sb.ToString()
}

# Locate an executable like find_first_executable: PATH + PATHEXT lookup.
function Find-Executable([string]$name) {
    $c = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    return $null
}

# Shells we recognise when walking up the process tree.
$knownShells = 'pwsh.exe', 'powershell.exe', 'cmd.exe', 'bash.exe', 'sh.exe', 'zsh.exe', 'fish.exe', 'nu.exe', 'busybox.exe'

function Get-ParentProcessId([int]$id) {
    (Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue).ParentProcessId
}

function Get-ProcessPath([int]$id) {
    $p = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($p -and $p.Path) { return $p.Path }
    (Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue).ExecutablePath
}

# Find the shell the user is sitting in. If this PowerShell was started only to
# run this script (its command line names the script, as `-File drop.ps1`,
# `.\drop.ps1`, or `-Command "& 'C:\...\drop.ps1' ..."`), skip it and walk up
# the ancestors looking for a known shell. Otherwise this PowerShell is the
# shell. Falls back to this PowerShell if nothing recognisable is found.
# Set DROP_DEBUG=1 to see how the shell was chosen, on stderr.
function Write-DropDebug([string]$Message) {
    if ($env:DROP_DEBUG) { [Console]::Error.WriteLine("drop: $Message") }
}

function Get-InvokingShell {
    $self = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $scriptName = [regex]::Escape([IO.Path]::GetFileName($PSCommandPath))
    $hostArgs = [Environment]::GetCommandLineArgs() | Select-Object -Skip 1
    $isWrapper = [bool]($hostArgs | Where-Object { $_ -match "(?i)(^|[\\/\s'`"&])$scriptName($|[\s'`"])" })
    Write-DropDebug "host=$self wrapper=$isWrapper args=[$($hostArgs -join ' ')]"
    if (-not $isWrapper) { return $self }

    # POSIX shells export SHELL. It names the user's real shell even when the
    # nearest ancestor is a wrapper such as a `#!/bin/sh` shim.
    $fromEnv = $null
    if ($env:SHELL) {
        $sh = Find-Executable ([IO.Path]::GetFileNameWithoutExtension($env:SHELL))
        if ($sh -and ($knownShells -contains [IO.Path]::GetFileName($sh).ToLower())) { $fromEnv = $sh }
    }
    Write-DropDebug "SHELL=[$env:SHELL] -> $fromEnv"

    $id = $PID
    $shWrapper = $null
    for ($depth = 0; $depth -lt 6; $depth++) {
        $id = Get-ParentProcessId $id
        if (-not $id) { break }
        $path = Get-ProcessPath $id
        Write-DropDebug "ancestor $depth pid=$id $path"
        if (-not $path) { continue }
        $name = [IO.Path]::GetFileName($path).ToLower()
        if ($knownShells -notcontains $name) { continue }
        if ($name -eq 'sh.exe' -and $fromEnv -notmatch '(^|[\\/])sh\.exe$') {
            # sh.exe is usually a shim's interpreter (Scoop, npm, ...) rather
            # than the shell the user is typing in. Remember it and keep
            # looking. Inside MSYS (Git bash), where a non-login shell does not
            # export SHELL, assume the bash.exe next to it is the real shell.
            $shWrapper = $path
            if (-not $fromEnv -and $env:MSYSTEM) {
                $sibling = Join-Path (Split-Path $path -Parent) 'bash.exe'
                if (Test-Path -LiteralPath $sibling) { $fromEnv = $sibling }
            }
            continue
        }
        return $path
    }
    # No live shell ancestor (e.g. run via the shebang from Git bash, where the
    # forking bash has already exec'd away): fall back to SHELL, then to sh.
    Write-DropDebug "no shell ancestor; fromEnv=$fromEnv shWrapper=$shWrapper"
    if ($fromEnv)   { return $fromEnv }
    if ($shWrapper) { return $shWrapper }
    return $self
}

# --- argument handling (no param block so child flags like -NoProfile pass through) ---
$rest = @($args)
$cmdString = $null
$optShell  = $null
while ($rest.Count -ge 1 -and $rest[0] -in '-c', '-s') {
    if ($rest.Count -lt 2) { [Console]::Error.WriteLine("drop: $($rest[0]) requires an argument"); exit 1 }
    if ($rest[0] -eq '-c') { $cmdString = $rest[1] } else { $optShell = $rest[1] }
    $rest = @($rest | Select-Object -Skip 2)
}

if ($rest.Count -eq 0 -or $null -ne $cmdString) {
    if ($optShell) {
        $exe = if ($optShell -match '[\\/]') { $optShell } else { Find-Executable $optShell }
        if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            [Console]::Error.WriteLine("drop: can't find '$optShell'"); exit 127
        }
    } else {
        $exe = Get-InvokingShell
    }
    $argv = @([IO.Path]::GetFileName($exe))
    if ($null -ne $cmdString) {
        $opt = if ([IO.Path]::GetFileName($exe) -ieq 'cmd.exe') { '/c' } else { '-c' }
        $argv += $opt, $cmdString
    }
    $argv += $rest
} else {
    $exe  = Find-Executable $rest[0]
    if (-not $exe) { [Console]::Error.WriteLine("drop: can't find '$($rest[0])'"); exit 127 }
    $argv = @($rest)
}

$cmdLine = ($argv | ForEach-Object { ConvertTo-CommandLineArg $_ }) -join ' '

try {
    $code = $native::Run($exe, $cmdLine)
} catch {
    $msg = $_.Exception.Message
    if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
    [Console]::Error.WriteLine("drop: can't execute '$exe': $msg")
    exit 126
}
exit $code
