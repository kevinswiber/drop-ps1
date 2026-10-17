# drop-ps1

[![CI](https://github.com/kevinswiber/drop-ps1/actions/workflows/ci.yml/badge.svg)](https://github.com/kevinswiber/drop-ps1/actions/workflows/ci.yml)

Run a command on Windows without elevated privileges, from a PowerShell script.

A port of the `drop` / `pdrop` applets from [busybox-w32](https://github.com/rmyorston/busybox-w32)
to a single `drop.ps1`, so you can carry it around as a script instead of a
renamed `busybox.exe`.

## Why

When you SSH into a Windows machine with an account that is in the local
Administrators group, OpenSSH gives you a fully elevated session: High
integrity, Administrators enabled. There is no UAC prompt to decline. If you
want to run something as a normal user, say a test suite that must not depend
on admin rights, you either create a second account or drop the privileges
yourself. `drop` does the latter.

```
PS> whoami /groups | findstr /c:"Administrators" /c:"Mandatory Level"
BUILTIN\Administrators         Alias   S-1-5-32-544  Mandatory group, Enabled by default, Enabled group, Group owner
Mandatory Label\High Mandatory Level   Label   S-1-16-12288

PS> drop whoami /groups | findstr /c:"Administrators" /c:"Mandatory Level"
BUILTIN\Administrators         Alias   S-1-5-32-544  Group used for deny only
Mandatory Label\Medium Mandatory Level Label   S-1-16-8192
```

## Install

### From the PowerShell Gallery (PowerShell users)

```powershell
Install-PSResource drop        # PowerShell 7.4+
Install-Script drop            # Windows PowerShell 5.1 or older pwsh
```

This installs `drop.ps1` into your user `Scripts` folder and offers to add
that folder to `PATH`, after which `drop` works from pwsh and Windows
PowerShell. The Gallery package is the script only; if you also want `drop`
from cmd.exe or Git bash, use the clone install below.

### With Scoop (every shell)

```powershell
scoop bucket add kevinswiber https://github.com/kevinswiber/scoop-bucket
scoop install kevinswiber/drop
```

Scoop generates its own `drop.cmd`, `drop.ps1` and `drop` shims in its
`shims` directory, which is already on `PATH`, so `drop` works from pwsh,
Windows PowerShell, cmd.exe and Git bash. `scoop update drop` picks up new
releases.

### From a clone (every shell)

Clone the repo and put its `bin` directory on your `PATH`. `bin` holds only
the three entry points, so nothing else leaks onto your `PATH`.

```powershell
git clone https://github.com/kevinswiber/drop-ps1
[Environment]::SetEnvironmentVariable('PATH', "$PWD\drop-ps1\bin;" + [Environment]::GetEnvironmentVariable('PATH', 'User'), 'User')
```

Open a new shell afterwards. Three entry points are provided so a bare `drop`
works from each shell:

| Shell              | What runs                                     |
|--------------------|-----------------------------------------------|
| pwsh / powershell  | `drop.ps1` directly (PowerShell finds `.ps1` files on `PATH`) |
| cmd.exe            | `drop.cmd`, a shim that calls `drop.ps1` via pwsh, or Windows PowerShell if pwsh is not installed |
| Git bash / MSYS    | `drop`, a bash shim that does the same        |

Requirements: Windows 10 or 11, and either PowerShell 7 (`pwsh`) or Windows
PowerShell 5.1. Both are supported; 5.1 ships with Windows.

## Usage

```
drop [COMMAND [ARG...] | [-s SHELL] -c CMD_STRING [ARG...]]
```

- `drop` with no arguments starts an interactive, de-elevated shell. It picks
  the shell you invoked it from: pwsh, Windows PowerShell, cmd.exe, bash, and
  so on. Over SSH, where there is no interactive parent shell, it uses the
  PowerShell that is running the script.
- `drop COMMAND ARG...` runs a program, found via `PATH`, de-elevated. Its
  exit code is returned.
- `drop -c 'STRING'` passes the string to the shell (`-c`, or `/c` for cmd.exe).
- `drop -s SHELL` picks the shell explicitly, by name or path.

```powershell
drop                       # de-elevated shell, same kind as the one you're in
drop whoami /groups        # run a program
drop -c 'Get-Process | Measure-Object'
drop -s cmd.exe -c 'ver'
drop npm test              # exit code comes back
```

## How it works

The same five Win32 calls as `drop.c`, done through an embedded C# class:

1. `SaferCreateLevel(SAFER_LEVELID_NORMALUSER)` and `SaferComputeTokenFromLevel`
   produce a copy of the current token with the Administrators group marked
   deny-only and the admin privileges removed.
2. `SetTokenInformation(TokenIntegrityLevel)` sets the token to Medium
   integrity (`S-1-16-8192`).
3. `CreateProcessAsUser` starts the child with that token, inheriting the
   current standard handles so it shares your console or SSH pipes.
4. The script waits for the child and exits with its exit code.

No second account, no stored credentials, no UAC. The child is the same user
with a weaker token, which is exactly what a non-elevated logon would get.

## Caveats

- **Output goes to the console, not the pipeline.** When run interactively,
  the child writes to the real console handles, so
  `$x = drop whoami` captures nothing. Run it as a separate process to
  capture: `$x = pwsh -File bin\drop.ps1 whoami`. In scripts and over SSH the
  standard handles are already pipes, so this does not come up.
- **Windows PowerShell 5.1 without `-File`.** `powershell.exe .\drop.ps1 ...`
  is treated as `-Command`, which strips double quotes from arguments and
  reports exit codes as 1. Use `powershell.exe -File .\drop.ps1 ...`, or the
  `drop.cmd` shim, which already does. `pwsh.exe` does not have this quirk.
- **The shebang needs pwsh.** `./drop.ps1` from Git bash uses
  `#!/usr/bin/env pwsh` and fails on a machine with only Windows PowerShell.
  The `drop` shim falls back to Windows PowerShell and works either way.
- **Execution policy.** The shims pass `-ExecutionPolicy Bypass`. Running
  `drop.ps1` directly from PowerShell needs a policy that allows local
  scripts, such as `RemoteSigned`.
- **The C# type is compiled once per session** and named after a hash of its
  source, so editing the script and re-running it in the same session picks
  up the change.

## Testing

CI runs on a stock `windows-latest` GitHub runner, where the runner account
is a local administrator. The [Pester](https://pester.dev) suite in `tests/`
launches real de-elevated children and checks that Administrators is
deny-only, the integrity level is Medium, only harmless privileges remain,
exit codes pass through, and the right shell is picked when invoked from
pwsh, Windows PowerShell 5.1, cmd.exe and Git bash. The workflow also lints
with [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer).

To run it yourself, `build.ps1` is the task runner; it installs Pester and
PSScriptAnalyzer into your user module scope if they are missing:

```powershell
.\build.ps1          # lint and test
.\build.ps1 Lint
.\build.ps1 Test
```

## Releasing

Bump `.VERSION` in the `PSScriptInfo` header of `bin/drop.ps1`, commit, then
push a matching tag:

```powershell
git tag v1.2.3
git push origin v1.2.3
```

The release workflow checks that the tag matches the header, runs the build,
publishes the script to the PowerShell Gallery, and creates a GitHub release
with notes generated from the commit history.

## Credits

The approach and the applet's interface come from `miscutils/drop.c` in
[busybox-w32](https://github.com/rmyorston/busybox-w32) by Ronald M Yorston,
which in turn credits
[this Stack Overflow answer](https://stackoverflow.com/questions/17765568/).
This is an independent reimplementation in PowerShell and C#; no code from
busybox-w32 is included.

## License

MIT. See [LICENSE](LICENSE).
