# Security

`drop` exists to reduce privileges, so a bug that leaves the child with more
access than a normal user would get is a security issue, not just a bug.

## Reporting

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/kevinswiber/drop-ps1/security/advisories/new)
for this repository rather than in a public issue. Include the Windows and
PowerShell versions, how you invoked `drop`, and what the child reported
(`whoami /groups` and `whoami /priv` are usually enough).

## Scope

In scope: anything that lets a process started by `drop` keep Administrators
enabled, run above Medium integrity, retain privileges beyond the handful a
standard user token holds, or escape to the parent's token.

Out of scope: the fact that the child is the same user account. `drop` does
not sandbox; it gives the same user a weaker token, equivalent to a
non-elevated logon.

## Supported versions

Only the latest commit on `main` is supported.
