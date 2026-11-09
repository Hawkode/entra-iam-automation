# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/).

## [1.2.2] - 2026-11-09

Tidy-up. No new features.

### Changed
- Shared module: `Get-IamValidManager`, `Get-IamAdManager`, `Set-IamCloudManager` and `Write-IamManagerWarning` replace manager code that was repeated in the joiners, movers and hybrid leaver.
- Hybrid leaver: reading the AD manager no longer fails if the Manager attribute points at an object that cannot be read.
- Joiners: the temporary password warning names no specific product.
- Shared module: help text on every function.
- README: leaver options in their own section, hybrid requirements renamed, status table ordered by folder, output warning in one place, `BreakGlassUpns` and Leavers OU sync scope text brought up to date.
- `config.example.psd1`: `BreakGlassUpns` comment brought up to date.

## [1.2.1] - 2026-11-09

### Added
- Movers (cloud and hybrid): `-Manager` sets the new manager, validated before any change. Pass the current department to change only the manager.
- Movers: a warning when the department changes but the manager stays, the user has no manager, or the manager is disabled. The leavers hand the mailbox to the manager, so a stale one gets the wrong mailbox.

### Changed
- `CHEATSHEET.md`: one line per job, rarer options in one Extras table.
- README status: `Get-MfaRegistration` and `Get-ManagerCoverage` tested in the lab.

## [1.2.0] - 2026-11-09

New options and reports are tested offline with Graph, Exchange Online and AD mocked, not yet in a live tenant.

### Added
- Leavers (cloud and hybrid): `-RemoveAuthMethods` removes every registered MFA method. Its Critical scope is requested only when the switch is used.
- Leavers (cloud and hybrid): `-ConvertMailbox` converts the mailbox to shared before the licence goes, with `-DelegateTo`, `-NoDelegate`, `-AutoReplyMessage` and `-HideFromGal`. Full Access goes to the manager by default.
- Leavers: the licence stays automatically when the shared mailbox still needs one (over 50 GB, litigation hold, archive) or when conversion fails.
- Leavers: the plan warns when a licensed mailbox would be deleted because `-ConvertMailbox` was not used.
- Joiners (cloud and hybrid): `-Manager` and a `Manager` CSV column, validated before anything is created.
- Reports: `Get-MfaRegistration` (no MFA, weak methods only, admins and break-glass accounts without phishing-resistant MFA) and `Get-ManagerCoverage`.
- Config key `LeaversOUInSyncScope`: the hybrid leaver's `-ConvertMailbox` refuses to run unless it is `$true`.
- `CHEATSHEET.md`: every command with example values, linked from the README.

### Changed
- Lint workflow: `actions/checkout@v7` (Dependabot).
- Sample CSV: `Manager` column, indentation removed.

## [1.1.0] - 2026-11-08

### Added
- Hybrid lifecycle: `New-HybridJoiner`, `Move-HybridUser`, `Disable-HybridLeaver` (AD first, then Entra Connect delta sync, then Graph).
- Config keys `DepartmentOUs`, `ProtectedAdGroups`. `LeaversOU` and `EntraConnectServer` are now used.
- Shared module: `Get-IamUpnPrefix`, `Get-IamRandomPassword`, `ConvertTo-IamSecureString`, `Import-IamAdModule`, `Invoke-IamDeltaSync`, `Wait-IamCloudUser`.
- Dependabot keeps the GitHub Actions in the lint workflow up to date.
- README: hybrid section with requirements and the Leavers OU sync scope check.

### Changed
- `New-CloudJoiner` uses the shared UPN and password helpers, so both joiners build UPNs the same way.
- Lint workflow: 10-minute job timeout, and PSScriptAnalyzer pinned to 1.23.0 so a runner image update cannot change or hang the results.
- Config check handles hashtable values (`DepartmentOUs`), including example values.
- README: install from a tagged release, a note for hybrid tenants, a "Before you run it in production" checklist.

## [1.0.0] - 2026-11-08

First release.

### Added
- Reports: `Get-RiskyAppPermissions`, `Get-StandingAdmins`, `Get-StaleAccounts`.
- Cloud lifecycle: `New-CloudJoiner`, `Move-CloudUser`, `Disable-CloudLeaver`.
- Shared module with Graph sign-in, logging, sync guard, session revoke and licence removal.
- Config validation: scripts check the values they need, and refuse example values, before signing in.
- `UpnFormat` config key for the joiner (default `{given}.{surname}`).
- README sections for using the scripts in another tenant, config reference and known limitations.
- `SECURITY.md`.

### Changed
- `Get-RiskyAppPermissions` always shows tenant-wide delegated grants, whatever their tier (standard sign-in scopes excepted).
- Output files go to a clean `output\` path with a seconds timestamp, so two runs in the same minute no longer overwrite each other.
- Lint workflow: read-only token, `actions/checkout@v6`, no reinstall of PSScriptAnalyzer.

### Fixed
- `Remove-IamUserLicense` skips group-assigned licences instead of failing the whole call.
