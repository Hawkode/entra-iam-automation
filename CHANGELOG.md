# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `CHEATSHEET.md`: every command with example values, linked from the README.

### Changed
- Lint workflow: `actions/checkout@v7` (Dependabot).

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
