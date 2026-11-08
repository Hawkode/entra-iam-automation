# Changelog

All notable changes to this project. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- README: install from a tagged release, a note for hybrid tenants, a "Before you run it in production" checklist, and the hybrid joiner back in the plan.

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
