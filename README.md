# Entra IAM Automation

PowerShell (Microsoft Graph SDK) scripts for identity lifecycle and security reporting in Microsoft Entra ID.
Built and tested in a lab tenant. Companion to [IAM Lab in Microsoft Entra ID](https://hawkode.github.io/projects/entra-iam-lab/).

| Folder | Contents |
|---|---|
| `Cloud/` | Joiner, mover, leaver for cloud-only users |
| `Hybrid/` | Joiner, mover, leaver for users synced from AD DS |
| `Reports/` | Read-only security reports, same in both setups |
| `Shared/` | Common module used by every script |

## Setup
1. `Install-Module Microsoft.Graph -Scope CurrentUser` (PowerShell 7 recommended, 5.1 supported)
2. Copy `config.example.psd1` to `config.local.psd1` and fill in your tenant values.
3. Run any script that makes changes with `-WhatIf` first.

## Reports
| Script | Finds | Graph scopes | Licence |
|---|---|---|---|
| `Get-RiskyAppPermissions.ps1` | Apps with high-risk Graph permissions, and whether they hold a credential | `Application.Read.All`, `DelegatedPermissionGrant.Read.All` | Free |
| `Get-StandingAdmins.ps1` | Permanent privileged role holders, PIM eligible vs active | `RoleManagement.Read.Directory`, `Directory.Read.All` | P2 for PIM data, falls back without |
| `Get-StaleAccounts.ps1` | Enabled accounts with no recent sign-in, or none ever | `User.Read.All`, `AuditLog.Read.All` | P1 or P2 |

All reports write a CSV to `output/` (gitignored) and log to `output/iam-automation.log`.

## Status
| Script | Status |
|---|---|
| Shared module | Done, tested in lab |
| Reports/Get-RiskyAppPermissions.ps1 | Done, tested in lab |
| Reports/Get-StandingAdmins.ps1 | Done, tested in lab (PIM data needs P2) |
| Reports/Get-StaleAccounts.ps1 | Done, tested in lab (needs P1). `-IncludeOnPrem` untested |
| Cloud/ joiner, mover, leaver | Not started |
| Hybrid/ joiner, mover, leaver | Not started |