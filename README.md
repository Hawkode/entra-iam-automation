# Entra IAM Automation

PowerShell (Microsoft Graph SDK) scripts for identity lifecycle and security reporting in Microsoft Entra ID.
Built and tested in a lab tenant. Companion to [IAM Lab in Microsoft Entra ID](https://hawkode.github.io/projects/entra-iam-lab/).

| Folder | Contents |
|---|---|
| `Cloud/` | Joiner, mover, leaver for cloud-only users |
| `Hybrid/` | Joiner, mover, leaver for users synced from AD DS |
| `Reports/` | Read-only security reports, same in both setups |
| `Shared/` | Common module used by every script |
| `samples/` | Example input files (fake names only) |

## Setup
1. `Install-Module Microsoft.Graph -Scope CurrentUser` (PowerShell 7 recommended, 5.1 supported)
2. Copy `config.example.psd1` to `config.local.psd1` and fill in your tenant values, licence SKU and `AllowedDepartments`.
3. Run any script that makes changes with `-WhatIf` first.

## Cloud lifecycle
| Script | Does | Graph scopes |
|---|---|---|
| `New-CloudJoiner.ps1` | Creates users (single or CSV), sets department and usage location, assigns the licence | `User.ReadWrite.All`, `LicenseAssignment.Read.All` |
| `Move-CloudUser.ps1` | Changes department so dynamic groups re-scope access, lists assigned groups and roles that do not move | `User.ReadWrite.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory` |
| `Disable-CloudLeaver.ps1` | Disables, revokes sessions, removes assigned groups and direct licences, clears department | `User.ReadWrite.All`, `GroupMember.ReadWrite.All`, `RoleManagement.Read.Directory` |

Signed-in admin needs User Administrator. Scripts use delegated sign-in only: no app secrets.

### Safety controls
- **Sync guard:** Cloud scripts stop on users synced from AD, Hybrid scripts stop on cloud-only users.
- **Department allowlist:** departments must match `AllowedDepartments`, so a typo cannot create a user outside every dynamic group.
- **Validate first:** the joiner checks every row and every UPN before creating anything. One bad row, nothing created.
- **`-WhatIf`** on every script that changes something.
- **Leaver:** lists the full plan, then asks for confirmation once. Refuses to run on break-glass accounts or on the signed-in admin.
- **Not automated on purpose:** removing directory roles (would need `RoleManagement.ReadWrite.Directory`). Reported for manual action instead.
- **Temporary passwords** are shown once in the console and never logged or written to CSV.

## Reports
| Script | Finds | Graph scopes | Licence |
|---|---|---|---|
| `Get-RiskyAppPermissions.ps1` | Apps with high-risk Graph permissions, and whether they hold a credential | `Application.Read.All`, `DelegatedPermissionGrant.Read.All` | Free |
| `Get-StandingAdmins.ps1` | Permanent privileged role holders, PIM eligible vs active | `RoleManagement.Read.Directory`, `Directory.Read.All` | P2 for PIM data, falls back without |
| `Get-StaleAccounts.ps1` | Enabled accounts with no recent sign-in, or none ever | `User.Read.All`, `AuditLog.Read.All` | P1 or P2 |

All scripts write a CSV to `output/` (gitignored) and log to `output/iam-automation.log`.

## Status
| Script | Status |
|---|---|
| Shared module | Done, tested in lab |
| Reports/Get-RiskyAppPermissions.ps1 | Done, tested in lab |
| Reports/Get-StandingAdmins.ps1 | Done, tested in lab (PIM data needs P2) |
| Reports/Get-StaleAccounts.ps1 | Done, tested in lab (needs P1). `-IncludeOnPrem` untested |
| Cloud/New-CloudJoiner.ps1 | Done, tested in lab (single user and CSV) |
| Cloud/Move-CloudUser.ps1 | Done, tested in lab |
| Cloud/Disable-CloudLeaver.ps1 | Done, tested in lab (direct licences). Group-assigned licence path untested |
| Hybrid/ joiner, mover, leaver | Not started (needs a lab DC with Entra Connect) |