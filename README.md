# Entra IAM Automation

[![lint](https://github.com/Hawkode/entra-iam-automation/actions/workflows/lint.yml/badge.svg)](https://github.com/Hawkode/entra-iam-automation/actions/workflows/lint.yml)

PowerShell (Microsoft Graph SDK) scripts for identity lifecycle and security reporting in Microsoft Entra ID.
Companion to [IAM Lab in Microsoft Entra ID](https://hawkode.github.io/projects/entra-iam-lab/).

> **Test in a non-production tenant first.** The lifecycle scripts create, change and disable accounts.

| Folder | Contents |
|---|---|
| `Cloud/` | Joiner, mover, leaver for cloud-only users |
| `Hybrid/` | Leaver and mover review for users synced from AD DS (planned) |
| `Reports/` | Read-only security reports, same in cloud-only and hybrid tenants |
| `Shared/` | Common module used by every script |
| `samples/` | Example input files (fake names only) |

## Requirements
- Windows PowerShell 5.1 or PowerShell 7.
- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`
- An admin account with the Entra role each script needs (User Administrator for the lifecycle scripts).
- Licences: lifecycle scripts and `Get-RiskyAppPermissions` work on Entra ID Free. `Get-StaleAccounts` needs P1. PIM data in `Get-StandingAdmins` needs P2.
- **Design requirement for the mover and leaver:** access is granted through dynamic groups keyed on the `department` attribute (dynamic groups need P1). Without that design the scripts still run, but changing the department moves no access.

## Use it in your own tenant
1. Clone the repo. Use `git clone`, not a zip download: Windows marks files from a downloaded zip as coming from the internet, and the `RemoteSigned` execution policy blocks them. If you do use a zip, run `Get-ChildItem -Recurse -File | Unblock-File` in the folder.
   ```powershell
   git clone https://github.com/Hawkode/entra-iam-automation.git
   ```
2. Copy `config.example.psd1` to `config.local.psd1` and replace every example value (reference below). `config.local.psd1` is gitignored. Scripts refuse to run while a value they need is empty or still holds an example value.
3. Run a read-only report first. It proves sign-in, consent and the module work in your tenant:
   ```powershell
   .\Reports\Get-RiskyAppPermissions.ps1
   ```
4. Run lifecycle scripts with `-WhatIf`, then for real on a test user, then in normal use.

**Consent:** the first run of each script asks you to consent to *Microsoft Graph Command Line Tools* for the scopes it needs. Consent for yourself only. Do **not** tick "Consent on behalf of your organization", which grants those scopes to every user in the tenant. Scripts use delegated sign-in only: no app registrations, no secrets.

### Config reference
| Key | Used by | Value |
|---|---|---|
| `TenantId` | All | Tenant ID (Entra admin center > Overview) |
| `DefaultDomain` | Joiner | Domain new UPNs are created in |
| `UpnFormat` | Joiner | UPN prefix pattern. Tokens `{given}`, `{surname}`, `{g}`, `{s}`. Default `{given}.{surname}` |
| `UsageLocation` | Joiner | Two-letter country code, e.g. `GB` |
| `LicenseSkuPartNumber` | Joiner | SKU to assign (`Get-MgSubscribedSku`). Not needed with `-SkipLicense` |
| `StaleDays` | Stale accounts | Days without sign-in before an account is flagged |
| `BreakGlassUpns` | Leaver, reports | Emergency access accounts. Reports mark them as expected, the leaver refuses to touch them |
| `AllowedDepartments` | Joiner, mover | Exact department names your dynamic groups key on |
| `LeaversOU`, `EntraConnectServer` | Hybrid | Planned hybrid scripts |

## Cloud lifecycle
| Script | Does | Graph scopes |
|---|---|---|
| `New-CloudJoiner.ps1` | Creates users (single or CSV), sets department and usage location, assigns the licence | `User.ReadWrite.All`, `LicenseAssignment.Read.All` |
| `Move-CloudUser.ps1` | Changes department so dynamic groups re-scope access, lists assigned groups and roles that do not move | `User.ReadWrite.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory` |
| `Disable-CloudLeaver.ps1` | Disables, revokes sessions, removes assigned groups and direct licences, clears department | `User.ReadWrite.All`, `GroupMember.ReadWrite.All`, `RoleManagement.Read.Directory` |

### Safety controls
- **Config check:** every script validates the config values it needs before signing in.
- **Sync guard:** Cloud scripts stop on users synced from AD. Hybrid scripts will stop on cloud-only users.
- **Department allowlist:** departments must match `AllowedDepartments`, so a typo cannot create a user outside every dynamic group.
- **Validate first:** the joiner checks every row and every UPN before creating anything. One bad row, nothing created.
- **`-WhatIf`** on every script that changes something.
- **Leaver:** lists the full plan, then asks for confirmation once. Refuses to run on break-glass accounts or on the signed-in admin.
- **Not automated on purpose:** removing directory roles (would need `RoleManagement.ReadWrite.Directory`). Reported for manual action instead.
- **Temporary passwords** are shown once in the console and never logged or written to CSV.

## Reports
| Script | Finds | Graph scopes | Licence |
|---|---|---|---|
| `Get-RiskyAppPermissions.ps1` | Apps with high-risk Graph permissions and whether they hold a credential. Always shows tenant-wide (all users) delegated grants | `Application.Read.All`, `DelegatedPermissionGrant.Read.All` | Free |
| `Get-StandingAdmins.ps1` | Permanent privileged role holders, PIM eligible vs active | `RoleManagement.Read.Directory`, `Directory.Read.All` | P2 for PIM data, falls back without |
| `Get-StaleAccounts.ps1` | Enabled accounts with no recent sign-in, or none ever | `User.Read.All`, `AuditLog.Read.All` | P1 or P2 |

## Output and logs
Every script writes a timestamped CSV to `output/` and appends to `output/iam-automation.log`. Both contain UPNs, so `output/` is gitignored. Treat it as personal data.

## Known limitations
- The leaver does not handle mailboxes (convert to shared **before** removing an Exchange licence), OneDrive handover, devices, MFA methods or shared credentials. Keep those in your offboarding checklist.
- The joiner assigns one licence SKU per run. For per-department licences, use group-based licensing and `-SkipLicense`.
- `signInActivity` can lag real sign-ins by a few hours. Fine for 30 or 90-day thresholds, not live data.
- Graph PowerShell on Windows signs in through WAM, which caches tokens. After a consent grant is revoked, the cached token keeps its old scopes until it expires (about an hour).

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
| Hybrid/ leaver, mover review | Planned. A hybrid joiner is not planned: AD provisioning tools already cover the AD side |

## Versioning
Changes are listed in [CHANGELOG.md](CHANGELOG.md). Use a tagged release, not whatever is on `main` that day, and test it before you rely on it.

## Security
See [SECURITY.md](SECURITY.md) to report a vulnerability. Never post tenant IDs, UPNs or log output in a public issue.

## Licence
[MIT](LICENSE). Provided as is, without warranty.
