# Entra IAM Automation

[![lint](https://github.com/Hawkode/entra-iam-automation/actions/workflows/lint.yml/badge.svg)](https://github.com/Hawkode/entra-iam-automation/actions/workflows/lint.yml)

PowerShell (Microsoft Graph SDK) scripts for identity lifecycle and security reporting in Microsoft Entra ID.
Companion to [IAM Lab in Microsoft Entra ID](https://hawkode.github.io/projects/entra-iam-lab/).

> **Test in a non-production tenant first.** The lifecycle scripts create, change and disable accounts.

| Folder | Contents |
|---|---|
| `Cloud/` | Joiner, mover, leaver for cloud-only users |
| `Hybrid/` | Joiner, mover, leaver for users synced from AD DS (AD first, then Entra Connect sync, then Graph) |
| `Reports/` | Read-only security reports, same in cloud-only and hybrid tenants |
| `Governance/` | Access review campaigns: extract per reviewer, then apply the decisions with evidence |
| `Shared/` | Common module used by every script |
| `samples/` | Example input files (fake names only) |

## Requirements
- Windows PowerShell 5.1 or PowerShell 7.
- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`
- For the leavers' `-ConvertMailbox` only: `Install-Module ExchangeOnlineManagement -Scope CurrentUser`
- An admin account with the Entra role each script needs (User Administrator for the lifecycle scripts).
- Licences: lifecycle scripts, `Get-RiskyAppPermissions`, `Get-ManagerCoverage` and the access review scripts work on Entra ID Free (`-IncludeSignIn` needs P1). `Get-StaleAccounts` and `Get-MfaRegistration` need P1. PIM data in `Get-StandingAdmins` needs P2.
- **Design requirement for the mover and leaver:** access is granted through dynamic groups keyed on the `department` attribute (dynamic groups need P1). Without that design the scripts still run, but changing the department moves no access.

## Use it in your own tenant
1. Get the latest tagged release, not `main`. Replace `v1.3.0` with the newest tag on the Releases page. Keep the folder out of OneDrive and other synced folders (see [Output and logs](#output-and-logs)).
   ```powershell
   git clone --branch v1.3.0 --depth 1 https://github.com/Hawkode/entra-iam-automation.git C:\Tools\entra-iam-automation
   ```
   No Git? Download **Source code (zip)** from the release page, extract it, then run `Get-ChildItem -Recurse -File | Unblock-File` in the folder. Windows marks files from a downloaded zip as coming from the internet, and the `RemoteSigned` execution policy blocks them.
2. Copy `config.example.psd1` to `config.local.psd1` and replace every example value (reference below). `config.local.psd1` is gitignored. Scripts refuse to run while a value they need is empty or still holds an example value.
3. Run a read-only report first. It proves sign-in, consent and the module work in your tenant:
   ```powershell
   .\Reports\Get-RiskyAppPermissions.ps1
   ```
4. Run lifecycle scripts with `-WhatIf`, then for real on a test user, then in normal use.

**Hybrid tenants (users synced from AD DS):** use the `Hybrid/` lifecycle scripts. The `Cloud/` scripts refuse synced users by design, and the `Hybrid/` scripts refuse cloud-only users. See [Hybrid lifecycle](#hybrid-lifecycle) for the extra requirements.

**Consent:** the first run of each script asks you to consent to *Microsoft Graph Command Line Tools* for the scopes it needs. Consent for yourself only. Do **not** tick "Consent on behalf of your organization", which grants those scopes to every user in the tenant. Scripts use delegated sign-in only: no app registrations, no secrets.

### Before you run it in production
- **Approval:** get written approval before the first run, including read-only reports. They read directory data and write it to CSV.
- **Consent blocked?** If the consent prompt asks for admin approval, or only offers to consent for the whole organisation, stop. A tenant-wide grant is a governance decision for your tenant owners, not a setup step.
- **Execution policy:** check with `Get-ExecutionPolicy -List`. If Group Policy enforces `AllSigned`, sign the scripts with your organisation's code-signing certificate rather than loosening the policy.
- **Accounts:** run the Graph scripts with a dedicated cloud-only admin account. Hybrid scripts also need an on-prem account with delegated rights on the target OUs. Do not use Domain Admin from a workstation.
- **Departments:** `AllowedDepartments` must match the values already in your directory exactly. List them first:
  ```powershell
  Connect-MgGraph -TenantId '<your-tenant-id>' -Scopes 'User.Read.All' -NoWelcome
  Get-MgUser -All -Property Department | Group-Object Department | Sort-Object Count -Descending | Select-Object Count, Name
  ```

### Config reference
| Key | Used by | Value |
|---|---|---|
| `TenantId` | All | Tenant ID (Entra admin center > Overview) |
| `DefaultDomain` | Joiner | Domain new UPNs are created in |
| `UpnFormat` | Joiner | UPN prefix pattern. Tokens `{given}`, `{surname}`, `{g}`, `{s}`. Default `{given}.{surname}` |
| `UsageLocation` | Joiner | Two-letter country code, e.g. `GB` |
| `LicenseSkuPartNumber` | Joiner | SKU to assign (`Get-MgSubscribedSku`). Not needed with `-SkipLicense` |
| `StaleDays` | Stale accounts | Days without sign-in before an account is flagged |
| `BreakGlassUpns` | Leaver, reports | Emergency access accounts. The leaver refuses to touch them. `Get-MfaRegistration` flags them without phishing-resistant MFA, the other reports mark them as expected |
| `AllowedDepartments` | Joiner, mover | Exact department names your dynamic groups key on |
| `DepartmentOUs` | Hybrid joiner, mover | Department name to OU. The keys are the allowed departments in hybrid scripts |
| `LeaversOU` | Hybrid leaver | OU for disabled leavers. Check its sync scope first (see below) |
| `EntraConnectServer` | Hybrid | Active Entra Connect server (not staging) |
| `ProtectedAdGroups` | Hybrid leaver, mover | AD groups never removed or listed. Default `Domain Users` |
| `ReviewFallbackUpn` | Access review extract | Reviewer for groups with no enabled owner, and for rows where the owner would review their own access |
| `LeaversOUInSyncScope` | Hybrid leaver with `-ConvertMailbox` | `$true` only after checking that `LeaversOU` is inside the Entra Connect sync scope (see below) |

## Cloud lifecycle
| Script | Does | Graph scopes |
|---|---|---|
| `New-CloudJoiner.ps1` | Creates users (single or CSV), sets department and usage location, assigns the licence | `User.ReadWrite.All`, `LicenseAssignment.Read.All` |
| `Move-CloudUser.ps1` | Changes department so dynamic groups re-scope access, lists assigned groups and roles that do not move | `User.ReadWrite.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory` |
| `Disable-CloudLeaver.ps1` | Disables, revokes sessions, removes assigned groups and direct licences, clears department. Options below | `User.ReadWrite.All`, `GroupMember.ReadWrite.All`, `RoleManagement.Read.Directory` |

Both joiners take `-Manager <upn>` (or a `Manager` CSV column). Both movers take `-Manager` too, and warn when the department changes but the manager does not. The leavers use the manager to hand over the mailbox.

## Hybrid lifecycle
| Script | Does | Graph scopes |
|---|---|---|
| `New-HybridJoiner.ps1` | Creates the user in AD in the department's OU, runs a delta sync, waits for the user in Entra ID, sets usage location and assigns the licence. `-ResumeUserPrincipalName` finishes the cloud steps later if the sync is slow | `User.ReadWrite.All`, `LicenseAssignment.Read.All` |
| `Move-HybridUser.ps1` | Changes department and title in AD, moves the account to the new department's OU, syncs. Lists AD groups, cloud-only groups and roles that do not move | `User.Read.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory` (read-only) |
| `Disable-HybridLeaver.ps1` | Disables and resets the password in AD, records and removes AD groups, clears department, stamps the description with date, ticket and operator, moves to `LeaversOU`, syncs, waits for the cloud account to show as disabled, then revokes sessions and removes cloud groups and direct licences | `User.ReadWrite.All`, `GroupMember.ReadWrite.All`, `RoleManagement.Read.Directory` |

### Hybrid requirements
- RSAT Active Directory module on the machine you run from (Windows 11: Settings > System > Optional features).
- An on-prem account with delegated rights on the OUs in `DepartmentOUs` and `LeaversOU`: create, edit, move, disable and reset password on users, and remove members from their groups. Not Domain Admin.
- WinRM to `EntraConnectServer`, and membership of `ADSyncOperators` (or local admin) on it.
- `DefaultDomain` must be a UPN suffix in AD (AD Domains and Trusts) and a verified domain in Entra ID. The joiner checks the AD side.

### Check the Leavers OU sync scope first
On the Entra Connect server: Microsoft Entra Connect > **Configure** > **Customize synchronization options** > **Domain and OU filtering**. Read the setting, then **Cancel**.
- **Leavers OU inside the scope:** the cloud account stays, disabled. The leaver revokes sessions and removes licences.
- **Leavers OU outside the scope:** the sync **deletes** the cloud account (Deleted users, 30 days) and **soft-deletes its mailbox**. The leaver detects this and skips the cloud steps. `-ConvertMailbox` refuses to run in this setup (`LeaversOUInSyncScope = $false`): if the mailbox has to be kept, convert it by hand before running the leaver.

The same applies to the mover: if a department OU is outside the scope, moving a user into it deletes their cloud account. The mover checks after the sync and reports it.

## Leaver options (cloud and hybrid)
| Option | Does | Needs |
|---|---|---|
| `-RemoveAuthMethods` | Removes every registered MFA method (Authenticator, phone, FIDO2, OATH, Windows Hello, TAP, email). Two passes, because Graph only removes the default method once it is the last one | `UserAuthenticationMethod.ReadWrite.All` (Critical, requested only with this switch) and Authentication Administrator |
| `-ConvertMailbox` | Converts the mailbox to shared before the licence goes. Gives Full Access to the manager by default | `ExchangeOnlineManagement` and Exchange Recipient Management |
| `-DelegateTo <upn>` / `-NoDelegate` | Someone other than the manager gets access, or nobody does | `-ConvertMailbox` |
| `-AutoReplyMessage '<text>'` | Sets an automatic reply on the shared mailbox | `-ConvertMailbox` |
| `-HideFromGal` | Hides from the address list. Cloud: on the mailbox. Hybrid: in AD (`msExchHideFromAddressLists`), only if the Exchange schema is in AD | Cloud: `-ConvertMailbox` |

- **The licence stays automatically** if the shared mailbox still needs one: over 50 GB, litigation hold or an active archive. If conversion fails, the licence stays too.
- **Without `-ConvertMailbox`**, the plan warns when a licensed mailbox would be deleted 30 days after the licence goes.
- **Hybrid order:** the mailbox is converted first, before any AD change, and only when `LeaversOUInSyncScope = $true`. A shared mailbox belongs to its user object: if the sync deletes the cloud account, the mailbox goes with it.
- **Mailbox access is personal data.** Access to a leaver's mailbox usually needs HR approval. Agree the "manager gets Full Access" default as policy, or name the person with `-DelegateTo`.
- **On-prem Exchange:** if an on-prem Exchange server still manages recipients, also run `Set-RemoteMailbox -Type Shared` on-prem.

## Safety controls
- **Config check:** every script validates the config values it needs before signing in.
- **Sync guard:** Cloud scripts stop on users synced from AD. Hybrid scripts stop on cloud-only users.
- **Soft-match guard:** the hybrid joiner stops if the UPN already exists in Entra ID, because Entra Connect would match the new AD account onto that cloud account and take it over.
- **Department allowlist:** departments must match `AllowedDepartments` (cloud) or a key of `DepartmentOUs` (hybrid), so a typo cannot create a user outside every dynamic group.
- **Validate first:** the joiner checks every row, UPN and manager before creating anything. One bad row, nothing created. The mover checks the new manager before changing anything.
- **`-WhatIf`** on every script that changes something.
- **Leavers:** list the full plan, then ask for confirmation once. Refuse break-glass accounts and the signed-in admin. The hybrid leaver also refuses AD protected accounts (`adminCount = 1`, members of Domain Admins and similar), which need a Tier 0 admin.
- **Hybrid leaver order:** sessions are revoked only after Entra ID shows the account as disabled. Before that, with password hash sync, the old password still works in the cloud.
- **Not automated on purpose:** removing directory roles (would need `RoleManagement.ReadWrite.Directory`). Reported for manual action instead.
- **Critical scopes only on request:** `UserAuthenticationMethod.ReadWrite.All` is requested only when `-RemoveAuthMethods` is used.
- **Temporary passwords** are shown once in the console and never logged or written to CSV.

## Reports
| Script | Finds | Graph scopes | Licence |
|---|---|---|---|
| `Get-RiskyAppPermissions.ps1` | Apps with high-risk Graph permissions and whether they hold a credential. Always shows tenant-wide (all users) delegated grants | `Application.Read.All`, `DelegatedPermissionGrant.Read.All` | Free |
| `Get-StandingAdmins.ps1` | Permanent privileged role holders, PIM eligible vs active | `RoleManagement.Read.Directory`, `Directory.Read.All` | P2 for PIM data, falls back without |
| `Get-StaleAccounts.ps1` | Enabled accounts with no recent sign-in, or none ever | `User.Read.All`, `AuditLog.Read.All` | P1 or P2 |
| `Get-MfaRegistration.ps1` | Users with no MFA, only weak methods (SMS, voice, email), admins and break-glass accounts without a phishing-resistant method | `AuditLog.Read.All` (role: Reports Reader) | P1 or P2 |
| `Get-ManagerCoverage.ps1` | Enabled users with no manager or a disabled manager. The leavers' mailbox handover depends on it | `User.Read.All` | Free |

## Access reviews
A quarterly recertification without Entra ID P2: each group owner gets a CSV of who is in their groups, marks each row Keep or Revoke, and sends it back. The second script checks the returned files and applies the decisions.

| Script | Does | Graph scopes |
|---|---|---|
| `Get-AccessReviewExtract.ps1` | One CSV per reviewer (the group's first enabled owner), with flags: disabled, guest or external, outside the group's main department, nested group, inactive (`-IncludeSignIn`). Plus `_master.csv`, the reference copy | `GroupMember.Read.All`, `User.Read.All` (+ `AuditLog.Read.All` with `-IncludeSignIn`) |
| `Invoke-AccessReviewDecisions.ps1` | Validates the returned files, removes the Revoke rows, writes `_evidence-*.csv` and `_summary-*.csv`. `-StatusOnly` shows completion per reviewer without signing in | `GroupMember.ReadWrite.All` |

**Running a campaign**
1. Extract: `.\Governance\Get-AccessReviewExtract.ps1 -GroupName 'Finance Share', 'Payroll App' -Campaign Q4-2026`
2. Send each `<reviewer>.csv` from `output\AccessReview-Q4-2026\` to its reviewer with a deadline. Keep `_master.csv` to yourself.
3. Save each returned file over the original, same name. Check progress with `-StatusOnly`.
4. Apply: run with `-Ticket` and `-WhatIf`, read the plan, then run again without `-WhatIf`.
5. File the evidence and summary CSVs with the reviewers' replies, under the ticket.

**Controls built in**
- **No self-review:** a row where the owner is the member goes to `ReviewFallbackUpn`. So does every group with no enabled owner, and the log lists those groups as findings.
- **Validate first:** every returned row must match `_master.csv`: same reviewer file, same GroupId and MemberId, no duplicates, decision Keep, Revoke or empty. One problem and nothing changes. The problems go to `_validation-*.csv`.
- **Justified exceptions:** Keep on a flagged row needs a Reason.
- **Fresh data only:** an extract older than 30 days is refused (`-MaxExtractAgeDays`).
- **Not automatic:** unreviewed rows are reported, never removed. Break-glass accounts, your own access, and rows in role-assignable, AD-synced or mail-enabled security groups are listed for manual action.
- **Rerun-safe:** membership is re-read before removal, so access already removed counts as done.

**Limits**
- Groups only. Dynamic groups are skipped (fix the attribute instead), distribution groups too. Directory roles: use `Get-StandingAdmins`.
- A CSV cannot prove who edited it. The evidence records which file each decision came from: keep the reviewer's reply as proof of who decided. This is the gap a governance tool such as Entra ID Governance closes.
- Excel: save returned files as CSV with the same name. Do not open `_master.csv` in Excel and save it.

## Output and logs
Every script writes a timestamped CSV to `output/` and appends to `output/iam-automation.log`. Both contain UPNs: `output/` is gitignored, keep the folder out of OneDrive and other synced folders, and delete old files once they have served their purpose.

## Known limitations
- The leavers do not handle OneDrive handover, devices or shared credentials. Keep those in your offboarding checklist.
- `-RemoveAuthMethods` reports any method type it does not recognise for manual removal. Graph cannot remove the default method while another method remains, so one unrecognised method can leave the default in place too.
- The hybrid joiner does not provision mailboxes through on-prem Exchange (`Enable-RemoteMailbox`). It fits tenants where Exchange Online creates the mailbox when the licence is assigned.
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
| Reports/Get-MfaRegistration.ps1 | Done, tested in lab |
| Reports/Get-ManagerCoverage.ps1 | Done, tested in lab |
| Governance/Get-AccessReviewExtract.ps1 | Done, tested in lab (`-GroupName`, owner, fallback reviewer, department, disabled and self-review flags). `-AllAssignedGroups` and `-IncludeSignIn` untested |
| Governance/Invoke-AccessReviewDecisions.ps1 | Done, tested in lab (validation refusal, `-StatusOnly`, `-WhatIf`, removal, evidence). Returned files saved by Excel untested |
| Cloud/New-CloudJoiner.ps1 | Done, tested in lab (single user, CSV, manager) |
| Cloud/Move-CloudUser.ps1 | Done, tested in lab (`-Manager` with `-WhatIf`) |
| Cloud/Disable-CloudLeaver.ps1 | Done, tested in lab (direct licences). Group-assigned licences, `-RemoveAuthMethods` and `-ConvertMailbox` tested offline only |
| Hybrid/New-HybridJoiner.ps1 | Done, tested offline with AD and Graph mocked. Not yet tested against a real domain |
| Hybrid/Move-HybridUser.ps1 | Done, tested offline with AD and Graph mocked. Not yet tested against a real domain |
| Hybrid/Disable-HybridLeaver.ps1 | Done, tested offline with AD, Graph and Exchange mocked. Not yet tested against a real domain |

## Cheat sheet
All commands with example values, ready to copy: [CHEATSHEET.md](CHEATSHEET.md). In a terminal, `Get-Help <script> -Examples` shows the examples for one script.

## Versioning
Changes are listed in [CHANGELOG.md](CHANGELOG.md). Use a tagged release, not whatever is on `main` that day, and test it before you rely on it.

## Security
See [SECURITY.md](SECURITY.md) to report a vulnerability. Never post tenant IDs, UPNs or log output in a public issue.

## Licence
[MIT](LICENSE). Provided as is, without warranty.
