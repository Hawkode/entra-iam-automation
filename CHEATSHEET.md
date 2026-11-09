# Cheat sheet

Run from the repo folder, signed in with an admin account.

**Rule:** run with `-WhatIf` first, read the plan, then run the same line again without `-WhatIf`.

- Users synced from AD: `Hybrid\`. Cloud-only users: `Cloud\`.
- Wrong one? It stops with "is synced from AD" or "is cloud-only" before changing anything.
- More examples per script: `Get-Help .\Cloud\Disable-CloudLeaver.ps1 -Full`

## Setup (once)
```powershell
git clone --branch v1.2.1 --depth 1 https://github.com/Hawkode/entra-iam-automation.git C:\Tools\entra-iam-automation
cd C:\Tools\entra-iam-automation
Copy-Item config.example.psd1 config.local.psd1   # then replace every example value
```

## Cloud-only users
```powershell
.\Cloud\New-CloudJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -Manager john.smith@contoso.com -WhatIf
.\Cloud\Move-CloudUser.ps1 -UserPrincipalName jane.doe@contoso.com -Department HR -JobTitle 'HR Assistant' -Manager sarah.jones@contoso.com -WhatIf
.\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -RemoveAuthMethods -ConvertMailbox -WhatIf
```

## Hybrid users (synced from AD)
```powershell
.\Hybrid\New-HybridJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -Manager john.smith@contoso.com -WhatIf
.\Hybrid\Move-HybridUser.ps1 -UserPrincipalName jane.doe@contoso.com -Department HR -JobTitle 'HR Assistant' -Manager sarah.jones@contoso.com -WhatIf
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -RemoveAuthMethods -ConvertMailbox -WhatIf
```

## Reports (read-only, no -WhatIf)
```powershell
.\Reports\Get-MfaRegistration.ps1
.\Reports\Get-StaleAccounts.ps1 -StaleDays 90
.\Reports\Get-StandingAdmins.ps1 -PrivilegedOnly
.\Reports\Get-RiskyAppPermissions.ps1
.\Reports\Get-ManagerCoverage.ps1
```

## Extras
Add to the lines above when needed.

| Add | To | Does |
|---|---|---|
| `-AutoReplyMessage 'Jane has left. Contact finance@contoso.com.'` | Leavers, with `-ConvertMailbox` | Auto-reply on the shared mailbox |
| `-HideFromGal` | Leavers (cloud: with `-ConvertMailbox`) | Hides from the address list |
| `-DelegateTo team.lead@contoso.com` | Leavers, with `-ConvertMailbox` | Someone other than the manager gets Full Access |
| `-NoDelegate` | Leavers, with `-ConvertMailbox` | Nobody gets access |
| `-KeepLicense` | Leavers | Keeps the licence |
| `-CsvPath .\joiners.local.csv` | Joiners, instead of the name parameters | Many joiners at once. Columns: GivenName, Surname, Department, JobTitle, Manager |
| `-SkipLicense` | Joiners | No licence (group-based licensing) |
| `-ResumeUserPrincipalName jane.doe@contoso.com` | Hybrid joiner, on its own | Finishes usage location and licence after a slow sync |
| `-IncludeOnPrem` | `Get-StaleAccounts` | Also checks AD last logon |
| `-IncludeGuests` | `Get-MfaRegistration`, `Get-ManagerCoverage` | Includes guests |
| `-MinimumRisk Low` | `Get-RiskyAppPermissions` | Shows lower-risk apps too |

Tenant, domain, licence, departments, OUs and the sync server live in `config.local.psd1`. Never edit a script for one run.

## Habits
- **Movers:** always give the new manager with `-Manager`. To change only the manager, keep the current department.
- **Mailbox access:** check who gets it in the leaver plan before pressing `Y`. It usually needs HR approval.
- **Departments** must match `AllowedDepartments` (cloud) or a key of `DepartmentOUs` (hybrid) exactly.
- **Temporary passwords** show once. Send them through a one-time secret link, not email or chat.
- **Output:** CSVs and the log in `output\` contain UPNs. Delete them once reviewed.
- **Consent prompt:** accept for yourself only. Never tick "Consent on behalf of your organization".
