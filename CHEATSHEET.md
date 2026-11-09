# Cheat sheet

Copy, change the values, run. Run everything from the repo folder, signed in with an admin account.
Every script that changes something supports `-WhatIf`: run it first, read the plan, then run again without it.

Per-script help with more examples: `Get-Help .\Hybrid\Disable-HybridLeaver.ps1 -Full`

## Which scripts?
- **Users synced from AD DS** (hybrid): `Hybrid\`
- **Cloud-only users**: `Cloud\`
- Not sure? Run either one. The wrong one stops with "is synced from AD" or "is cloud-only" before it changes anything.

## Setup (once)
```powershell
git clone --branch v1.1.0 --depth 1 https://github.com/Hawkode/entra-iam-automation.git C:\Tools\entra-iam-automation
cd C:\Tools\entra-iam-automation
Copy-Item config.example.psd1 config.local.psd1   # then replace every example value
```

## Reports (read-only)
```powershell
.\Reports\Get-RiskyAppPermissions.ps1
.\Reports\Get-RiskyAppPermissions.ps1 -MinimumRisk Low
.\Reports\Get-StandingAdmins.ps1 -PrivilegedOnly
.\Reports\Get-StaleAccounts.ps1 -StaleDays 90
.\Reports\Get-StaleAccounts.ps1 -StaleDays 90 -IncludeOnPrem   # hybrid: also checks AD lastLogonTimestamp
```

## Hybrid (users synced from AD DS)
```powershell
# Joiner: one user
.\Hybrid\New-HybridJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -WhatIf
.\Hybrid\New-HybridJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant'

# Joiner: a list (columns GivenName, Surname, Department, JobTitle). Name real lists *.local.csv so git ignores them.
.\Hybrid\New-HybridJoiner.ps1 -CsvPath .\joiners.local.csv -WhatIf

# Joiner: finish usage location and licence later, if the sync was slow
.\Hybrid\New-HybridJoiner.ps1 -ResumeUserPrincipalName jane.doe@contoso.com

# Mover
.\Hybrid\Move-HybridUser.ps1 -UserPrincipalName jane.doe@contoso.com -Department HR -JobTitle 'HR Assistant' -WhatIf

# Leaver (asks for confirmation once)
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -WhatIf
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -KeepLicense   # mailbox still being converted
```

## Cloud (cloud-only users)
```powershell
# Joiner
.\Cloud\New-CloudJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -WhatIf
.\Cloud\New-CloudJoiner.ps1 -CsvPath .\joiners.local.csv -WhatIf
.\Cloud\New-CloudJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -SkipLicense   # group-based licensing

# Mover
.\Cloud\Move-CloudUser.ps1 -UserPrincipalName jane.doe@contoso.com -Department HR -JobTitle 'HR Assistant' -WhatIf

# Leaver (asks for confirmation once)
.\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -WhatIf
.\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -KeepLicense
```

## What changes per run
| Script | Change each time |
|---|---|
| Joiner | `-GivenName`, `-Surname`, `-Department`, `-JobTitle`, or `-CsvPath` |
| Mover | `-UserPrincipalName`, `-Department`, `-JobTitle` (optional) |
| Leaver | `-UserPrincipalName`, `-Ticket` (hybrid) |

Tenant, domain, licence, departments, OUs and the sync server live in `config.local.psd1`. Set them once. Never edit a script for a single run.

## Habits
- **Leavers:** convert the mailbox to shared **before** running the leaver if it has to be kept.
- **Departments** must match `AllowedDepartments` (cloud) or a key of `DepartmentOUs` (hybrid) exactly.
- **Temporary passwords** appear once on screen. Pass them on through a one-time secret link, not email or chat.
- **Output:** CSVs and the log in `output\` contain UPNs. Delete them once reviewed.
- **Consent prompt:** accept for yourself only. Never tick "Consent on behalf of your organization".
