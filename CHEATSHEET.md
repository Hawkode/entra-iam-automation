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
git clone --branch v1.2.0 --depth 1 https://github.com/Hawkode/entra-iam-automation.git C:\Tools\entra-iam-automation
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
.\Reports\Get-MfaRegistration.ps1                                # needs P1
.\Reports\Get-ManagerCoverage.ps1
```

## Hybrid (users synced from AD DS)
```powershell
# Joiner: one user, with manager
.\Hybrid\New-HybridJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -Manager john.smith@contoso.com -WhatIf
.\Hybrid\New-HybridJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -Manager john.smith@contoso.com

# Joiner: a list (columns GivenName, Surname, Department, JobTitle, Manager). Name real lists *.local.csv so git ignores them.
.\Hybrid\New-HybridJoiner.ps1 -CsvPath .\joiners.local.csv -WhatIf

# Joiner: finish usage location and licence later, if the sync was slow
.\Hybrid\New-HybridJoiner.ps1 -ResumeUserPrincipalName jane.doe@contoso.com

# Mover
.\Hybrid\Move-HybridUser.ps1 -UserPrincipalName jane.doe@contoso.com -Department HR -JobTitle 'HR Assistant' -WhatIf

# Leaver (asks for confirmation once)
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -WhatIf
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -KeepLicense

# Leaver: full offboarding (MFA methods removed, mailbox to shared for the manager, auto-reply, hidden from GAL)
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -RemoveAuthMethods -ConvertMailbox -HideFromGal -AutoReplyMessage 'Jane has left. Please contact finance@contoso.com.' -WhatIf

# Leaver: mailbox to someone other than the manager, or to nobody
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -ConvertMailbox -DelegateTo team.lead@contoso.com -WhatIf
.\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -Ticket INC12345 -ConvertMailbox -NoDelegate -WhatIf
```

## Cloud (cloud-only users)
```powershell
# Joiner
.\Cloud\New-CloudJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -JobTitle 'Accounts Assistant' -Manager john.smith@contoso.com -WhatIf
.\Cloud\New-CloudJoiner.ps1 -CsvPath .\joiners.local.csv -WhatIf
.\Cloud\New-CloudJoiner.ps1 -GivenName Jane -Surname Doe -Department Finance -SkipLicense   # group-based licensing

# Mover
.\Cloud\Move-CloudUser.ps1 -UserPrincipalName jane.doe@contoso.com -Department HR -JobTitle 'HR Assistant' -WhatIf

# Leaver (asks for confirmation once)
.\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -WhatIf
.\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -RemoveAuthMethods -ConvertMailbox -HideFromGal -AutoReplyMessage 'Jane has left. Please contact finance@contoso.com.' -WhatIf
.\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName jane.doe@contoso.com -ConvertMailbox -DelegateTo team.lead@contoso.com -WhatIf
```

## What changes per run
| Script | Change each time |
|---|---|
| Joiner | `-GivenName`, `-Surname`, `-Department`, `-JobTitle`, `-Manager`, or `-CsvPath` |
| Mover | `-UserPrincipalName`, `-Department`, `-JobTitle` (optional) |
| Leaver | `-UserPrincipalName`, `-Ticket` (hybrid), options: `-RemoveAuthMethods`, `-ConvertMailbox`, `-DelegateTo`, `-NoDelegate`, `-AutoReplyMessage`, `-HideFromGal` |

Tenant, domain, licence, departments, OUs and the sync server live in `config.local.psd1`. Set them once. Never edit a script for a single run.

## Habits
- **Leavers:** use `-ConvertMailbox` if the mailbox has to be kept. Check who gets access in the plan before pressing `Y`: access to a leaver's mailbox usually needs HR approval.
- **Managers:** set `-Manager` on every joiner. `Get-ManagerCoverage.ps1` shows who is missing one.
- **Departments** must match `AllowedDepartments` (cloud) or a key of `DepartmentOUs` (hybrid) exactly.
- **Temporary passwords** appear once on screen. Pass them on through a one-time secret link, not email or chat.
- **Output:** CSVs and the log in `output\` contain UPNs. Delete them once reviewed.
- **Consent prompt:** accept for yourself only. Never tick "Consent on behalf of your organization".
