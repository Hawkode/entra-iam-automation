# Admin runbook

For the admin who installs, runs and looks after the scripts (and the IAM console, if you use it). The [README](../README.md) is the reference for each script, config key and safety control. This page is the order to do things in, the routine checks, and what to do when something goes wrong.

Examples use `contoso.com`, `jdoe` and the group `IAM Operators`. Replace them with your own.

## Roles
| Who | Needs | When |
|---|---|---|
| Installer | Local admin on the machine | Install, event source, `-Scope AllUsers` |
| App owner | Global Administrator or Privileged Role Administrator | Once, for `New-IamAppRegistration.ps1`. Again only to change the app |
| Operator | User Administrator (joiner, mover, leaver). Authentication Administrator for Remove MFA. Global Reader or Reports Reader for reports | Every run. Make them PIM eligible, not permanent, where you have P2 |
| Hybrid operator | The above, plus an on-prem account with delegated rights on the department OUs and the Leavers OU, and `ADSyncOperators` on the Entra Connect server | Hybrid runs. Not Domain Admin |

## First install
Do these in order, on the machine the operators will use: a Windows admin workstation or jump server, domain-joined with RSAT for hybrid. Not a domain controller.

### 1. Before you start
- Written approval for the first run, reports included. Reports read directory data and write it to CSV.
- PowerShell 7 installed: `winget install --id Microsoft.PowerShell`
- A folder outside OneDrive and other synced folders: `C:\Tools`
- Close every other PowerShell window, VS Code terminals included. A module in use cannot be replaced.

### 2. Get the release
- `PowerShell 7 (opened from Start, elevated) > run` - use the newest tag from Releases

```powershell
git clone --branch v1.8.0 --depth 1 https://github.com/Hawkode/entra-iam-automation.git C:\Tools\entra-iam-automation
cd C:\Tools\entra-iam-automation
```

### 3. Install the modules and the shortcut
- `Same window > run` - shows the plan, then asks once

```powershell
.\Setup\Install-IamAutomation.ps1 -Scope AllUsers -WhatIf
.\Setup\Install-IamAutomation.ps1 -Scope AllUsers
```
- With the IAM console: add `-ConsolePath C:\Tools\entra-iam-console` for the Start menu shortcut.
- Every module line must say installed or current. "NOT installed" means a window still has it loaded: close it and run again.
- Elevated, the installer also registers the event source. Not elevated: run `.\Setup\Register-IamEventSource.ps1` as admin later.

### 4. Build the config
- `Same window > run` - signs in read-only and asks only for what it cannot find

```powershell
.\Setup\New-IamConfig.ps1 -WhatIf
.\Setup\New-IamConfig.ps1
```
- Check `AllowedDepartments` and `BreakGlassUpns` by hand before you accept them.
- Hybrid: confirm `LeaversOUInSyncScope` only after reading the Entra Connect OU filtering (README, [Check the Leavers OU sync scope first](../README.md#check-the-leavers-ou-sync-scope-first)).

### 5. Create the app registration
- `Entra admin center > Groups > New group > Security > IAM Operators` - add the operators
- `Same window, as the app owner > run`

```powershell
.\Setup\New-IamAppRegistration.ps1 -OperatorGroup 'IAM Operators' -WhatIf
.\Setup\New-IamAppRegistration.ps1 -OperatorGroup 'IAM Operators'
```
- No Entra ID P1: use `-OperatorUpn jdoe@contoso.com` instead of the group.
- It writes `GraphClientId` to `config.local.psd1` after a backup.

### 6. Conditional Access for the operators
- `Entra admin center > Conditional Access > New policy`
- `Users > Include > IAM Operators and the operators' admin roles > Exclude > break-glass accounts`
- `Target resources > All resources` - not the app: error 1034
- `Grant > phishing-resistant MFA and compliant or hybrid-joined device`
- `Session > Sign-in frequency > 4 hours`
- `Enable policy > Report-only` - check the sign-in logs for a week, then On

### 7. Signing (only where the policy is AllSigned)
- `Same window > run`

```powershell
Get-ExecutionPolicy -List
.\Setup\Set-IamSignature.ps1 -Path C:\Tools\entra-iam-automation -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
.\Setup\Set-IamSignature.ps1 -Path C:\Tools\entra-iam-automation -Verify
```
- The thumbprint above is an example: use your organisation's code-signing certificate.

### 8. Console settings (IAM console only)
- `C:\Tools\entra-iam-console > copy console.example.psd1 to console.local.psd1 > set TicketPattern` - match your ticket system's IDs
- Numbers only (for example `12345`): `TicketPattern = '^[0-9]{3,10}$'`

### 9. Smoke test
- `PowerShell 7 > run as an operator, not the app owner`

```powershell
.\Reports\Get-RiskyAppPermissions.ps1
```
- Then a joiner, mover and leaver on a test user: preview first, then run. In the console or with `-WhatIf` then without.
- Check the audit record landed:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'IamAutomation' } -MaxEvents 20 |
    Format-Table TimeCreated, Id, Message -Wrap
```

- Verify: the report wrote a CSV to `output\`, the test user went through all three stages, and the events show the operator's account and computer.
- Rollback: `Remove-Item C:\Tools\entra-iam-automation -Recurse`, then the [Decommission](#decommission) steps for the app and event source.

## Add or remove an operator
- Add: `Entra admin center > Groups > IAM Operators > Members > Add`
- Add: `Entra admin center > Roles and administrators > User Administrator > Add assignments > Eligible` - Active if you have no P2
- Remove: take them out of `IAM Operators` and the role, then `Users > jdoe > Revoke sessions`
- Verify: `Entra admin center > Enterprise applications > IAM Automation > Sign-in logs` - a removed operator gets AADSTS50105 (not assigned)
- Rollback: add them back to the group and the role.

## Upgrade
Read the release's CHANGELOG first. If the release adds Graph scopes, add them to the app before you upgrade: `Entra admin center > App registrations > IAM Automation > API permissions > Add a permission > Microsoft Graph > Delegated`, then **Grant admin consent**.

- `PowerShell 7 (elevated) > run` - keeps the same path, so the shortcut still works

```powershell
cd C:\Tools
Rename-Item entra-iam-automation entra-iam-automation.old
git clone --branch v1.9.0 --depth 1 https://github.com/Hawkode/entra-iam-automation.git entra-iam-automation
Copy-Item .\entra-iam-automation.old\config.local.psd1 .\entra-iam-automation\
Copy-Item .\entra-iam-automation.old\output .\entra-iam-automation\ -Recurse
cd .\entra-iam-automation
.\Setup\Install-IamAutomation.ps1 -Scope AllUsers
```
- Replace `v1.9.0` with the tag you are installing.
- AllSigned: sign again (step 7). Every update breaks the old signatures.
- Run the smoke test (step 9) with previews only.
- Verify: the report runs and the event log shows the run.
- Rollback: `Remove-Item C:\Tools\entra-iam-automation -Recurse`, then `Rename-Item C:\Tools\entra-iam-automation.old entra-iam-automation`
- Delete `entra-iam-automation.old` after a week of normal use.

The console upgrades the same way, in `C:\Tools\entra-iam-console`, keeping `console.local.psd1`.

## Routine checks
| How often | Check | Where |
|---|---|---|
| Monthly | Who ran what, and with which ticket | `Get-WinEvent` query in step 9, or your SIEM |
| Monthly | Operator list is still right | `Enterprise applications > IAM Automation > Users and groups`, and the `IAM Operators` members |
| Monthly | Delete CSVs you no longer need (they hold UPNs) | `output\` |
| Quarterly | Access review campaign | README, [Access reviews](../README.md#access-reviews) |
| Quarterly | New release or Graph module version | Releases page. Upgrade as above |
| Before it expires | Code-signing certificate | Re-sign with the new one (step 7) |

## When a run went wrong
A leaver cuts access at once. Re-enabling the account does not bring the access back: rebuild it from the leaver CSV in `output\`.

| What happened | Fix |
|---|---|
| Wrong user offboarded, cloud | `Users > jdoe > Edit > Account enabled`, issue a Temporary Access Pass, add back the groups in `GroupsRemoved` and the licence, set the department from `OldDepartment`. The user registers MFA again if it was removed |
| Wrong user offboarded, hybrid | Move the account back to `OldDistinguishedName`, enable it, reset the password, add back `AdGroupsRemoved` and the department, restore the description, delta sync. Then the cloud groups in `CloudGroupsRemoved` and the licence |
| Hybrid leaver: cloud account deleted by sync | `Entra admin center > Users > Deleted users > jdoe > Restore` within 30 days, after moving the AD account back into a synced OU |
| Wrong department or manager on a move | Run the mover again with the old values. The log line reads `Moved jdoe@contoso.com. department 'Sales' -> 'Finance', ...` |
| Joiner created a wrong user | Delete the user. It sits in Deleted users for 30 days |
| Hybrid joiner: sync too slow | `.\Hybrid\New-HybridJoiner.ps1 -ResumeUserPrincipalName jdoe@contoso.com` finishes the cloud steps |
| A run stopped half way | Read the log line before running again. The console says "part of it may have run". Check the account in AD and Entra first |

Log every fix under the original ticket.

## Troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| Console shortcut does nothing | Graph modules installed only for Windows PowerShell 5.1 (often in `OneDrive\Documents\WindowsPowerShell\Modules`) | Close all PowerShell windows, open PowerShell 7 from Start (elevated), run `.\Setup\Install-IamAutomation.ps1 -Scope AllUsers` |
| Installer reports a module as NOT installed | Another window has the module loaded | Close every PowerShell window and VS Code terminal, run it again |
| "Needs PowerShell 7" | Started in Windows PowerShell | Open PowerShell 7 from Start. Set it as the Windows Terminal default profile |
| "Need admin approval" at sign-in | No `GraphClientId`: signing in through Microsoft Graph Command Line Tools | Run `New-IamAppRegistration.ps1` (step 5). Never consent for the whole organisation |
| AADSTS50105 at sign-in | Operator not assigned to the app | Add them to `IAM Operators` |
| Conditional Access error 1034 | The policy targets the app | Target the operators and All resources (step 6) |
| Console refuses to run: "cannot write the audit log" | `output\iam-automation.log` created by an elevated session, now read-only for the operator | Run elevated as before, or give the operator write access (below) |
| "Event source not registered" warning | Source missing on this machine | `.\Setup\Register-IamEventSource.ps1` as admin |
| "Not digitally signed" under AllSigned | Files changed since signing (update or edit) | Sign again (step 7) |
| Role or consent change not picked up | WAM caches the token for about an hour | `Disconnect-MgGraph`, close the console, wait, sign in again |
| Hybrid: "did not show up in Entra ID within 60 seconds" | Sync slower than the wait | Check the sync on the Entra Connect server, then `-ResumeUserPrincipalName` (joiner) or check the account (mover, leaver) |

Audit log write access for the operator:
- `Script machine > PowerShell 7 (elevated) > run`

```powershell
icacls C:\Tools\entra-iam-automation\output\iam-automation.log /grant "CONTOSO\jdoe:M"
```

## Decommission
- `Entra admin center > App registrations > IAM Automation > Delete` - removes its consent and assignments
- `Entra admin center > Conditional Access > operator policy > Off or Delete`
- `Script machine > PowerShell 7 (elevated) > run`

```powershell
.\Setup\Register-IamEventSource.ps1 -Remove
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Entra IAM Console.lnk" -ErrorAction SilentlyContinue   # -Scope AllUsers
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Entra IAM Console.lnk" -ErrorAction SilentlyContinue       # -Scope CurrentUser
```
- Keep `output\` CSVs and the event log for your retention period, then delete `C:\Tools\entra-iam-automation`.
- Verify: an operator gets an error when signing in through the app, and the shortcut is gone.
