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

## Status
| Script | Status |
|---|---|
| Shared module | Done |Powershell and Microsoft Graph scripts for Entra ID Identity lifecycle (cloud-only and hybrid) and security reporting
