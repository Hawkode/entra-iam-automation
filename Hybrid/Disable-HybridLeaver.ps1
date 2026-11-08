<#
.SYNOPSIS
    Offboards a synced leaver: AD first, then sync, then Entra ID.

.DESCRIPTION
    For hybrid tenants where AD DS is the source of authority. Order matters:

      AD
        1. Disable the account.
        2. Reset the password to a random value, so re-enabling the account by
           mistake does not bring the old password back.
        3. Record the AD group memberships (to the CSV), then remove them, except
           ProtectedAdGroups (default: Domain Users).
        4. Clear the department (the Dept- dynamic groups drop the user after sync)
           and stamp the description with the date, ticket and operator.
        5. Move the account to LeaversOU.
      Sync
        6. Run an Entra Connect delta sync and wait until Entra ID shows the account
           as disabled. Until then the cloud account is still enabled, and with
           password hash sync the old password still works there.
      Entra ID
        7. Revoke sign-in sessions.
        8. Remove cloud-only assigned groups and direct licences.

    If LeaversOU is outside the sync scope, step 6 deletes the cloud account
    (Entra ID Deleted users, 30 days) and soft-deletes its mailbox. The script
    detects this and skips the cloud steps. Convert the mailbox to shared BEFORE
    running the leaver if it has to be kept.

    Everything is listed before anything changes, then confirmed once.
    Refuses break-glass accounts, your own account, and AD protected accounts
    (adminCount = 1: members of Domain Admins and other privileged groups).

    Reported, not removed: active directory roles (removing them would need
    RoleManagement.ReadWrite.Directory).

    Graph scopes (delegated): User.ReadWrite.All, GroupMember.ReadWrite.All, RoleManagement.Read.Directory
    AD rights: disable, reset password, edit and move users in the source OUs and LeaversOU,
    and remove members from their groups. Entra Connect server: WinRM and ADSyncOperators.

.PARAMETER Ticket
    Ticket or request reference, written to the AD description and the CSV.

.PARAMETER KeepLicense
    Skip licence removal, for example while a mailbox is converted to shared.

.EXAMPLE
    .\Hybrid\Disable-HybridLeaver.ps1 -UserPrincipalName stefan.ionescu@contoso.com -Ticket INC12345 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$Ticket,
    [switch]$KeepLicense,
    [int]$SyncTimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig -Require BreakGlassUpns, LeaversOU, EntraConnectServer
$protected = if ($cfg.ProtectedAdGroups) { @($cfg.ProtectedAdGroups) } else { @('Domain Users') }
if (@($cfg.BreakGlassUpns) -contains $UserPrincipalName) {
    throw "$UserPrincipalName is a break-glass account. The leaver script will not touch it."
}

Import-IamAdModule
$ad = Get-ADUser -Filter "UserPrincipalName -eq '$UserPrincipalName'" -Properties Department, Description, MemberOf, Enabled, adminCount
if (-not $ad) { throw "$UserPrincipalName not found in AD." }
if ($ad.adminCount -eq 1) {
    throw "$UserPrincipalName is an AD protected account (adminCount = 1). Offboard it by hand with a Tier 0 admin account."
}
if ($ad.SamAccountName -eq [Environment]::UserName) { throw 'You are signed in to Windows as the account you are trying to offboard.' }
try { $null = Get-ADOrganizationalUnit -Identity $cfg.LeaversOU }
catch { throw "LeaversOU not found: $($cfg.LeaversOU)" }

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'RoleManagement.Read.Directory'
if ((Get-MgContext).Account -eq $UserPrincipalName) {
    throw 'You are signed in to Graph as the account you are trying to offboard. Use a different admin account.'
}
$cloud = Assert-IamSyncState -UserPrincipalName $UserPrincipalName -Expected Hybrid

# ---- Plan (read-only) ----
$adGroups = @()
foreach ($dn in @($ad.MemberOf)) {
    $g = Get-ADGroup -Identity $dn
    if ($protected -notcontains $g.Name) { $adGroups += [pscustomobject]@{ Name = $g.Name; DN = $dn } }
}
$cloudGroups = @()
$manual = @()
foreach ($m in (Get-MgUserMemberOf -UserId $cloud.Id -All)) {
    $props = $m.AdditionalProperties
    if ($props.'@odata.type' -ne '#microsoft.graph.group') { continue }
    if (@($props.groupTypes) -contains 'DynamicMembership') { continue }
    if ($props.onPremisesSyncEnabled -eq $true) { continue }   # AD groups, handled in AD
    $roleAssignable = $props.isAssignableToRole -eq $true
    $exchangeManaged = ($props.mailEnabled -eq $true) -and (@($props.groupTypes) -notcontains 'Unified')
    if ($roleAssignable -or $exchangeManaged) { $manual += "Cloud group (remove by hand): $($props.displayName)" }
    else { $cloudGroups += [pscustomobject]@{ Name = $props.displayName; Id = $m.Id } }
}
foreach ($a in (Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($cloud.Id)'" -All)) {
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
    $manual += "Directory role (remove by hand): $($role.DisplayName)"
}

$oldDN = $ad.DistinguishedName
$stamp = 'Leaver {0:yyyy-MM-dd} {1} by {2}' -f (Get-Date), $Ticket, [Environment]::UserName
$plan = @('AD: disable', 'reset password')
if ($adGroups.Count) { $plan += "remove from $($adGroups.Count) AD group(s): $($adGroups.Name -join ', ')" }
$plan += "clear department '$($ad.Department)'", "description '$stamp'", "move to $($cfg.LeaversOU)", 'delta sync'
$plan += 'Entra: revoke sessions'
if ($cloudGroups.Count) { $plan += "remove from $($cloudGroups.Count) cloud group(s): $($cloudGroups.Name -join ', ')" }
if ($KeepLicense) { $plan += 'keep licences (-KeepLicense)' } else { $plan += 'remove direct licences' }

Write-IamLog -Message "Leaver plan for ${UserPrincipalName}: $($plan -join '; ')"
foreach ($item in $manual) { Write-IamLog -Level WARN -Message "Manual follow-up for ${UserPrincipalName}: $item" }

if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, ($plan -join '; '))) { return }

# ---- AD ----
# 1-2. Disable and reset. If either fails, stop.
Disable-ADAccount -Identity $ad.ObjectGUID
Set-ADAccountPassword -Identity $ad.ObjectGUID -Reset -NewPassword (ConvertTo-IamSecureString -Text (Get-IamRandomPassword -Length 32))
Write-IamLog -Message "AD: disabled and password reset: $UserPrincipalName"

# 3. AD groups. Carry on past a failure and report it.
$adRemoved = @()
foreach ($g in $adGroups) {
    try {
        Remove-ADGroupMember -Identity $g.DN -Members $ad.ObjectGUID -Confirm:$false
        $adRemoved += $g.Name
        Write-IamLog -Message "AD: removed $UserPrincipalName from $($g.Name)"
    }
    catch {
        $manual += "AD group (removal failed): $($g.Name)"
        Write-IamLog -Level ERROR -Message "AD: could not remove $UserPrincipalName from $($g.Name): $($_.Exception.Message)"
    }
}

# 4-5. Department, description, move.
Set-ADUser -Identity $ad.ObjectGUID -Clear department -Description $stamp
Move-ADObject -Identity $ad.ObjectGUID -TargetPath $cfg.LeaversOU
Write-IamLog -Message "AD: department cleared, description stamped, moved to $($cfg.LeaversOU): $UserPrincipalName"

# ---- Sync ----
$null = Invoke-IamDeltaSync -Server $cfg.EntraConnectServer -TimeoutSeconds $SyncTimeoutSeconds
$state = Wait-IamCloudUser -UserId $cloud.Id -TimeoutSeconds $SyncTimeoutSeconds -Until { param($x) $x.AccountEnabled -eq $false }

# ---- Entra ID ----
$cloudOutcome = ''
$cloudRemoved = @()
if ($state -eq 'Deleted') {
    $cloudOutcome = 'Deleted by sync (LeaversOU outside sync scope)'
    Write-IamLog -Level WARN -Message ("$UserPrincipalName was deleted from Entra ID by the sync: LeaversOU is outside the sync scope. " +
        'Licences are released and sessions end with the account. Restore window: 30 days in Deleted users.')
}
else {
    if (-not $state) {
        $cloudOutcome = 'Not disabled in Entra ID by timeout'
        $manual += 'Cloud account still enabled at timeout: check the sync, then confirm it shows as disabled'
        Write-IamLog -Level WARN -Message "$UserPrincipalName still shows as enabled in Entra ID. Revoking sessions anyway."
    }
    else { $cloudOutcome = 'Disabled in Entra ID' }

    Revoke-IamUserSession -UserId $cloud.Id -Confirm:$false

    foreach ($g in $cloudGroups) {
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "v1.0/groups/$($g.Id)/members/$($cloud.Id)/`$ref" | Out-Null
            $cloudRemoved += $g.Name
            Write-IamLog -Message "Entra: removed $UserPrincipalName from $($g.Name)"
        }
        catch {
            $manual += "Cloud group (removal failed): $($g.Name)"
            Write-IamLog -Level ERROR -Message "Entra: could not remove $UserPrincipalName from $($g.Name): $($_.Exception.Message)"
        }
    }

    if (-not $KeepLicense) {
        try { Remove-IamUserLicense -UserId $cloud.Id -Confirm:$false }
        catch {
            $manual += 'Licence removal failed'
            Write-IamLog -Level ERROR -Message "Licence removal failed for ${UserPrincipalName}: $($_.Exception.Message)"
        }
    }
}

$csv = Get-IamOutputPath -Prefix 'HybridLeaver'
[pscustomobject]@{
    Upn                  = $UserPrincipalName
    Ticket               = $Ticket
    Operator             = [Environment]::UserName
    OldDistinguishedName = $oldDN
    OldDepartment        = $ad.Department
    OldDescription       = $ad.Description
    AdGroupsRemoved      = ($adRemoved -join '; ')
    CloudOutcome         = $cloudOutcome
    CloudGroupsRemoved   = ($cloudRemoved -join '; ')
    LicencesKept         = [bool]$KeepLicense
    ManualFollowUp       = ($manual -join '; ')
} | Export-Csv -Path $csv -NoTypeInformation

if ($manual.Count) {
    Write-IamLog -Level WARN -Message "Leaver done with $($manual.Count) manual item(s) for ${UserPrincipalName}. CSV: $csv"
    $manual | ForEach-Object { Write-Warning $_ }
}
else {
    Write-IamLog -Message "Leaver done for ${UserPrincipalName}, no manual items. CSV: $csv"
}
