<#
.SYNOPSIS
    Offboards a cloud-only leaver: disable, revoke sessions, remove access and licences.

.DESCRIPTION
    Order matters, and the script follows it:
      1. Disable the account (blocks new sign-ins).
      2. Revoke sign-in sessions (kills refresh tokens). Disable first, otherwise a
         stolen password could start a new session between the two steps.
      3. Remove assigned group memberships.
      4. Remove direct licences (group-assigned licences drop with the group).
      5. Clear the department, so the Dept- dynamic groups drop the user.

    Everything is listed before anything changes, then confirmed once.
    Refuses to run on break-glass accounts from config or on your own account.

    Reported, not removed (needs a human or a higher-privileged admin):
      - Active directory roles. Removing them needs RoleManagement.ReadWrite.Directory,
        which this script deliberately does not request.
      - Role-assignable, mail-enabled security and distribution groups, which Graph
        cannot change through this path.

    Not covered, handle in your offboarding checklist: mailbox (convert to shared
    BEFORE removing an Exchange licence, or the mailbox is deleted after 30 days),
    OneDrive handover, devices, MFA methods, shared credentials, assets.

    Cloud-only: stops if the user is synced from AD. Use Hybrid\Disable-HybridLeaver.ps1.

    Graph scopes (delegated): User.ReadWrite.All, GroupMember.ReadWrite.All, RoleManagement.Read.Directory
    Entra role for the signed-in admin: User Administrator (cannot disable admins, by design)

.PARAMETER KeepLicense
    Skip licence removal, for example while a mailbox is converted to shared.

.EXAMPLE
    .\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName stefan.ionescu@contoso.onmicrosoft.com -WhatIf
.EXAMPLE
    .\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName stefan.ionescu@contoso.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [switch]$KeepLicense
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig -Require BreakGlassUpns
if (@($cfg.BreakGlassUpns) -contains $UserPrincipalName) {
    throw "$UserPrincipalName is a break-glass account. The leaver script will not touch it."
}

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'RoleManagement.Read.Directory'

if ((Get-MgContext).Account -eq $UserPrincipalName) {
    throw 'You are signed in as the account you are trying to offboard. Use a different admin account.'
}

$null = Assert-IamSyncState -UserPrincipalName $UserPrincipalName -Expected Cloud
$user = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, UserPrincipalName, AccountEnabled, Department, LicenseAssignmentStates

# ---- Plan (read-only) ----
$removeGroups = @()
$manual = @()
foreach ($m in (Get-MgUserMemberOf -UserId $user.Id -All)) {
    $props = $m.AdditionalProperties
    if ($props.'@odata.type' -ne '#microsoft.graph.group') { continue }
    if (@($props.groupTypes) -contains 'DynamicMembership') { continue }
    $g = [pscustomobject]@{ Name = $props.displayName; Id = $m.Id }
    $roleAssignable = $props.isAssignableToRole -eq $true
    $exchangeManaged = ($props.mailEnabled -eq $true) -and (@($props.groupTypes) -notcontains 'Unified')
    if ($roleAssignable -or $exchangeManaged) { $manual += "Group (remove by hand): $($g.Name)" }
    else { $removeGroups += $g }
}
foreach ($a in (Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -All)) {
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
    $manual += "Directory role (remove by hand): $($role.DisplayName)"
}
$directLicences = @($user.LicenseAssignmentStates | Where-Object { -not $_.AssignedByGroup }).Count

$plan = @('disable account', 'revoke sessions')
if ($removeGroups.Count) { $plan += "remove from $($removeGroups.Count) assigned group(s): $($removeGroups.Name -join ', ')" }
if ($KeepLicense) { $plan += 'keep licences (-KeepLicense)' }
elseif ($directLicences) { $plan += "remove $directLicences direct licence(s)" }
if ($user.Department) { $plan += "clear department '$($user.Department)'" }

Write-IamLog -Message "Leaver plan for ${UserPrincipalName}: $($plan -join '; ')"
foreach ($item in $manual) { Write-IamLog -Level WARN -Message "Manual follow-up for ${UserPrincipalName}: $item" }
if (-not $user.AccountEnabled) { Write-IamLog -Level WARN -Message "$UserPrincipalName is already disabled. Running the remaining steps." }

if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, ($plan -join '; '))) { return }

# ---- Execute ----
$uri = "v1.0/users/$($user.Id)"

# 1. Disable. If this fails, stop: nothing else matters until sign-in is blocked.
Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body '{"accountEnabled": false}' -ContentType 'application/json' | Out-Null
Write-IamLog -Message "Disabled: $UserPrincipalName"

# 2. Revoke sessions. Also stop on failure.
Revoke-IamUserSession -UserId $user.Id -Confirm:$false

# 3. Assigned groups. Carry on past a failure and report it.
foreach ($g in $removeGroups) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "v1.0/groups/$($g.Id)/members/$($user.Id)/`$ref" | Out-Null
        Write-IamLog -Message "Removed $UserPrincipalName from $($g.Name)"
    }
    catch {
        $manual += "Group (removal failed): $($g.Name)"
        Write-IamLog -Level ERROR -Message "Could not remove $UserPrincipalName from $($g.Name): $($_.Exception.Message)"
    }
}

# 4. Licences.
if (-not $KeepLicense) {
    try { Remove-IamUserLicense -UserId $user.Id -Confirm:$false }
    catch {
        $manual += 'Licence removal failed'
        Write-IamLog -Level ERROR -Message "Licence removal failed for ${UserPrincipalName}: $($_.Exception.Message)"
    }
}

# 5. Department, last: the dynamic groups drop the user within minutes.
if ($user.Department) {
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body '{"department": null}' -ContentType 'application/json' | Out-Null
        Write-IamLog -Message "Cleared department '$($user.Department)' on $UserPrincipalName. Dynamic groups update within minutes."
    }
    catch {
        $manual += 'Department not cleared'
        Write-IamLog -Level ERROR -Message "Could not clear department on ${UserPrincipalName}: $($_.Exception.Message)"
    }
}

$csv = Get-IamOutputPath -Prefix 'Leaver'
[pscustomobject]@{
    Upn            = $UserPrincipalName
    Disabled       = $true
    SessionsRevoke = $true
    GroupsRemoved  = ($removeGroups.Name -join '; ')
    LicencesKept   = [bool]$KeepLicense
    OldDepartment  = $user.Department
    ManualFollowUp = ($manual -join '; ')
} | Export-Csv -Path $csv -NoTypeInformation

if ($manual.Count) {
    Write-IamLog -Level WARN -Message "Leaver done with $($manual.Count) manual item(s) for ${UserPrincipalName}. CSV: $csv"
    $manual | ForEach-Object { Write-Warning $_ }
}
else {
    Write-IamLog -Message "Leaver done for ${UserPrincipalName}, no manual items. CSV: $csv"
}