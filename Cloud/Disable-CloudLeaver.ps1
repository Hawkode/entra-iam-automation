<#
.SYNOPSIS
    Offboards a cloud-only leaver: disable, revoke sessions, remove access and licences.

.DESCRIPTION
    Order matters, and the script follows it:
      1. Disable the account (blocks new sign-ins).
      2. Revoke sign-in sessions (kills refresh tokens). Disable first, otherwise a
         stolen password could start a new session between the two steps.
      3. Optional: remove MFA / authentication methods (-RemoveAuthMethods).
      4. Optional: convert the mailbox to shared (-ConvertMailbox), BEFORE the licence goes.
      5. Remove assigned group memberships.
      6. Remove direct licences (group-assigned licences drop with the group). Skipped
         automatically when the shared mailbox still needs a licence.
      7. Clear the department, so the Dept- dynamic groups drop the user.

    Everything is listed before anything changes, then confirmed once.
    Refuses to run on break-glass accounts from config or on your own account.

    Reported, not removed (needs a human or a higher-privileged admin):
      - Active directory roles. Removing them needs RoleManagement.ReadWrite.Directory,
        which this script deliberately does not request.
      - Role-assignable, mail-enabled security and distribution groups, which Graph
        cannot change through this path.

    Not covered, handle in your offboarding checklist: OneDrive handover, devices,
    shared credentials, assets. Without -ConvertMailbox, a licensed mailbox is deleted
    30 days after the licence goes: the plan warns about it.

    Cloud-only: stops if the user is synced from AD. Use Hybrid\Disable-HybridLeaver.ps1.

    Mailbox: by default the leaver's manager gets Full Access to the shared mailbox.
    Access to a leaver's mailbox usually needs HR approval: agree this default as policy,
    or name the person with -DelegateTo, or use -NoDelegate.

    Graph scopes (delegated): User.ReadWrite.All, GroupMember.ReadWrite.All, RoleManagement.Read.Directory
      plus UserAuthenticationMethod.ReadWrite.All with -RemoveAuthMethods (Critical: requested only then)
    Roles: User Administrator (cannot disable admins, by design); Authentication Administrator
      for -RemoveAuthMethods; Exchange Recipient Management for -ConvertMailbox.

.PARAMETER KeepLicense
    Skip licence removal.

.PARAMETER RemoveAuthMethods
    Remove every registered authentication method (Authenticator, phone, FIDO2, OATH,
    Windows Hello, TAP, email). The password is reset separately, not removed.

.PARAMETER ConvertMailbox
    Convert the mailbox to shared before the licence is removed. Needs the
    ExchangeOnlineManagement module.

.PARAMETER DelegateTo
    Who gets Full Access to the shared mailbox. Default: the leaver's manager.

.PARAMETER NoDelegate
    Convert without granting anyone access.

.PARAMETER AutoReplyMessage
    Automatic reply text set on the shared mailbox.

.PARAMETER HideFromGal
    Hide the shared mailbox from the address list.

.EXAMPLE
    .\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName stefan.ionescu@contoso.onmicrosoft.com -WhatIf
.EXAMPLE
    .\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName stefan.ionescu@contoso.onmicrosoft.com
.EXAMPLE
    .\Cloud\Disable-CloudLeaver.ps1 -UserPrincipalName stefan.ionescu@contoso.onmicrosoft.com -RemoveAuthMethods -ConvertMailbox -HideFromGal -AutoReplyMessage 'Stefan has left. Please contact it@contoso.com.'
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [switch]$KeepLicense,
    [switch]$RemoveAuthMethods,
    [switch]$ConvertMailbox,
    [string]$DelegateTo,
    [switch]$NoDelegate,
    [string]$AutoReplyMessage,
    [switch]$HideFromGal
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

if (($DelegateTo -or $NoDelegate -or $AutoReplyMessage -or $HideFromGal) -and -not $ConvertMailbox) {
    throw '-DelegateTo, -NoDelegate, -AutoReplyMessage and -HideFromGal need -ConvertMailbox.'
}
if ($DelegateTo -and $NoDelegate) { throw 'Use -DelegateTo or -NoDelegate, not both.' }

$cfg = Import-IamConfig -Require BreakGlassUpns
if (@($cfg.BreakGlassUpns) -contains $UserPrincipalName) {
    throw "$UserPrincipalName is a break-glass account. The leaver script will not touch it."
}

$scopes = @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'RoleManagement.Read.Directory')
if ($RemoveAuthMethods) { $scopes += 'UserAuthenticationMethod.ReadWrite.All' }
Connect-IamGraph -TenantId $cfg.TenantId -Scopes $scopes

if ((Get-MgContext).Account -eq $UserPrincipalName) {
    throw 'You are signed in as the account you are trying to offboard. Use a different admin account.'
}

$null = Assert-IamSyncState -UserPrincipalName $UserPrincipalName -Expected Cloud
$user = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, UserPrincipalName, AccountEnabled, Department, LicenseAssignmentStates, AssignedPlans

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

$authMethods = @()
if ($RemoveAuthMethods) { $authMethods = @(Get-IamUserAuthMethod -UserId $user.Id) }

$manager = $null
if ($ConvertMailbox -and -not $DelegateTo -and -not $NoDelegate) { $manager = Get-IamCloudManager -UserId $user.Id }
$mbx = Get-IamLeaverMailboxPlan -UserPrincipalName $UserPrincipalName -ConvertMailbox:$ConvertMailbox -DelegateTo $DelegateTo `
    -NoDelegate:$NoDelegate -Manager $manager -HasExchangePlan (Test-IamExchangePlan -User $user) `
    -WillRemoveLicence (-not $KeepLicense -and $directLicences -gt 0)
$manual += $mbx.Manual
$keepLicence = $KeepLicense -or $mbx.ForceKeepLicence

$plan = @('disable account', 'revoke sessions')
if ($RemoveAuthMethods) {
    if ($authMethods.Count) { $plan += "remove $($authMethods.Count) authentication method(s): $($authMethods.Type -join ', ')" }
    else { $plan += 'no authentication methods to remove' }
}
$plan += $mbx.Lines
if ($mbx.Convert -and $AutoReplyMessage) { $plan += 'set automatic reply' }
if ($mbx.Convert -and $HideFromGal) { $plan += 'hide from address list' }
if ($removeGroups.Count) { $plan += "remove from $($removeGroups.Count) assigned group(s): $($removeGroups.Name -join ', ')" }
if ($KeepLicense) { $plan += 'keep licences (-KeepLicense)' }
elseif (-not $mbx.ForceKeepLicence -and $directLicences) { $plan += "remove $directLicences direct licence(s)" }
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

# 3. Authentication methods (optional). Carry on past a failure and report it.
$authRemoved = @()
if ($RemoveAuthMethods -and $authMethods.Count) {
    try {
        $r = Remove-IamUserAuthMethod -UserId $user.Id -Confirm:$false
        $authRemoved = @($r.Removed)
        $manual += @($r.Failed | ForEach-Object { "Authentication method (remove by hand): $_" })
    }
    catch {
        $manual += 'Authentication methods not removed'
        Write-IamLog -Level ERROR -Message "Authentication method removal failed for ${UserPrincipalName}: $($_.Exception.Message)"
    }
}

# 4. Mailbox (optional), before the licence goes. If it fails, keep the licence.
$mailboxOutcome = ''
if ($mbx.Convert) {
    try {
        Convert-IamMailboxToShared -Identity $UserPrincipalName -DelegateTo $mbx.Delegate -AutoReplyMessage $AutoReplyMessage `
            -HideFromGal:$HideFromGal -Confirm:$false
        $mailboxOutcome = 'Shared' + $(if ($mbx.Delegate) { "; Full Access: $($mbx.Delegate)" } else { '' })
    }
    catch {
        $keepLicence = $true
        $mailboxOutcome = 'Conversion failed, licence kept'
        $manual += 'Mailbox conversion failed: licence kept. Convert by hand, then remove the licence'
        Write-IamLog -Level ERROR -Message "Mailbox conversion failed for ${UserPrincipalName}: $($_.Exception.Message)"
    }
}

# 5. Assigned groups. Carry on past a failure and report it.
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

# 6. Licences.
if (-not $keepLicence) {
    try { Remove-IamUserLicense -UserId $user.Id -Confirm:$false }
    catch {
        $manual += 'Licence removal failed'
        Write-IamLog -Level ERROR -Message "Licence removal failed for ${UserPrincipalName}: $($_.Exception.Message)"
    }
}

# 7. Department, last: the dynamic groups drop the user within minutes.
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
    LicencesKept   = [bool]$keepLicence
    AuthMethods    = ($authRemoved -join '; ')
    Mailbox        = $mailboxOutcome
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