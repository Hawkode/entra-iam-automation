<#
.SYNOPSIS
    Moves a synced user to a new department in AD and lists access that does not move with them.

.DESCRIPTION
    For hybrid tenants where AD DS is the source of authority and each department has its own OU.

      1. Changes department (and optionally job title) in AD.
      2. Moves the account to the new department's OU (DepartmentOUs).
      3. Runs an Entra Connect delta sync. The department syncs to Entra ID and the
         Dept- dynamic groups re-scope cloud access.
      4. Checks the user still exists in Entra ID. If the new OU is outside the sync
         scope, the sync deletes the cloud account: the script reports it so you can
         restore it from Deleted users.

    Manager: -Manager sets the AD Manager attribute (must exist and be enabled in AD); it
    syncs to Entra ID with the department. If the department changes without -Manager, the
    script warns that the old manager stays. The leavers use the manager to hand over the
    mailbox. To change only the manager, pass the user's current department.

    Review list (removes nothing): on-prem AD group memberships, cloud-only assigned
    groups and active directory roles. In a hybrid tenant the AD groups (file shares,
    VPN, apps) are usually the bigger leftover risk, and no dynamic group touches them.
    The review is read-only, so it runs and writes its CSV under -WhatIf too.

    Graph scopes (delegated, read-only): User.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory
    AD rights: write department, title and manager, move users between the DepartmentOUs.
    Entra Connect server: WinRM and ADSyncOperators.

.EXAMPLE
    .\Hybrid\Move-HybridUser.ps1 -UserPrincipalName sofia.novak@contoso.com -Department HR -WhatIf
.EXAMPLE
    .\Hybrid\Move-HybridUser.ps1 -UserPrincipalName sofia.novak@contoso.com -Department HR -JobTitle 'HR Assistant' -Manager sofia.rossi@contoso.com
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$Department,
    [string]$JobTitle,
    [string]$Manager,
    [int]$SyncTimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig -Require DepartmentOUs, EntraConnectServer
$deptOUs = $cfg.DepartmentOUs
$protected = if ($cfg.ProtectedAdGroups) { @($cfg.ProtectedAdGroups) } else { @('Domain Users') }

$newDept = $deptOUs.Keys | Where-Object { $_ -eq $Department.Trim() } | Select-Object -First 1
if (-not $newDept) { throw "Department '$Department' is not in DepartmentOUs. Allowed: $(($deptOUs.Keys | Sort-Object) -join ', ')" }
$newOU = $deptOUs[$newDept]

Import-IamAdModule
$ad = Get-ADUser -Filter "UserPrincipalName -eq '$UserPrincipalName'" -Properties Department, Title, MemberOf, Enabled, Manager
if (-not $ad) { throw "$UserPrincipalName not found in AD." }
if (-not $ad.Enabled) { throw "$UserPrincipalName is disabled in AD. Movers apply to active users only." }
try { $null = Get-ADOrganizationalUnit -Identity $newOU }
catch { throw "OU for $newDept not found: $newOU" }

# Manager: validate the new one before any change, read the current one for the plan.
$newManager = $null
if ($Manager) {
    $mUpn = $Manager.Trim()
    if ($mUpn -eq $UserPrincipalName) { throw 'A user cannot be their own manager. Nothing changed.' }
    $newManager = Get-ADUser -Filter "UserPrincipalName -eq '$mUpn'" -Properties Enabled, UserPrincipalName
    if (-not $newManager) { throw "Manager $mUpn not found in AD. Nothing changed." }
    if (-not $newManager.Enabled) { throw "Manager $mUpn is disabled in AD. Nothing changed." }
}
$oldManager = $null
if ($ad.Manager) {
    try { $oldManager = Get-ADUser -Identity $ad.Manager -Properties Enabled, UserPrincipalName } catch { $oldManager = $null }
}
$oldManagerUpn = if ($oldManager) { $oldManager.UserPrincipalName } else { '(none)' }
$managerChange = $newManager -and $ad.Manager -ne $newManager.DistinguishedName

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory'
$cloud = Assert-IamSyncState -UserPrincipalName $UserPrincipalName -Expected Hybrid

$oldDept = $ad.Department
$oldOU = ($ad.DistinguishedName -split '(?<!\\),', 2)[1]
$newTitle = if ($JobTitle) { $JobTitle.Trim() } else { $null }
$moveOU = $oldOU -ne $newOU
$deptChange = $oldDept -cne $newDept
$titleChange = $newTitle -and $newTitle -cne $ad.Title
if (-not $deptChange -and -not $moveOU -and -not $titleChange -and -not $managerChange) {
    Write-IamLog -Message "$UserPrincipalName is already in $newDept ($newOU) with that title and manager. Nothing to change."
    return
}

if ($deptChange -and -not $Manager) {
    if (-not $oldManager) {
        Write-IamLog -Level WARN -Message "$UserPrincipalName has no manager in AD. Add -Manager so the leaver can hand over the mailbox later."
    }
    elseif (-not $oldManager.Enabled) {
        Write-IamLog -Level WARN -Message "Manager $oldManagerUpn is disabled in AD. Add -Manager with the new manager."
    }
    else {
        Write-IamLog -Level WARN -Message "Department changes but manager stays $oldManagerUpn. Add -Manager if that is wrong."
    }
}

# Access that does not follow the department.
$review = @()
foreach ($dn in @($ad.MemberOf)) {
    $g = Get-ADGroup -Identity $dn
    if ($protected -contains $g.Name) { continue }
    $review += [pscustomobject]@{ Type = 'AD group'; Name = $g.Name; Id = $dn }
}
foreach ($m in (Get-MgUserMemberOf -UserId $cloud.Id -All)) {
    $props = $m.AdditionalProperties
    if ($props.'@odata.type' -ne '#microsoft.graph.group') { continue }
    if (@($props.groupTypes) -contains 'DynamicMembership') { continue }
    if ($props.onPremisesSyncEnabled -eq $true) { continue }   # synced AD groups are listed above
    $review += [pscustomobject]@{ Type = 'Cloud assigned group'; Name = $props.displayName; Id = $m.Id }
}
foreach ($a in (Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($cloud.Id)'" -All)) {
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
    $review += [pscustomobject]@{ Type = 'Directory role (active)'; Name = $role.DisplayName; Id = $a.Id }
}

$parts = @()
if ($deptChange) { $parts += "department '$oldDept' -> '$newDept'" }
if ($titleChange) { $parts += "job title '$($ad.Title)' -> '$newTitle'" }
if ($managerChange) { $parts += "manager $oldManagerUpn -> $($newManager.UserPrincipalName)" }
if ($moveOU) { $parts += "move to $newOU" }
$what = ($parts -join ', ') + ', delta sync'

if ($PSCmdlet.ShouldProcess($UserPrincipalName, $what)) {
    $set = @{ Identity = $ad.ObjectGUID }
    if ($deptChange) { $set.Department = $newDept }
    if ($titleChange) { $set.Title = $newTitle }
    if ($managerChange) { $set.Manager = $newManager.DistinguishedName }
    if ($set.Count -gt 1) { Set-ADUser @set }
    if ($moveOU) { Move-ADObject -Identity $ad.ObjectGUID -TargetPath $newOU }
    Write-IamLog -Message "Moved $UserPrincipalName in AD. $what"

    $null = Invoke-IamDeltaSync -Server $cfg.EntraConnectServer -TimeoutSeconds $SyncTimeoutSeconds
    $after = Wait-IamCloudUser -UserId $cloud.Id -TimeoutSeconds 60
    if ($after -eq 'Deleted') {
        Write-IamLog -Level ERROR -Message ("$UserPrincipalName no longer exists in Entra ID: $newOU is outside the sync scope. " +
            'Move the account back to a synced OU and run a delta sync, or restore it from Deleted users.')
    }
    else {
        Write-IamLog -Message "$UserPrincipalName synced. Dynamic groups update within minutes."
    }
}

if ($review.Count -gt 0) {
    $summary = ($review | ForEach-Object { "$($_.Type): $($_.Name)" }) -join '; '
    Write-IamLog -Level WARN -Message "$($review.Count) item(s) do not follow the move for ${UserPrincipalName}. Review with the new manager: $summary"
    $csv = Get-IamOutputPath -Prefix 'HybridMoverReview'
    $review | Select-Object @{ n = 'Upn'; e = { $UserPrincipalName } }, @{ n = 'From'; e = { $oldDept } },
    @{ n = 'To'; e = { $newDept } }, Type, Name, Id | Export-Csv -Path $csv -NoTypeInformation -WhatIf:$false
    Write-IamLog -Message "Review list: $csv"
    $review | Format-Table Type, Name -AutoSize
}
else {
    Write-IamLog -Message "No AD groups, cloud assigned groups or active roles on $UserPrincipalName."
}
