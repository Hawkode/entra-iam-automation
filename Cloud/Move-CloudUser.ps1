<#
.SYNOPSIS
    Moves a cloud-only user to a new department and lists access that does not move with them.

.DESCRIPTION
    Changes the department (and optionally the job title). The Dept- dynamic groups then
    add the user to the new department group and remove them from the old one, usually
    within minutes.

    Dynamic groups only cover access tied to department. Assigned group memberships and
    active directory roles stay with the user after a move, which is how privilege creep
    builds up. The script lists them for review and removes nothing: each one needs a
    decision from the new manager or the access owner.

    Manager: -Manager sets the new manager (must exist and be enabled). If the department
    changes without -Manager, the script warns that the old manager stays. The leavers use
    the manager to hand over the mailbox, so a stale manager gets the wrong mailbox later.
    To change only the manager, pass the user's current department.

    Cloud-only: stops if the user is synced from AD. Use Hybrid\Move-HybridUser.ps1 for those.

    Graph scopes (delegated): User.ReadWrite.All, GroupMember.Read.All, RoleManagement.Read.Directory
    Entra role for the signed-in admin: User Administrator

.EXAMPLE
    .\Cloud\Move-CloudUser.ps1 -UserPrincipalName sofia.novak@contoso.onmicrosoft.com -Department HR -WhatIf
.EXAMPLE
    .\Cloud\Move-CloudUser.ps1 -UserPrincipalName sofia.novak@contoso.onmicrosoft.com -Department HR -JobTitle 'HR Assistant' -Manager sofia.rossi@contoso.onmicrosoft.com
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$Department,
    [string]$JobTitle,
    [string]$Manager
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig -Require AllowedDepartments
$allowed = @($cfg.AllowedDepartments)
$newDept = $allowed | Where-Object { $_ -eq $Department.Trim() } | Select-Object -First 1
if (-not $newDept) { throw "Department '$Department' is not allowed. Allowed: $($allowed -join ', ')" }

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.ReadWrite.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory'

$null = Assert-IamSyncState -UserPrincipalName $UserPrincipalName -Expected Cloud
$user = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName, UserPrincipalName, Department, JobTitle, AccountEnabled

if (-not $user.AccountEnabled) { throw "$UserPrincipalName is disabled. Movers apply to active users only." }

# Manager: validate the new one before any change, read the current one for the plan.
$newManager = $null
if ($Manager) {
    $mUpn = $Manager.Trim()
    if ($mUpn -eq $user.UserPrincipalName) { throw 'A user cannot be their own manager. Nothing changed.' }
    try { $newManager = Get-MgUser -UserId $mUpn -Property Id, UserPrincipalName, AccountEnabled -ErrorAction Stop } catch { $newManager = $null }
    if (-not $newManager) { throw "Manager $mUpn not found in Entra ID. Nothing changed." }
    if (-not $newManager.AccountEnabled) { throw "Manager $mUpn is disabled. Nothing changed." }
}
$oldManager = Get-IamCloudManager -UserId $user.Id
$oldManagerUpn = if ($oldManager) { $oldManager.UserPrincipalName } else { '(none)' }
$managerChange = $newManager -and (-not $oldManager -or $oldManager.Id -ne $newManager.Id)

$oldDept = $user.Department
$newTitle = if ($JobTitle) { $JobTitle.Trim() } else { $null }
$deptChange = $oldDept -cne $newDept
$titleChange = $newTitle -and $newTitle -cne $user.JobTitle
if (-not $deptChange -and -not $titleChange -and -not $managerChange) {
    Write-IamLog -Message "$UserPrincipalName is already in $newDept with that title and manager. Nothing to change."
    return
}

if ($deptChange -and -not $Manager) {
    if (-not $oldManager) {
        Write-IamLog -Level WARN -Message "$UserPrincipalName has no manager. Add -Manager so the leaver can hand over the mailbox later."
    }
    elseif (-not $oldManager.AccountEnabled) {
        Write-IamLog -Level WARN -Message "Manager $oldManagerUpn is disabled. Add -Manager with the new manager."
    }
    else {
        Write-IamLog -Level WARN -Message "Department changes but manager stays $oldManagerUpn. Add -Manager if that is wrong."
    }
}

# Access that does not follow the department: assigned groups and active directory roles.
# Read-only, so it runs and writes its CSV under -WhatIf too.
$review = @()
foreach ($m in (Get-MgUserMemberOf -UserId $user.Id -All)) {
    $props = $m.AdditionalProperties
    if ($props.'@odata.type' -ne '#microsoft.graph.group') { continue }
    if (@($props.groupTypes) -contains 'DynamicMembership') { continue }
    $review += [pscustomobject]@{ Type = 'Assigned group'; Name = $props.displayName; Id = $m.Id }
}
foreach ($a in (Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -All)) {
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
    $review += [pscustomobject]@{ Type = 'Directory role (active)'; Name = $role.DisplayName; Id = $a.Id }
}

$body = @{}
$parts = @()
if ($deptChange) { $body.Department = $newDept; $parts += "department '$oldDept' -> '$newDept'" }
if ($titleChange) { $body.JobTitle = $newTitle; $parts += "job title '$($user.JobTitle)' -> '$newTitle'" }
if ($managerChange) { $parts += "manager $oldManagerUpn -> $($newManager.UserPrincipalName)" }
$what = $parts -join ', '

if ($PSCmdlet.ShouldProcess($UserPrincipalName, $what)) {
    if ($body.Count -gt 0) { Update-MgUser -UserId $user.Id -BodyParameter $body }
    if ($managerChange) {
        $ref = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($newManager.Id)" } | ConvertTo-Json
        Invoke-MgGraphRequest -Method PUT -Uri "v1.0/users/$($user.Id)/manager/`$ref" -Body $ref -ContentType 'application/json'
    }
    $msg = "Moved $UserPrincipalName. $what."
    if ($deptChange) { $msg += ' Dynamic groups update within minutes.' }
    Write-IamLog -Message $msg
}

if ($review.Count -gt 0) {
    $summary = ($review | ForEach-Object { "$($_.Type): $($_.Name)" }) -join '; '
    Write-IamLog -Level WARN -Message "$($review.Count) item(s) do not follow the move for ${UserPrincipalName}. Review with the new manager: $summary"

    $csv = Get-IamOutputPath -Prefix 'MoverReview'
    $review | Select-Object @{ n = 'Upn'; e = { $UserPrincipalName } }, @{ n = 'From'; e = { $oldDept } },
    @{ n = 'To'; e = { $newDept } }, Type, Name, Id | Export-Csv -Path $csv -NoTypeInformation -WhatIf:$false
    Write-IamLog -Message "Review list: $csv"

    $review | Format-Table Type, Name -AutoSize
}
else {
    Write-IamLog -Message "No assigned groups or active roles on $UserPrincipalName. All group access follows the department."
}