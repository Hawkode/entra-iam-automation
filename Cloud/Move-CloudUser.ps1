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

    Cloud-only: stops if the user is synced from AD. Use Hybrid\Move-HybridUser.ps1 for those.

    Graph scopes (delegated): User.ReadWrite.All, GroupMember.Read.All, RoleManagement.Read.Directory
    Entra role for the signed-in admin: User Administrator

.EXAMPLE
    .\Cloud\Move-CloudUser.ps1 -UserPrincipalName sofia.novak@contoso.onmicrosoft.com -Department HR -WhatIf
.EXAMPLE
    .\Cloud\Move-CloudUser.ps1 -UserPrincipalName sofia.novak@contoso.onmicrosoft.com -Department HR -JobTitle 'HR Assistant'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [Parameter(Mandatory)][string]$Department,
    [string]$JobTitle
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

$oldDept = $user.Department
$newTitle = if ($JobTitle) { $JobTitle.Trim() } else { $null }
if ($oldDept -ceq $newDept -and (-not $newTitle -or $newTitle -ceq $user.JobTitle)) {
    Write-IamLog -Message "$UserPrincipalName is already in $newDept. Nothing to change."
    return
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

$body = @{ Department = $newDept }
$what = "Department '$oldDept' -> '$newDept'"
if ($newTitle) {
    $body.JobTitle = $newTitle
    $what += ", job title '$($user.JobTitle)' -> '$newTitle'"
}

if ($PSCmdlet.ShouldProcess($UserPrincipalName, $what)) {
    Update-MgUser -UserId $user.Id -BodyParameter $body
    Write-IamLog -Message "Moved $UserPrincipalName. $what. Dynamic groups update within minutes."
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