<#
.SYNOPSIS
    Finds groups with no working owner: no owner, only disabled owners, or fewer than -MinOwners.

.DESCRIPTION
    Access reviews, self-service requests and "who decides who gets in" all depend on a group
    owner who still works here. This report lists every cloud group with its owners and a finding:
      No owner               nobody owns it, or only apps do
      Only disabled owners   every human owner has left
      Single owner           one owner, so no cover when they are away (with -MinOwners 2)
    Groups synced from AD and distribution lists are labelled, not flagged: their owners live
    in AD (managedBy) or Exchange. Role-assignable groups are marked: those need owners most.
    Flagged groups also show their member count, so empty, ownerless groups stand out as
    clean-up.

    Read-only. Graph scopes (delegated): GroupMember.Read.All, User.Read.All. Entra ID Free.

.PARAMETER MinOwners
    Working owners each group should have. Default 2. Use 1 to flag only groups with none.

.PARAMETER All
    Also lists groups that are fine, and synced groups and distribution lists.

.EXAMPLE
    .\Reports\Get-GroupOwnerCoverage.ps1
.EXAMPLE
    .\Reports\Get-GroupOwnerCoverage.ps1 -MinOwners 1 -All
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 5)][int]$MinOwners = 2,
    [switch]$All
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig
Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'GroupMember.Read.All', 'User.Read.All'

$uri = 'v1.0/groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,isAssignableToRole' +
'&$expand=owners($select=id,displayName,userPrincipalName,accountEnabled)'
$groups = @(Invoke-IamGraphGetAll -Uri $uri)

$flaggedNames = 'No owner', 'Only disabled owners', 'Single owner'
$rows = foreach ($g in $groups) { Get-IamGroupOwnerFinding -Group $g -MinOwners $MinOwners }
$isFlagged = { param($Row) $Row.Finding -in $flaggedNames -or $Row.Finding -like 'Only * owners' }

$report = foreach ($r in $rows) {
    $flag = & $isFlagged $r
    if (-not $flag -and -not $All) { continue }
    $members = $null
    if ($flag) {
        try {
            $members = [int](Invoke-MgGraphRequest -Method GET -Uri "v1.0/groups/$($r.Id)/members/`$count" -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop)
        }
        catch { Write-IamLog -Level WARN -Message "Member count of $($r.DisplayName): $($_.Exception.Message)" }
    }
    $r | Select-Object DisplayName, Type, Membership, Source, RoleAssignable, @{ n = 'Members'; e = { $members } }, Owners, EnabledOwners, Finding, Action, Id
}
$order = @{ 'No owner' = 0; 'Only disabled owners' = 1; 'Single owner' = 3; '' = 5; 'Synced from AD' = 6; 'Distribution list' = 7 }
$report = @($report | Sort-Object -Property @{ Expression = { -not $_.RoleAssignable } },
    @{ Expression = { if ($order.ContainsKey($_.Finding)) { $order[$_.Finding] } else { 2 } } }, DisplayName)

$csv = Get-IamOutputPath -Prefix 'GroupOwnerCoverage'
$report | Export-Csv -Path $csv

$flagged = @($rows | Where-Object { & $isFlagged $_ })
$none = @($flagged | Where-Object Finding -EQ 'No owner').Count
$gone = @($flagged | Where-Object Finding -EQ 'Only disabled owners').Count
$few = $flagged.Count - $none - $gone
$role = @($flagged | Where-Object RoleAssignable).Count
Write-IamLog -Message "Group owners: $($flagged.Count) of $($groups.Count) group(s) need attention. No owner: $none. Only disabled owners: $gone. Fewer than $MinOwners owners: $few. Role-assignable among them: $role. CSV: $csv"

$report | Format-Table DisplayName, Type, RoleAssignable, Members, EnabledOwners, Finding -AutoSize
