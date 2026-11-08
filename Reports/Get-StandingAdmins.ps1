<#
.SYNOPSIS
    Lists Entra ID directory role holders and flags standing privileged access.

.DESCRIPTION
    With PIM (Entra ID P2), each assignment is classed as Standing (permanent),
    Time-bound, Activated (JIT) or Eligible. Without P2 it falls back to active
    assignments only. Break-glass accounts from config are marked as expected.

    Read-only. Graph scopes (delegated): RoleManagement.Read.Directory, Directory.Read.All

.PARAMETER PrivilegedOnly
    Show privileged roles only.

.EXAMPLE
    .\Reports\Get-StandingAdmins.ps1
.EXAMPLE
    .\Reports\Get-StandingAdmins.ps1 -PrivilegedOnly
#>
[CmdletBinding()]
param([switch]$PrivilegedOnly)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig -Require BreakGlassUpns
Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'RoleManagement.Read.Directory', 'Directory.Read.All'

$breakGlass = @($cfg.BreakGlassUpns)
$privilegedRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Application Administrator', 'Cloud Application Administrator',
    'Conditional Access Administrator', 'Hybrid Identity Administrator', 'Authentication Administrator',
    'User Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator',
    'Helpdesk Administrator', 'Groups Administrator'
)

$roleNames = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All -Property Id, DisplayName |
    ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }

$principalCache = @{}
function Get-PrincipalInfo {
    param([string]$Id)
    if (-not $principalCache.ContainsKey($Id)) {
        try {
            $p = (Get-MgDirectoryObject -DirectoryObjectId $Id).AdditionalProperties
            $principalCache[$Id] = [pscustomobject]@{
                Name = $p.displayName
                Upn  = $p.userPrincipalName
                Type = $p.'@odata.type' -replace '#microsoft.graph.', ''
            }
        }
        catch {
            $principalCache[$Id] = [pscustomobject]@{ Name = "Unknown ($Id)"; Upn = $null; Type = 'unknown' }
        }
    }
    $principalCache[$Id]
}

$rows = [System.Collections.Generic.List[object]]::new()
function Add-RoleRow {
    param($PrincipalId, $RoleDefinitionId, $Scope, $Status, $EndsOn)
    $who = Get-PrincipalInfo -Id $PrincipalId
    $role = $roleNames[$RoleDefinitionId]
    $isPriv = $privilegedRoles -contains $role
    $finding = ''
    if ($who.Upn -and $breakGlass -contains $who.Upn) { $finding = 'Expected (break-glass)' }
    elseif ($isPriv -and $Status -in 'Standing', 'Active (no PIM data)') { $finding = 'Standing privileged access' }
    elseif ($isPriv -and $who.Type -eq 'group') { $finding = 'Check group members' }
    $rows.Add([pscustomobject]@{
            Principal  = $who.Name
            Upn        = $who.Upn
            Type       = $who.Type
            Role       = $role
            Privileged = $isPriv
            Status     = $Status
            EndsOn     = $EndsOn
            Scope      = $Scope
            Finding    = $finding
        })
}

$pimAvailable = $true
try {
    $active = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All
    $eligible = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All
}
catch {
    $pimAvailable = $false
    Write-IamLog -Level WARN -Message "PIM data unavailable (needs Entra ID P2). Falling back to active assignments. $($_.Exception.Message)"
}

if ($pimAvailable) {
    foreach ($a in $active) {
        $status = if ($a.AssignmentType -eq 'Activated') { 'Activated (JIT)' }
        elseif ($null -eq $a.EndDateTime) { 'Standing' }
        else { 'Time-bound' }
        Add-RoleRow -PrincipalId $a.PrincipalId -RoleDefinitionId $a.RoleDefinitionId -Scope $a.DirectoryScopeId -Status $status -EndsOn $a.EndDateTime
    }
    foreach ($e in $eligible) {
        Add-RoleRow -PrincipalId $e.PrincipalId -RoleDefinitionId $e.RoleDefinitionId -Scope $e.DirectoryScopeId -Status 'Eligible' -EndsOn $e.EndDateTime
    }
}
else {
    foreach ($a in Get-MgRoleManagementDirectoryRoleAssignment -All) {
        Add-RoleRow -PrincipalId $a.PrincipalId -RoleDefinitionId $a.RoleDefinitionId -Scope $a.DirectoryScopeId -Status 'Active (no PIM data)' -EndsOn $null
    }
}

$report = @($rows | Where-Object { -not $PrivilegedOnly -or $_.Privileged } |
        Sort-Object -Property @{ Expression = { $_.Finding -eq 'Standing privileged access' }; Descending = $true }, Role, Principal)

foreach ($f in $report | Where-Object Finding -EQ 'Standing privileged access') {
    Write-IamLog -Level WARN -Message "Standing privileged access: $($f.Principal) holds $($f.Role) permanently."
}

$csv = Get-IamOutputPath -Prefix 'StandingAdmins'
$report | Export-Csv -Path $csv -NoTypeInformation

$standing = @($report | Where-Object Finding -EQ 'Standing privileged access').Count
Write-IamLog -Message "Role assignments: $($report.Count) rows, $standing standing privileged. PIM data: $pimAvailable. CSV: $csv"

$report | Format-Table Principal, Type, Role, Status, Finding -AutoSize