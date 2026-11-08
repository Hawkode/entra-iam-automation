<#
.SYNOPSIS
    Reports Microsoft Graph permissions granted to apps, ranked by risk.

.DESCRIPTION
    Lists application permissions and delegated grants on Microsoft Graph,
    tags each with a risk tier, and for Critical/High rows checks whether the
    app has a credential (secret or certificate) that could be stolen.

    Tenant-wide delegated grants (consented for all users) are always shown,
    whatever their tier, because the grant itself is a finding. The standard
    sign-in scopes (openid, profile, email, offline_access, User.Read) are the
    only exception: almost every app that uses Entra sign-in has them.

    Read-only. Graph scopes (delegated): Application.Read.All, DelegatedPermissionGrant.Read.All

.PARAMETER MinimumRisk
    Lowest tier to include. Default: Medium.

.EXAMPLE
    .\Reports\Get-RiskyAppPermissions.ps1
.EXAMPLE
    .\Reports\Get-RiskyAppPermissions.ps1 -MinimumRisk Critical
#>
[CmdletBinding()]
param(
    [ValidateSet('Low', 'Medium', 'High', 'Critical')]
    [string]$MinimumRisk = 'Medium'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig
Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'Application.Read.All', 'DelegatedPermissionGrant.Read.All'

# Critical = direct path to Global Admin or tenant takeover.
$tiers = @{
    Critical = @('RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
        'Directory.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess')
    High     = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send',
        'Files.ReadWrite.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All')
    Medium   = @('Directory.Read.All', 'User.Read.All', 'Group.Read.All', 'Mail.Read', 'Files.Read.All',
        'Sites.Read.All', 'AuditLog.Read.All')
}
$rank = @{ Low = 0; Medium = 1; High = 2; Critical = 3 }
$signInScopes = @('openid', 'profile', 'email', 'offline_access', 'User.Read')

function Get-PermissionRisk {
    param([string]$Permission)
    foreach ($t in 'Critical', 'High', 'Medium') { if ($tiers[$t] -contains $Permission) { return $t } }
    'Low'
}

$spCache = @{}
function Get-CachedServicePrincipal {
    param([string]$Id)
    if (-not $spCache.ContainsKey($Id)) {
        $spCache[$Id] = Get-MgServicePrincipal -ServicePrincipalId $Id `
            -Property Id, AppId, DisplayName, AppOwnerOrganizationId, PasswordCredentials, KeyCredentials
    }
    $spCache[$Id]
}

function Test-HasCredential {
    param($ServicePrincipal)
    if ($ServicePrincipal.PasswordCredentials.Count -or $ServicePrincipal.KeyCredentials.Count) { return $true }
    # Apps registered in this tenant keep their credentials on the application object.
    $app = Get-MgApplication -Filter "appId eq '$($ServicePrincipal.AppId)'" -Property PasswordCredentials, KeyCredentials
    [bool]($app -and ($app.PasswordCredentials.Count -or $app.KeyCredentials.Count))
}

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$roleNames = @{}
foreach ($r in $graphSp.AppRoles) { $roleNames[[string]$r.Id] = $r.Value }

$results = [System.Collections.Generic.List[object]]::new()

# Application permissions: Graph app roles assigned to service principals
$appGrants = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graphSp.Id -All |
    Where-Object { $_.PrincipalType -eq 'ServicePrincipal' }
foreach ($g in $appGrants) {
    $sp = Get-CachedServicePrincipal -Id $g.PrincipalId
    $perm = $roleNames[[string]$g.AppRoleId]
    $results.Add([pscustomobject]@{
            App           = $sp.DisplayName
            Type          = 'Application'
            Permission    = $perm
            Risk          = Get-PermissionRisk -Permission $perm
            HasCredential = $null
            ThisTenantApp = [string]$sp.AppOwnerOrganizationId -eq $cfg.TenantId
            SpId          = $sp.Id
        })
}

# Delegated permissions: AllPrincipals = consented for every user in the tenant
$delegated = Get-MgOauth2PermissionGrant -All -Filter "resourceId eq '$($graphSp.Id)'"
foreach ($d in $delegated) {
    $sp = Get-CachedServicePrincipal -Id $d.ClientId
    $type = if ($d.ConsentType -eq 'AllPrincipals') { 'Delegated (all users)' } else { 'Delegated (one user)' }
    foreach ($perm in ($d.Scope -split ' ' | Where-Object { $_ })) {
        $results.Add([pscustomobject]@{
                App           = $sp.DisplayName
                Type          = $type
                Permission    = $perm
                Risk          = Get-PermissionRisk -Permission $perm
                HasCredential = $null
                ThisTenantApp = [string]$sp.AppOwnerOrganizationId -eq $cfg.TenantId
                SpId          = $sp.Id
            })
    }
}

$report = @($results | Where-Object {
        $rank[$_.Risk] -ge $rank[$MinimumRisk] -or
        ($_.Type -eq 'Delegated (all users)' -and $signInScopes -notcontains $_.Permission)
    } |
        Sort-Object -Property @{ Expression = { $rank[$_.Risk] }; Descending = $true }, App, Permission)

foreach ($row in $report | Where-Object { $_.Risk -in 'Critical', 'High' }) {
    $row.HasCredential = Test-HasCredential -ServicePrincipal (Get-CachedServicePrincipal -Id $row.SpId)
    if ($row.Risk -eq 'Critical' -and $row.HasCredential) {
        Write-IamLog -Level WARN -Message "$($row.App) holds $($row.Permission) AND has a credential. Review now."
    }
}

$tenantWide = @($report | Where-Object { $_.Type -eq 'Delegated (all users)' -and $signInScopes -notcontains $_.Permission })
foreach ($app in ($tenantWide | Group-Object -Property App)) {
    Write-IamLog -Level WARN -Message "$($app.Name) has tenant-wide consent (all users) for: $($app.Group.Permission -join ', '). Check it was approved."
}

$csv = Get-IamOutputPath -Prefix 'RiskyAppPermissions'
$report | Export-Csv -Path $csv -NoTypeInformation

$crit = @($report | Where-Object Risk -EQ 'Critical').Count
$high = @($report | Where-Object Risk -EQ 'High').Count
Write-IamLog -Message "Risky app permissions: $($report.Count) rows (Critical $crit, High $high). CSV: $csv"

$report | Format-Table App, Type, Permission, Risk, HasCredential, ThisTenantApp -AutoSize