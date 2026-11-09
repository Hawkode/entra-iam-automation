<#
.SYNOPSIS
    Finds enabled users with no manager, or whose manager is disabled.

.DESCRIPTION
    The leavers hand a shared mailbox to the leaver's manager by default, and access
    reviews usually go to managers too. Both break when the Manager attribute is empty
    or points at someone who has left. This report shows where.

    For users synced from AD the manager comes from the AD manager attribute; fix it
    there, not in Entra ID.

    Break-glass accounts from config are marked as expected. Guests are excluded
    unless -IncludeGuests is used.

    Read-only. Graph scopes (delegated): User.Read.All

.PARAMETER IncludeGuests
    Include guest users.

.EXAMPLE
    .\Reports\Get-ManagerCoverage.ps1
#>
[CmdletBinding()]
param([switch]$IncludeGuests)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig
$breakGlass = @($cfg.BreakGlassUpns)
Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.Read.All'

$users = @()
$uri = 'v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,department,onPremisesSyncEnabled' +
'&$expand=manager($select=id,userPrincipalName,accountEnabled)&$top=999'
while ($uri) {
    $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $users += @($page.value)
    $uri = $page.'@odata.nextLink'
}

$report = foreach ($u in $users) {
    if (-not $u.accountEnabled) { continue }
    if (-not $IncludeGuests -and $u.userType -eq 'Guest') { continue }
    $m = $u.manager

    $finding = ''
    if ($breakGlass -contains $u.userPrincipalName) { $finding = 'Expected (break-glass)' }
    elseif (-not $m) { $finding = 'No manager' }
    elseif ($m.accountEnabled -eq $false) { $finding = 'Manager disabled' }

    [pscustomobject]@{
        DisplayName = $u.displayName
        Upn         = $u.userPrincipalName
        Department  = $u.department
        Source      = if ($u.onPremisesSyncEnabled) { 'AD' } else { 'Cloud' }
        Manager     = if ($m) { $m.userPrincipalName } else { '' }
        Finding     = $finding
    }
}

$report = @($report | Sort-Object -Property @{ Expression = { $_.Finding -in 'No manager', 'Manager disabled' }; Descending = $true }, DisplayName)

$csv = Get-IamOutputPath -Prefix 'ManagerCoverage'
$report | Export-Csv -Path $csv -NoTypeInformation

$missing = @($report | Where-Object { $_.Finding -eq 'No manager' }).Count
$disabled = @($report | Where-Object { $_.Finding -eq 'Manager disabled' }).Count
$total = @($report | Where-Object { $_.Finding -notlike 'Expected*' }).Count
$pct = if ($total) { [math]::Round(100 * ($total - $missing - $disabled) / $total) } else { 0 }
Write-IamLog -Message "Manager coverage: $pct% of $total enabled users (break-glass excluded). No manager: $missing. Manager disabled: $disabled. CSV: $csv"

$report | Format-Table DisplayName, Department, Source, Manager, Finding -AutoSize
