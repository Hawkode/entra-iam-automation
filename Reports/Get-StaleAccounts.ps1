<#
.SYNOPSIS
    Finds enabled accounts with no recent sign-in (stale or orphaned accounts).

.DESCRIPTION
    Uses signInActivity, which needs Entra ID P1 or P2. Takes the latest of the
    interactive, non-interactive and successful sign-in timestamps. Accounts that
    never signed in are flagged once older than the threshold.

    Cloud sign-ins only by default: a user who only logs on to domain PCs looks
    stale. -IncludeOnPrem cross-checks AD lastLogonTimestamp for synced users
    (ActiveDirectory module, domain-joined machine). lastLogonTimestamp replicates
    with up to 14 days' lag, so keep StaleDays at 30 or more when using it.

    signInActivity itself can lag real sign-ins by a few hours.

    Read-only. Graph scopes (delegated): User.Read.All, AuditLog.Read.All

.PARAMETER StaleDays
    Days without sign-in before an account counts as stale. Default: StaleDays in config.

.PARAMETER IncludeOnPrem
    Cross-check AD lastLogonTimestamp for synced users.

.EXAMPLE
    .\Reports\Get-StaleAccounts.ps1
.EXAMPLE
    .\Reports\Get-StaleAccounts.ps1 -StaleDays 30 -IncludeOnPrem
#>
[CmdletBinding()]
param(
    [int]$StaleDays,
    [switch]$IncludeOnPrem
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig
if (-not $PSBoundParameters.ContainsKey('StaleDays')) { $StaleDays = $cfg.StaleDays }
$now = (Get-Date).ToUniversalTime()
$cutoff = $now.AddDays(-$StaleDays)
$breakGlass = @($cfg.BreakGlassUpns)

if ($IncludeOnPrem) { Import-Module ActiveDirectory }

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.Read.All', 'AuditLog.Read.All'

try {
    $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType, AccountEnabled,
    CreatedDateTime, OnPremisesSyncEnabled, SignInActivity
}
catch {
    if ($_.Exception.Message -match 'NonPremiumTenant|premium license') {
        throw 'signInActivity needs Entra ID P1 or P2 in this tenant. This report cannot run without it.'
    }
    throw
}

$report = foreach ($u in $users) {
    $s = $u.SignInActivity
    $cloudLast = @($s.LastSignInDateTime, $s.LastNonInteractiveSignInDateTime, $s.LastSuccessfulSignInDateTime) |
        Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

    $adLast = $null
    if ($IncludeOnPrem -and $u.OnPremisesSyncEnabled) {
        $ad = Get-ADUser -Filter "UserPrincipalName -eq '$($u.UserPrincipalName)'" -Properties LastLogonTimestamp
        if ($ad.LastLogonTimestamp) { $adLast = [datetime]::FromFileTimeUtc($ad.LastLogonTimestamp) }
    }

    $last = @($cloudLast, $adLast) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

    $finding = ''
    if ($breakGlass -contains $u.UserPrincipalName) { $finding = 'Expected (break-glass)' }
    elseif (-not $u.AccountEnabled) { $finding = '' }
    elseif (-not $last -and $u.CreatedDateTime -lt $cutoff) { $finding = 'Never signed in' }
    elseif ($last -and $last -lt $cutoff) { $finding = 'Stale' }

    [pscustomobject]@{
        DisplayName     = $u.DisplayName
        Upn             = $u.UserPrincipalName
        UserType        = $u.UserType
        Enabled         = $u.AccountEnabled
        Synced          = [bool]$u.OnPremisesSyncEnabled
        LastCloudSignIn = $cloudLast
        LastAdLogon     = $adLast
        DaysSince       = if ($last) { [math]::Floor(($now - $last).TotalDays) } else { $null }
        Finding         = $finding
    }
}

$report = @($report | Sort-Object -Property @{ Expression = { $_.Finding -in 'Stale', 'Never signed in' }; Descending = $true }, DisplayName)

$outDir = Join-Path -Path $PSScriptRoot -ChildPath '..\output'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$csv = Join-Path -Path $outDir -ChildPath ('StaleAccounts-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date))
$report | Export-Csv -Path $csv -NoTypeInformation

$stale = @($report | Where-Object { $_.Finding -in 'Stale', 'Never signed in' }).Count
Write-IamLog -Message "Stale accounts (threshold $StaleDays days): $stale of $($report.Count). On-prem check: $IncludeOnPrem. CSV: $csv"

$report | Format-Table DisplayName, UserType, Enabled, LastCloudSignIn, DaysSince, Finding -AutoSize