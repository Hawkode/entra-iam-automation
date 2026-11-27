<#
.SYNOPSIS
    Finds licences on disabled accounts and on enabled accounts nobody signs in to.

.DESCRIPTION
    Lists every licensed user with the licences, how they are assigned (direct or group),
    the last sign-in, and a finding:
      Disabled         the account is disabled but still holds a licence
      Never signed in  enabled, created before the threshold, never signed in
      Inactive         enabled, no sign-in for InactiveDays or more
    Then a summary per licence: how many look unused, and how many are free.

    A disabled account can keep a licence on purpose: a shared mailbox over 50 GB, on
    litigation hold or with an archive still needs one. The leavers keep it automatically
    in those cases. Check before removing.

    Sign-in data (signInActivity) needs Entra ID P1 or P2, and a role that can read it: Reports
    Reader, Global Reader or Security Reader (User Administrator cannot). Without either the
    report still runs, flags disabled accounts only, and says why.
    Cloud sign-ins only: a user who only logs on to domain PCs can look inactive. Cross-check
    with Get-StaleAccounts -IncludeOnPrem before acting on a synced user.

    Read-only. Graph scopes (delegated): User.Read.All, AuditLog.Read.All, LicenseAssignment.Read.All

.PARAMETER InactiveDays
    Days without sign-in before a licensed account counts as inactive. Default: StaleDays in config.

.EXAMPLE
    .\Reports\Get-UnusedLicences.ps1
.EXAMPLE
    .\Reports\Get-UnusedLicences.ps1 -InactiveDays 60
#>
[CmdletBinding()]
param([int]$InactiveDays)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$required = @('BreakGlassUpns')
if (-not $PSBoundParameters.ContainsKey('InactiveDays')) { $required += 'StaleDays' }
$cfg = Import-IamConfig -Require $required
if (-not $PSBoundParameters.ContainsKey('InactiveDays')) { $InactiveDays = $cfg.StaleDays }
if ($InactiveDays -lt 1) { throw 'InactiveDays must be 1 or more.' }
$now = (Get-Date).ToUniversalTime()
$cutoff = $now.AddDays(-$InactiveDays)

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.Read.All', 'AuditLog.Read.All', 'LicenseAssignment.Read.All'

$skus = @(Get-MgSubscribedSku -All)
$skuName = @{}
foreach ($k in $skus) { $skuName["$($k.SkuId)"] = $k.SkuPartNumber }

$props = 'Id', 'DisplayName', 'UserPrincipalName', 'AccountEnabled', 'CreatedDateTime', 'OnPremisesSyncEnabled',
'AssignedLicenses', 'LicenseAssignmentStates'
# -ErrorAction Stop: Get-MgUser -All reports a refused page as a non-terminating error, and the
# report would carry on with no users.
$noSignIn = $false
try {
    $users = Get-MgUser -All -Property ($props + 'SignInActivity') -ErrorAction Stop
}
catch {
    $why = switch -Regex ($_.Exception.Message) {
        'NonPremiumTenant|premium license' { 'no Entra ID P1 or P2 in this tenant' }
        'UnsupportedUserRole|not in the allowed roles' { 'your role cannot read sign-in data (needs Reports Reader, Global Reader or Security Reader)' }
        default { $null }
    }
    if (-not $why) { throw }
    Write-IamLog -Level WARN -Message "No sign-in data: $why. Only disabled accounts are flagged."
    $noSignIn = $true
    $users = Get-MgUser -All -Property $props -ErrorAction Stop
}

$licensed = @($users | Where-Object { @($_.AssignedLicenses).Count -gt 0 })
$report = foreach ($u in $licensed) {
    Get-IamLicenceFinding -User $u -SkuName $skuName -Cutoff $cutoff -Now $now -BreakGlass @($cfg.BreakGlassUpns) -NoSignInData:$noSignIn
}
$flaggedNames = 'Disabled', 'Never signed in', 'Inactive'
$report = @($report | Sort-Object -Property @{ Expression = { $_.Finding -in $flaggedNames }; Descending = $true }, Finding, DisplayName)

$csv = Get-IamOutputPath -Prefix 'UnusedLicences'
$report | Export-Csv -Path $csv

# Per licence: how many look unused, and how many are free to assign.
$flagged = @($report | Where-Object { $_.Finding -in $flaggedNames })
$summary = foreach ($k in ($skus | Sort-Object SkuPartNumber)) {
    $name = $k.SkuPartNumber
    $onFlagged = @($flagged | Where-Object { ($_.Licences -split '; ') -contains $name })
    [pscustomobject]@{
        Licence       = $name
        Assigned      = $k.ConsumedUnits
        Bought        = $k.PrepaidUnits.Enabled
        Free          = $k.PrepaidUnits.Enabled - $k.ConsumedUnits
        OnDisabled    = @($onFlagged | Where-Object { $_.Finding -eq 'Disabled' }).Count
        OnInactive    = @($onFlagged | Where-Object { $_.Finding -in 'Never signed in', 'Inactive' }).Count
    }
}

$disabled = @($flagged | Where-Object { $_.Finding -eq 'Disabled' }).Count
$inactive = $flagged.Count - $disabled
$scope = if ($noSignIn) { 'disabled accounts only (no sign-in data)' } else { "inactive threshold $InactiveDays days" }
Write-IamLog -Message "Unused licences ($scope): $($flagged.Count) of $($licensed.Count) licensed users. Disabled: $disabled. Inactive or never signed in: $inactive. CSV: $csv"

$report | Where-Object { $_.Finding } | Format-Table DisplayName, Licences, AssignedBy, LastSignIn, DaysInactive, Finding -AutoSize
$summary | Format-Table -AutoSize
