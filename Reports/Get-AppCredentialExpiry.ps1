<#
.SYNOPSIS
    Finds app secrets and certificates that have expired or expire soon.

.DESCRIPTION
    Checks every app registration and every enterprise app (service principal) in the tenant:
    client secrets, certificates, and the SAML signing certificates of enterprise apps.
    One row per credential, with the days left and a status:
      Expired              past its end date
      Expiring             ends within -Days
      ..., replaced        a newer one of the same type is valid beyond -Days, so the old
                           one only needs deleting
      OK                   only with -All
    Each flagged row lists the app's owners, so you know who to ask before you renew.

    An expired secret on an app nobody uses is clean-up, not an outage. Check the app's
    sign-in logs before renewing.

    Read-only. Graph scope (delegated): Application.Read.All. Entra ID Free.
    Roles that can read it: Global Reader, Application Administrator, Cloud Application Administrator.

.PARAMETER Days
    Warning window in days. Default 60.

.PARAMETER All
    Also lists credentials that are fine.

.EXAMPLE
    .\Reports\Get-AppCredentialExpiry.ps1
.EXAMPLE
    .\Reports\Get-AppCredentialExpiry.ps1 -Days 30 -All
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 730)][int]$Days = 60,
    [switch]$All
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig
$now = (Get-Date).ToUniversalTime()

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'Application.Read.All'

$props = 'Id', 'AppId', 'DisplayName', 'PasswordCredentials', 'KeyCredentials'
$hasCred = { @($_.PasswordCredentials).Count -gt 0 -or @($_.KeyCredentials).Count -gt 0 }
$apps = @(Get-MgApplication -All -Property $props -ErrorAction Stop | Where-Object $hasCred)
$sps = @(Get-MgServicePrincipal -All -Property $props -ErrorAction Stop | Where-Object $hasCred)

$rows = @()
foreach ($a in $apps) { $rows += Get-IamCredentialFinding -Object $a -Kind 'App registration' -Now $now -Days $Days }
foreach ($s in $sps) { $rows += Get-IamCredentialFinding -Object $s -Kind 'Enterprise app' -Now $now -Days $Days }

# Owners for flagged rows only: one lookup per app.
$ownerCache = @{}
$report = foreach ($r in $rows) {
    if ($r.Status -eq 'OK' -and -not $All) { continue }
    $owners = ''
    if ($r.Status -ne 'OK') {
        if (-not $ownerCache.ContainsKey($r.ObjectId)) {
            $path = if ($r.Kind -eq 'App registration') { 'applications' } else { 'servicePrincipals' }
            try {
                $list = @(Invoke-IamGraphGetAll -Uri "v1.0/$path/$($r.ObjectId)/owners?`$select=displayName,userPrincipalName" |
                        ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } })
                $ownerCache[$r.ObjectId] = if ($list.Count) { $list -join '; ' } else { 'No owner' }
            }
            catch {
                Write-IamLog -Level WARN -Message "Owners of $($r.DisplayName): $($_.Exception.Message)"
                $ownerCache[$r.ObjectId] = 'Not checked'
            }
        }
        $owners = $ownerCache[$r.ObjectId]
    }
    $r | Select-Object Kind, DisplayName, AppId, Type, Name, KeyId, Usage, EndDate, DaysLeft, Status, Action, @{ n = 'Owners'; e = { $owners } }
}

$order = @{ 'Expired' = 0; 'Expiring' = 1; 'Expired, replaced' = 2; 'Expiring, replaced' = 3; 'OK' = 4 }
$report = @($report | Sort-Object -Property @{ Expression = { $order[$_.Status] } }, DaysLeft, DisplayName)

$csv = Get-IamOutputPath -Prefix 'AppCredentialExpiry'
$report | Export-Csv -Path $csv

$expired = @($rows | Where-Object Status -EQ 'Expired').Count
$expiring = @($rows | Where-Object Status -EQ 'Expiring').Count
$replaced = @($rows | Where-Object Status -Like '*replaced').Count
Write-IamLog -Message "App credentials: $($rows.Count) on $($apps.Count) app registration(s) and $($sps.Count) enterprise app(s). Expired: $expired. Expiring within $Days days: $expiring. Old ones to delete (replaced): $replaced. CSV: $csv"

$report | Format-Table DisplayName, Kind, Type, EndDate, DaysLeft, Status, Owners -AutoSize
