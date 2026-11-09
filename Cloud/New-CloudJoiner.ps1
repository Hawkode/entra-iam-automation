<#
.SYNOPSIS
    Creates cloud-only joiners in Entra ID and assigns their licence.

.DESCRIPTION
    Creates each user with department, job title and usage location, then assigns
    the licence named in config (LicenseSkuPartNumber).

    Department must match AllowedDepartments in config. The Dept- dynamic groups key
    on it, so a typo would leave the user licensed but with no group access.

    UPN format: UpnFormat in config (default {given}.{surname}), lower case, accents
    removed, @DefaultDomain. Tokens: {given}, {surname}, {g} (first initial), {s}.
    Every row is validated, and every UPN checked for collisions, before anything is
    created. If any row fails, nothing is created. Existing UPNs are not auto-numbered:
    a duplicate name needs a human decision.

    Temporary password: random, 20 characters, must be changed at first sign-in.
    Shown once in the console. Never logged and never written to the CSV.

    Cloud-only. For users synced from AD, use Hybrid\New-HybridJoiner.ps1.

    Graph scopes (delegated): User.ReadWrite.All, LicenseAssignment.Read.All
    Entra role for the signed-in admin: User Administrator

.PARAMETER Manager
    UPN of the new user's manager. Must exist and be enabled. Sets the Manager attribute,
    which the leaver later uses to hand over the mailbox.

.PARAMETER CsvPath
    CSV with columns GivenName, Surname, Department, JobTitle, Manager (JobTitle and Manager optional).

.PARAMETER SkipLicense
    Create the users without assigning a licence (for example, group-based licensing).

.EXAMPLE
    .\Cloud\New-CloudJoiner.ps1 -GivenName Oliver -Surname Bennett -Department Engineering -WhatIf
.EXAMPLE
    .\Cloud\New-CloudJoiner.ps1 -GivenName Oliver -Surname Bennett -Department Engineering -Manager grace.miller@contoso.onmicrosoft.com
.EXAMPLE
    .\Cloud\New-CloudJoiner.ps1 -CsvPath .\samples\joiners.example.csv
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$GivenName,
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$Surname,
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$Department,
    [Parameter(ParameterSetName = 'Single')][string]$JobTitle,
    [Parameter(ParameterSetName = 'Single')][string]$Manager,
    [Parameter(Mandatory, ParameterSetName = 'Csv')][string]$CsvPath,
    [switch]$SkipLicense
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$required = @('DefaultDomain', 'UsageLocation', 'AllowedDepartments')
if (-not $SkipLicense) { $required += 'LicenseSkuPartNumber' }
$cfg = Import-IamConfig -Require $required
$allowed = @($cfg.AllowedDepartments)
$upnFormat = if ($cfg.UpnFormat) { [string]$cfg.UpnFormat } else { '{given}.{surname}' }

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    if (-not (Test-Path -Path $CsvPath)) { throw "CSV not found: $CsvPath" }
    $rows = @(Import-Csv -Path $CsvPath -Encoding UTF8)
}
else {
    $rows = @([pscustomobject]@{ GivenName = $GivenName; Surname = $Surname; Department = $Department; JobTitle = $JobTitle; Manager = $Manager })
}
if ($rows.Count -eq 0) { throw 'No joiners to process.' }

# Validate every row before signing in or changing anything.
$i = 0
$plan = foreach ($r in $rows) {
    $i++
    $gn = "$($r.GivenName)".Trim()
    $sn = "$($r.Surname)".Trim()
    $deptIn = "$($r.Department)".Trim()
    if (-not $gn -or -not $sn) { throw "Row ${i}: GivenName and Surname are both required." }

    $dept = $allowed | Where-Object { $_ -eq $deptIn } | Select-Object -First 1
    if (-not $dept) { throw "Row ${i} ($gn $sn): department '$deptIn' is not allowed. Allowed: $($allowed -join ', ')" }

    try { $nick = Get-IamUpnPrefix -GivenName $gn -Surname $sn -Format $upnFormat }
    catch { throw "Row ${i} ($gn $sn): $($_.Exception.Message)" }

    [pscustomobject]@{
        GivenName    = $gn
        Surname      = $sn
        DisplayName  = "$gn $sn"
        Department   = $dept
        JobTitle     = "$($r.JobTitle)".Trim()
        Manager      = "$($r.Manager)".Trim()
        MailNickname = $nick
        Upn          = "$nick@$($cfg.DefaultDomain)"
    }
}

$dupes = @($plan | Group-Object -Property Upn | Where-Object { $_.Count -gt 1 })
if ($dupes) { throw "Duplicate UPNs in input: $($dupes.Name -join ', ')" }

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.ReadWrite.All', 'LicenseAssignment.Read.All'

foreach ($p in $plan) {
    $existing = Get-MgUser -Filter "userPrincipalName eq '$($p.Upn)'" -Property Id, OnPremisesSyncEnabled
    if ($existing) {
        $kind = if ($existing.OnPremisesSyncEnabled) { 'a synced user' } else { 'a cloud user' }
        throw "$($p.Upn) already exists as $kind. Nothing was created. Resolve the duplicate and run again."
    }
}

$managerIds = @{}
foreach ($mUpn in @($plan.Manager | Where-Object { $_ } | Sort-Object -Unique)) {
    $mUser = $null
    try { $mUser = Get-MgUser -UserId $mUpn -Property Id, AccountEnabled -ErrorAction Stop } catch { $mUser = $null }
    if (-not $mUser) { throw "Manager $mUpn not found in Entra ID. Nothing was created." }
    if (-not $mUser.AccountEnabled) { throw "Manager $mUpn is disabled. Nothing was created." }
    $managerIds[$mUpn] = $mUser.Id
}

$skuId = $null
if (-not $SkipLicense) {
    $sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $cfg.LicenseSkuPartNumber }
    if (-not $sku) { throw "Licence $($cfg.LicenseSkuPartNumber) not found in this tenant. Fix LicenseSkuPartNumber or use -SkipLicense." }
    $free = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
    if ($free -lt $plan.Count) { throw "Only $free $($cfg.LicenseSkuPartNumber) licence(s) free for $($plan.Count) joiner(s). Nothing was created." }
    $skuId = $sku.SkuId
}

$results = foreach ($p in $plan) {
    $action = "Create cloud user ($($p.Department))"
    if ($skuId) { $action += " and assign $($cfg.LicenseSkuPartNumber)" }
    if ($p.Manager) { $action += ", manager $($p.Manager)" }
    if (-not $PSCmdlet.ShouldProcess($p.Upn, $action)) { continue }

    $password = Get-IamRandomPassword
    $body = @{
        AccountEnabled    = $true
        DisplayName       = $p.DisplayName
        GivenName         = $p.GivenName
        Surname           = $p.Surname
        UserPrincipalName = $p.Upn
        MailNickname      = $p.MailNickname
        Department        = $p.Department
        UsageLocation     = $cfg.UsageLocation
        PasswordProfile   = @{ Password = $password; ForceChangePasswordNextSignIn = $true }
    }
    if ($p.JobTitle) { $body.JobTitle = $p.JobTitle }

    $user = New-MgUser -BodyParameter $body
    Write-IamLog -Message "Created $($p.Upn) ($($p.Department)). Id: $($user.Id)"

    $managerSet = ''
    if ($p.Manager) {
        $managerSet = 'FAILED'
        $ref = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($managerIds[$p.Manager])" } | ConvertTo-Json
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Invoke-MgGraphRequest -Method PUT -Uri "v1.0/users/$($user.Id)/manager/`$ref" -Body $ref -ContentType 'application/json' | Out-Null
                $managerSet = $p.Manager
                Write-IamLog -Message "Manager of $($p.Upn) set to $($p.Manager)"
                break
            }
            catch {
                if ($attempt -eq 3) { Write-IamLog -Level ERROR -Message "Manager not set on $($p.Upn): $($_.Exception.Message)" }
                else { Start-Sleep -Seconds 5 }
            }
        }
    }

    $licence = 'Skipped'
    if ($skuId) {
        # A new user can take a few seconds to replicate before a licence can be assigned.
        $licence = 'FAILED'
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try {
                Set-MgUserLicense -UserId $user.Id -AddLicenses @(@{ SkuId = $skuId }) -RemoveLicenses @() | Out-Null
                $licence = $cfg.LicenseSkuPartNumber
                Write-IamLog -Message "Assigned $licence to $($p.Upn)"
                break
            }
            catch {
                if ($attempt -eq 5) { Write-IamLog -Level ERROR -Message "Licence failed for $($p.Upn): $($_.Exception.Message)" }
                else { Start-Sleep -Seconds 5 }
            }
        }
    }

    [pscustomobject]@{
        DisplayName  = $p.DisplayName
        Upn          = $p.Upn
        Department   = $p.Department
        Licence      = $licence
        Manager      = $managerSet
        TempPassword = $password
        Id           = $user.Id
    }
}

$results = @($results)
if ($results.Count -gt 0) {
    $csv = Get-IamOutputPath -Prefix 'Joiners'
    $results | Select-Object -Property * -ExcludeProperty TempPassword | Export-Csv -Path $csv -NoTypeInformation
    Write-IamLog -Message "Joiners created: $($results.Count). CSV (no passwords): $csv"

    $results | Format-Table DisplayName, Upn, Department, Manager, Licence, TempPassword -AutoSize
    Write-Warning 'Temporary passwords are shown once. Pass them on through Bitwarden Send, not email or Teams.'
}