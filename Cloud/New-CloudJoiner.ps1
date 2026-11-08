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

.PARAMETER CsvPath
    CSV with columns GivenName, Surname, Department, JobTitle (JobTitle optional).

.PARAMETER SkipLicense
    Create the users without assigning a licence (for example, group-based licensing).

.EXAMPLE
    .\Cloud\New-CloudJoiner.ps1 -GivenName Oliver -Surname Bennett -Department Engineering -WhatIf
.EXAMPLE
    .\Cloud\New-CloudJoiner.ps1 -CsvPath .\samples\joiners.example.csv
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$GivenName,
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$Surname,
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$Department,
    [Parameter(ParameterSetName = 'Single')][string]$JobTitle,
    [Parameter(Mandatory, ParameterSetName = 'Csv')][string]$CsvPath,
    [switch]$SkipLicense
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

function ConvertTo-UpnPart {
    param([Parameter(Mandatory)][string]$Text)
    # Strip accents (S-comma to S, a-breve to a), then keep only a-z, 0-9 and hyphen.
    $decomposed = $Text.Trim().Normalize([Text.NormalizationForm]::FormD)
    $plain = -join ($decomposed.ToCharArray() | Where-Object {
            [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark
        })
    $plain.ToLowerInvariant() -replace '[^a-z0-9-]', ''
}

function Get-RandomPassword {
    param([int]$Length = 20)
    # No I, O, l, o, 0, 1: avoids misreads when the password is passed on.
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%*+-=?@'.ToCharArray()
    $bytes = New-Object -TypeName byte[] -ArgumentList $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        do {
            $rng.GetBytes($bytes)
            $pw = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
        } until ($pw -cmatch '[A-Z]' -and $pw -cmatch '[a-z]' -and $pw -match '[0-9]' -and $pw -match '[^A-Za-z0-9]')
    }
    finally { $rng.Dispose() }
    $pw
}

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
    $rows = @([pscustomobject]@{ GivenName = $GivenName; Surname = $Surname; Department = $Department; JobTitle = $JobTitle })
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

    $first = ConvertTo-UpnPart -Text $gn
    $last = ConvertTo-UpnPart -Text $sn
    if (-not $first -or -not $last) { throw "Row ${i} ($gn $sn): name has no characters usable in a UPN." }
    $nick = $upnFormat.Replace('{given}', $first).Replace('{surname}', $last)
    $nick = $nick.Replace('{g}', $first.Substring(0, 1)).Replace('{s}', $last.Substring(0, 1))
    if ($nick -match '[{}]') { throw "UpnFormat '$upnFormat' has an unknown token. Use {given}, {surname}, {g} or {s}." }
    if ($nick -cnotmatch '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$' -or $nick -match '\.\.') {
        throw "Row ${i} ($gn $sn): UPN prefix '$nick' from UpnFormat '$upnFormat' is not valid."
    }

    [pscustomobject]@{
        GivenName    = $gn
        Surname      = $sn
        DisplayName  = "$gn $sn"
        Department   = $dept
        JobTitle     = "$($r.JobTitle)".Trim()
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
    if (-not $PSCmdlet.ShouldProcess($p.Upn, $action)) { continue }

    $password = Get-RandomPassword
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
        TempPassword = $password
        Id           = $user.Id
    }
}

$results = @($results)
if ($results.Count -gt 0) {
    $csv = Get-IamOutputPath -Prefix 'Joiners'
    $results | Select-Object -Property * -ExcludeProperty TempPassword | Export-Csv -Path $csv -NoTypeInformation
    Write-IamLog -Message "Joiners created: $($results.Count). CSV (no passwords): $csv"

    $results | Format-Table DisplayName, Upn, Department, Licence, TempPassword -AutoSize
    Write-Warning 'Temporary passwords are shown once. Pass them on through Bitwarden Send, not email or Teams.'
}