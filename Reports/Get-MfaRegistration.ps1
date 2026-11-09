<#
.SYNOPSIS
    Finds users with no MFA, only weak MFA methods, or admins without a phishing-resistant method.

.DESCRIPTION
    Reads the Entra "Authentication methods - registration" data
    (reports/authenticationMethods/userRegistrationDetails). One row per enabled user.

    Findings:
      No MFA                       - no MFA method registered.
      Weak MFA only                - only SMS, voice or email.
      Admin without phishing-resistant - an admin with no FIDO2 key, passkey,
                                     Windows Hello for Business or certificate.
      Break-glass without phishing-resistant - a break-glass account from config with no
                                     FIDO2 key, passkey or certificate. Microsoft's mandatory MFA
                                     for admin portals applies to break-glass accounts too.
    Break-glass accounts that have a phishing-resistant method show "OK (break-glass)".

    The data excludes disabled and soft-deleted users, and can lag by a few hours.
    Needs Entra ID P1 or P2 in the tenant.

    Read-only. Graph scopes (delegated): AuditLog.Read.All
    Entra role for the signed-in admin: Reports Reader (or Security Reader, Global Reader)

.PARAMETER IncludeGuests
    Include guest users. Default: members only.

.EXAMPLE
    .\Reports\Get-MfaRegistration.ps1
.EXAMPLE
    .\Reports\Get-MfaRegistration.ps1 -IncludeGuests
#>
[CmdletBinding()]
param([switch]$IncludeGuests)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig
$breakGlass = @($cfg.BreakGlassUpns)
Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'AuditLog.Read.All'

$weak = @('mobilePhone', 'alternateMobilePhone', 'officePhone', 'email')
$phishingResistant = @('fido2SecurityKey', 'windowsHelloForBusiness', 'macOsSecureEnclaveKey', 'certificateBasedAuthentication')

$rows = @()
$uri = 'v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
try {
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $rows += @($page.value)
        $uri = $page.'@odata.nextLink'
    }
}
catch {
    if ($_.Exception.Message -match 'premium|license|Forbidden|403') {
        throw 'Could not read MFA registration details. This report needs Entra ID P1 or P2 and a role such as Reports Reader.'
    }
    throw
}

$report = foreach ($r in $rows) {
    if (-not $IncludeGuests -and $r.userType -eq 'guest') { continue }
    $methods = @($r.methodsRegistered)
    $strongResistant = @($methods | Where-Object { $phishingResistant -contains $_ -or $_ -like 'passKey*' })
    $nonWeak = @($methods | Where-Object { $weak -notcontains $_ })

    $finding = ''
    if ($breakGlass -contains $r.userPrincipalName) {
        if ($strongResistant.Count -gt 0) { $finding = 'OK (break-glass)' }
        else { $finding = 'Break-glass without phishing-resistant' }
    }
    elseif (-not $r.isMfaRegistered) { $finding = 'No MFA' }
    elseif ($nonWeak.Count -eq 0) { $finding = 'Weak MFA only' }
    elseif ($r.isAdmin -and $strongResistant.Count -eq 0) { $finding = 'Admin without phishing-resistant' }

    [pscustomobject]@{
        DisplayName   = $r.userDisplayName
        Upn           = $r.userPrincipalName
        UserType      = $r.userType
        IsAdmin       = [bool]$r.isAdmin
        MfaRegistered = [bool]$r.isMfaRegistered
        DefaultMethod = $r.defaultMfaMethod
        Methods       = ($methods -join ', ')
        Finding       = $finding
    }
}

$rank = @{ 'Break-glass without phishing-resistant' = 0; 'No MFA' = 1; 'Admin without phishing-resistant' = 2; 'Weak MFA only' = 3 }
$report = @($report | Sort-Object -Property @{ Expression = { if ($rank.ContainsKey($_.Finding)) { $rank[$_.Finding] } else { 9 } } }, DisplayName)

$csv = Get-IamOutputPath -Prefix 'MfaRegistration'
$report | Export-Csv -Path $csv -NoTypeInformation

$counts = $report | Where-Object { $rank.ContainsKey($_.Finding) } | Group-Object -Property Finding |
    ForEach-Object { "$($_.Name) $($_.Count)" }
Write-IamLog -Message "MFA registration: $($report.Count) users. Findings: $(if ($counts) { $counts -join ', ' } else { 'none' }). CSV: $csv"

$report | Format-Table DisplayName, IsAdmin, MfaRegistered, DefaultMethod, Finding -AutoSize
