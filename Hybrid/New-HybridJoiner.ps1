<#
.SYNOPSIS
    Creates joiners in on-prem AD, syncs them to Entra ID, then sets usage location and licence.

.DESCRIPTION
    For hybrid tenants where AD DS is the source of authority.

      1. Validates every row before anything is created: department (a key of
         DepartmentOUs), UPN format, duplicates in the input, the target OU, and
         clashes with existing AD users or cloud users. One bad row, nothing created.
      2. Creates each user with New-ADUser in the department's OU, with a random
         temporary password that must be changed at first sign-in.
      3. Runs one Entra Connect delta sync for the whole batch.
      4. Waits for each user to appear in Entra ID as synced, then sets usage
         location and assigns the licence through Graph.

    If a user has not synced in time, finish the cloud steps later with
    -ResumeUserPrincipalName (no AD changes in that mode).

    A clash with an existing cloud-only user stops the run: Entra Connect would
    soft-match the new AD account onto that cloud account and take it over.

    DefaultDomain must be a UPN suffix in AD (AD Domains and Trusts) and a verified
    domain in Entra ID. Otherwise the user syncs as @<tenant>.onmicrosoft.com.

    Temporary passwords are shown once in the console, never logged or written to CSV.

    Graph scopes (delegated): User.ReadWrite.All, LicenseAssignment.Read.All
    AD rights: create users in the DepartmentOUs. Entra Connect server: WinRM and ADSyncOperators.

.PARAMETER Manager
    UPN of the new user's manager in AD. Must exist and be enabled. Sets the AD manager
    attribute, which syncs to Entra ID and which the leaver later uses for the mailbox.

.PARAMETER CsvPath
    CSV with columns GivenName, Surname, Department, JobTitle, Manager (JobTitle and Manager optional).

.PARAMETER ResumeUserPrincipalName
    Synced users that still need usage location and licence. Skips AD and sync.

.PARAMETER SkipLicense
    Do not assign a licence (for example, group-based licensing).

.EXAMPLE
    .\Hybrid\New-HybridJoiner.ps1 -GivenName Oliver -Surname Bennett -Department Engineering -WhatIf
.EXAMPLE
    .\Hybrid\New-HybridJoiner.ps1 -GivenName Oliver -Surname Bennett -Department Engineering -Manager grace.miller@contoso.com
.EXAMPLE
    .\Hybrid\New-HybridJoiner.ps1 -CsvPath .\samples\joiners.example.csv
.EXAMPLE
    .\Hybrid\New-HybridJoiner.ps1 -ResumeUserPrincipalName oliver.bennett@contoso.com
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$GivenName,
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$Surname,
    [Parameter(Mandatory, ParameterSetName = 'Single')][string]$Department,
    [Parameter(ParameterSetName = 'Single')][string]$JobTitle,
    [Parameter(ParameterSetName = 'Single')][string]$Manager,
    [Parameter(Mandatory, ParameterSetName = 'Csv')][string]$CsvPath,
    [Parameter(Mandatory, ParameterSetName = 'Resume')][string[]]$ResumeUserPrincipalName,
    [switch]$SkipLicense,
    [int]$SyncTimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$required = @('UsageLocation')
if ($PSCmdlet.ParameterSetName -ne 'Resume') { $required += 'DefaultDomain', 'DepartmentOUs', 'EntraConnectServer' }
if (-not $SkipLicense) { $required += 'LicenseSkuPartNumber' }
$cfg = Import-IamConfig -Require $required
$deptOUs = $cfg.DepartmentOUs
$upnFormat = if ($cfg.UpnFormat) { [string]$cfg.UpnFormat } else { '{given}.{surname}' }

$plan = @()
if ($PSCmdlet.ParameterSetName -ne 'Resume') {
    Import-IamAdModule

    $domain = "$($cfg.DefaultDomain)".ToLowerInvariant()
    $suffixes = @((Get-ADForest).UPNSuffixes) + @((Get-ADDomain).DNSRoot) | ForEach-Object { "$_".ToLowerInvariant() }
    if ($suffixes -notcontains $domain) {
        throw "DefaultDomain '$domain' is not a UPN suffix in AD. Add it in AD Domains and Trusts, or users sync as @<tenant>.onmicrosoft.com."
    }

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

        $dept = $deptOUs.Keys | Where-Object { $_ -eq $deptIn } | Select-Object -First 1
        if (-not $dept) { throw "Row ${i} ($gn $sn): department '$deptIn' is not in DepartmentOUs. Allowed: $(($deptOUs.Keys | Sort-Object) -join ', ')" }

        try { $nick = Get-IamUpnPrefix -GivenName $gn -Surname $sn -Format $upnFormat }
        catch { throw "Row ${i} ($gn $sn): $($_.Exception.Message)" }

        # sAMAccountName: 20 characters maximum.
        $sam = $nick.Substring(0, [Math]::Min(20, $nick.Length)).TrimEnd('.', '-', '_')

        [pscustomobject]@{
            Row         = $i
            GivenName   = $gn
            Surname     = $sn
            DisplayName = "$gn $sn"
            Department  = $dept
            JobTitle    = "$($r.JobTitle)".Trim()
            Manager     = "$($r.Manager)".Trim()
            ManagerDN   = $null
            Sam         = $sam
            Upn         = "$nick@$domain"
            OU          = $deptOUs[$dept]
        }
    }

    foreach ($prop in 'Upn', 'Sam') {
        $dupes = @($plan | Group-Object -Property $prop | Where-Object { $_.Count -gt 1 })
        if ($dupes) { throw "Duplicate $prop in input: $($dupes.Name -join ', ')" }
    }

    $managerDNs = @{}
    foreach ($mUpn in @($plan.Manager | Where-Object { $_ } | Sort-Object -Unique)) {
        $managerDNs[$mUpn] = (Get-IamValidManager -UserPrincipalName $mUpn -Source AD -OnFail 'Nothing was created.').DistinguishedName
    }
    foreach ($p in $plan) { if ($p.Manager) { $p.ManagerDN = $managerDNs[$p.Manager] } }

    foreach ($p in $plan) {
        try { $null = Get-ADOrganizationalUnit -Identity $p.OU }
        catch { throw "Row $($p.Row): OU for $($p.Department) not found: $($p.OU)" }

        $clash = Get-ADUser -Filter "UserPrincipalName -eq '$($p.Upn)' -or SamAccountName -eq '$($p.Sam)'" -Properties UserPrincipalName
        if ($clash) { throw "Row $($p.Row): $($p.Upn) or sAMAccountName '$($p.Sam)' already exists in AD ($($clash.DistinguishedName)). Nothing was created." }

        $nameClash = Get-ADObject -Filter "Name -eq '$($p.DisplayName -replace "'", "''")'" -SearchBase $p.OU -SearchScope OneLevel
        if ($nameClash) { throw "Row $($p.Row): an object named '$($p.DisplayName)' already exists in $($p.OU). Nothing was created." }
    }
}

Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'User.ReadWrite.All', 'LicenseAssignment.Read.All'

foreach ($p in $plan) {
    $cloud = Get-MgUser -Filter "userPrincipalName eq '$($p.Upn)'" -Property Id, OnPremisesSyncEnabled
    if ($cloud) {
        throw "Row $($p.Row): $($p.Upn) already exists in Entra ID. Entra Connect would soft-match the new AD account onto it. Nothing was created."
    }
}

$skuId = $null
if (-not $SkipLicense) {
    $count = if ($PSCmdlet.ParameterSetName -eq 'Resume') { $ResumeUserPrincipalName.Count } else { $plan.Count }
    $sku = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $cfg.LicenseSkuPartNumber }
    if (-not $sku) { throw "Licence $($cfg.LicenseSkuPartNumber) not found in this tenant. Fix LicenseSkuPartNumber or use -SkipLicense." }
    $free = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
    if ($free -lt $count) { throw "Only $free $($cfg.LicenseSkuPartNumber) licence(s) free for $count joiner(s). Nothing was created." }
    $skuId = $sku.SkuId
}

# ---- AD ----
$created = @()
foreach ($p in $plan) {
    $action = "Create AD user in $($p.OU) ($($p.Department)), sync, set usage location"
    if ($skuId) { $action += ", assign $($cfg.LicenseSkuPartNumber)" }
    if ($p.Manager) { $action += ", manager $($p.Manager)" }
    if (-not $PSCmdlet.ShouldProcess($p.Upn, $action)) { continue }

    $password = Get-IamRandomPassword
    $adParams = @{
        Name                  = $p.DisplayName
        GivenName             = $p.GivenName
        Surname               = $p.Surname
        DisplayName           = $p.DisplayName
        UserPrincipalName     = $p.Upn
        SamAccountName        = $p.Sam
        Department            = $p.Department
        Path                  = $p.OU
        AccountPassword       = ConvertTo-IamSecureString -Text $password
        Enabled               = $true
        ChangePasswordAtLogon = $true
    }
    if ($p.JobTitle) { $adParams.Title = $p.JobTitle }
    if ($p.ManagerDN) { $adParams.Manager = $p.ManagerDN }
    New-ADUser @adParams
    Write-IamLog -Message "Created AD user $($p.Upn) (sAMAccountName $($p.Sam)) in $($p.OU)"
    $created += [pscustomobject]@{ Upn = $p.Upn; DisplayName = $p.DisplayName; Department = $p.Department; TempPassword = $password }
}

$targets = if ($PSCmdlet.ParameterSetName -eq 'Resume') {
    $ResumeUserPrincipalName | ForEach-Object { [pscustomobject]@{ Upn = $_; DisplayName = $null; Department = $null; TempPassword = $null } }
}
else { $created }
if (-not $targets) { return }

if ($PSCmdlet.ParameterSetName -ne 'Resume') {
    $null = Invoke-IamDeltaSync -Server $cfg.EntraConnectServer -TimeoutSeconds $SyncTimeoutSeconds
}

# ---- Cloud ----
$results = foreach ($t in $targets) {
    $status = 'Not synced yet'
    $licence = 'Skipped'
    $u = Wait-IamCloudUser -UserPrincipalName $t.Upn -TimeoutSeconds $SyncTimeoutSeconds -Until { param($x) $x.OnPremisesSyncEnabled -eq $true }
    if (-not $u) {
        Write-IamLog -Level WARN -Message "$($t.Upn) is not in Entra ID as a synced user yet. Finish later with -ResumeUserPrincipalName $($t.Upn)"
    }
    else {
        $status = 'Synced'
        try {
            Update-MgUser -UserId $u.Id -BodyParameter @{ UsageLocation = $cfg.UsageLocation }
            Write-IamLog -Message "Usage location $($cfg.UsageLocation) set on $($t.Upn)"
        }
        catch {
            $status = 'Usage location failed'
            Write-IamLog -Level ERROR -Message "Usage location failed for $($t.Upn): $($_.Exception.Message)"
        }
        if ($skuId -and $status -eq 'Synced') {
            $licence = 'FAILED'
            for ($attempt = 1; $attempt -le 5; $attempt++) {
                try {
                    Set-MgUserLicense -UserId $u.Id -AddLicenses @(@{ SkuId = $skuId }) -RemoveLicenses @() | Out-Null
                    $licence = $cfg.LicenseSkuPartNumber
                    Write-IamLog -Message "Assigned $licence to $($t.Upn)"
                    break
                }
                catch {
                    if ($attempt -eq 5) { Write-IamLog -Level ERROR -Message "Licence failed for $($t.Upn): $($_.Exception.Message)" }
                    else { Start-Sleep -Seconds 5 }
                }
            }
        }
    }
    [pscustomobject]@{
        DisplayName  = $t.DisplayName
        Upn          = $t.Upn
        Department   = $t.Department
        Cloud        = $status
        Licence      = $licence
        TempPassword = $t.TempPassword
    }
}

$results = @($results)
$csv = Get-IamOutputPath -Prefix 'HybridJoiners'
$results | Select-Object -Property * -ExcludeProperty TempPassword | Export-Csv -Path $csv -NoTypeInformation
Write-IamLog -Message "Hybrid joiners processed: $($results.Count). CSV (no passwords): $csv"

if ($PSCmdlet.ParameterSetName -eq 'Resume') {
    $results | Format-Table Upn, Cloud, Licence -AutoSize
}
else {
    $results | Format-Table DisplayName, Upn, Department, Cloud, Licence, TempPassword -AutoSize
    Write-Warning 'Temporary passwords are shown once. Pass them on through a one-time secret link, not email or chat.'
}
