<#
.SYNOPSIS
    Builds config.local.psd1 from what Entra ID and AD already know, and asks only for the rest.

.DESCRIPTION
    Read-only against the tenant, AD and Entra Connect. The only files it writes are
    config.local.psd1 and a backup of the old one, after showing the result and asking.

      Found in Entra ID     TenantId, UsageLocation, DefaultDomain (picked if several),
                            LicenseSkuPartNumber (picked), UpnFormat (from existing UPNs)
      Suggested, you check  AllowedDepartments (departments in use), ReviewFallbackUpn
                            (signed-in account), BreakGlassUpns (Global Administrators excluded
                            from every enabled Conditional Access policy that would cover them)
      Found in AD           DepartmentOUs and LeaversOU (by OU name), EntraConnectServer
                            (from the MSOL_ account description, staging servers skipped)
      Found on Entra Connect  LeaversOUInSyncScope (OU filtering scope). Set to $true only
                            after you confirm
      Your choice           StaleDays (default 90), ProtectedAdGroups (default Domain Users)

    An existing config.local.psd1 is read first. Its values are the default whenever nothing
    better is found, and keys this script does not know are kept.

    Hybrid keys are skipped when the ActiveDirectory module is missing or -SkipHybrid is set.
    They keep their current values, so the hybrid scripts keep refusing to run until they are
    filled in.

    The sync scope check reads OU filtering only. Group-based filtering and attribute
    filtering are not checked.

    Graph scopes (delegated, read-only): User.Read.All, Organization.Read.All, Policy.Read.All,
      RoleManagement.Read.Directory, GroupMember.Read.All
    AD: read access. Entra Connect server: WinRM and ADSyncOperators, as for the hybrid scripts.

.PARAMETER TenantId
    Tenant ID or initial domain (contoso.onmicrosoft.com) to sign in to.
    Default: TenantId from the existing config.local.psd1. Asked for when neither is there.

.PARAMETER Path
    Config file to write. Default: config.local.psd1 in the repo root.

.PARAMETER SkipHybrid
    Do not read AD or Entra Connect. Hybrid keys keep their current values.

.EXAMPLE
    .\Setup\New-IamConfig.ps1 -WhatIf
    Gathers everything and shows the file it would write. Writes nothing.
.EXAMPLE
    .\Setup\New-IamConfig.ps1 -TenantId contoso.onmicrosoft.com
.EXAMPLE
    .\Setup\New-IamConfig.ps1 -SkipHybrid
    Cloud-only tenant, or a machine without RSAT.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$TenantId,
    [string]$Path,
    [switch]$SkipHybrid
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force
Assert-IamGraphHost
if (-not $Path) { $Path = Join-Path -Path $repoRoot -ChildPath 'config.local.psd1' }

#region Prompt helpers

function Show-SetupLine {
    param([AllowEmptyString()][string]$Message = '')
    Write-Information -MessageData $Message -InformationAction Continue
}

function Show-SetupHeading {
    param([Parameter(Mandatory)][string]$Title)
    Show-SetupLine ''
    Show-SetupLine "== $Title"
}

function Read-SetupValue {
    # Enter keeps the suggestion, anything else replaces it.
    param([Parameter(Mandatory)][string]$Prompt, [AllowEmptyString()][string]$Suggested = '')
    $shown = if ($Suggested) { " [$Suggested]" } else { '' }
    $answer = Read-Host -Prompt "$Prompt$shown"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Suggested }
    $answer.Trim()
}

function Read-SetupList {
    # Comma-separated list. Enter keeps the suggestion.
    param([Parameter(Mandatory)][string]$Prompt, [string[]]$Suggested = @())
    $answer = Read-SetupValue -Prompt "$Prompt, comma-separated" -Suggested ($Suggested -join ', ')
    , @("$answer" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Read-SetupChoice {
    # Numbered list. Enter takes the default, a number picks one, other text is used as typed.
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Option,
        [string[]]$Detail = @(),
        [int]$Default = 0
    )
    for ($i = 0; $i -lt $Option.Count; $i++) {
        $extra = if ($i -lt $Detail.Count -and $Detail[$i]) { "  ($($Detail[$i]))" } else { '' }
        Show-SetupLine ('  [{0}] {1}{2}' -f ($i + 1), $Option[$i], $extra)
    }
    $answer = Read-Host -Prompt "$Prompt [$($Default + 1)]"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Option[$Default] }
    $n = 0
    if ([int]::TryParse($answer.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $Option.Count) { return $Option[$n - 1] }
    $answer.Trim()
}

function Read-SetupYesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    $answer = Read-Host -Prompt "$Prompt [$hint]"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    $answer.Trim() -match '^(y|yes)$'
}

function Get-SetupCurrent {
    # The existing config value, or $null when it is empty or still an example value.
    param([Parameter(Mandatory)][string]$Key)
    if (-not $existing.ContainsKey($Key)) { return $null }
    $value = $existing[$Key]
    $check = if ($value -is [System.Collections.IDictionary]) { @($value.Values) } else { @($value) }
    $filled = @($check | Where-Object { "$_".Trim() })
    if ($filled.Count -eq 0 -or "$filled" -match 'contoso') { return $null }
    $value
}

function Format-SetupValue {
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        return (@($Value.Keys | ForEach-Object { "$_ = $($Value[$_])" }) -join '; ')
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return (@($Value) -join ', ') }
    "$Value"
}

#endregion

$keyOrder = 'TenantId', 'DefaultDomain', 'UpnFormat', 'UsageLocation', 'LicenseSkuPartNumber', 'StaleDays',
'BreakGlassUpns', 'ReviewFallbackUpn', 'AllowedDepartments', 'DepartmentOUs', 'LeaversOU', 'EntraConnectServer',
'ProtectedAdGroups', 'LeaversOUInSyncScope'
$hybridKeys = 'DepartmentOUs', 'LeaversOU', 'EntraConnectServer', 'ProtectedAdGroups', 'LeaversOUInSyncScope'

$example = Import-PowerShellDataFile -Path (Join-Path -Path $repoRoot -ChildPath 'config.example.psd1')
$existing = @{}
if (Test-Path -Path $Path) {
    $existing = Import-PowerShellDataFile -Path $Path
    Show-SetupLine "Read $Path. Its values are the defaults below."
}

$config = [ordered]@{}
$source = [ordered]@{}
foreach ($k in $keyOrder) { $config[$k] = $null; $source[$k] = '' }

#region Entra ID

if (-not $TenantId) {
    $guid = [guid]::Empty
    if ([guid]::TryParse("$($existing.TenantId)", [ref]$guid) -and $guid -ne [guid]::Empty) { $TenantId = "$guid" }
    else { $TenantId = Read-SetupValue -Prompt 'Tenant ID or initial domain (contoso.onmicrosoft.com)' }
}
if (-not $TenantId) { throw 'A tenant ID or domain is needed to sign in. Nothing was written.' }

$scopes = 'User.Read.All', 'Organization.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'GroupMember.Read.All'
Connect-IamGraph -TenantId $TenantId -Scopes $scopes
$ctx = Get-MgContext
$org = @(Invoke-IamGraphGetAll -Uri 'v1.0/organization?$select=id,displayName,countryLetterCode,verifiedDomains')[0]

Show-SetupHeading 'Tenant'
Show-SetupLine "Signed in to $($org.displayName) ($($ctx.TenantId)) as $($ctx.Account)."
if (-not (Read-SetupYesNo -Prompt 'Is this the tenant the config is for?' -Default $true)) {
    throw 'Wrong tenant. Run Disconnect-MgGraph, then run this again with -TenantId. Nothing was written.'
}
$config.TenantId = "$($ctx.TenantId)"; $source.TenantId = 'found'

# DefaultDomain: default domain first, then by name.
# *.mail.onmicrosoft.com is the Exchange Online mail routing domain, never a UPN domain.
$domains = @($org.verifiedDomains | Where-Object { "$($_.name)" -notlike '*.mail.onmicrosoft.com' } | Sort-Object -Property @{ Expression = { -not $_.isDefault } }, @{ Expression = { $_.name } })
$domainNames = @($domains | ForEach-Object { "$($_.name)" })
$current = Get-SetupCurrent -Key DefaultDomain
if ($domainNames.Count -eq 1) {
    $config.DefaultDomain = $domainNames[0]; $source.DefaultDomain = 'found'
}
elseif ($domainNames.Count -gt 1) {
    Show-SetupHeading 'Domain for new users (DefaultDomain)'
    $details = @($domains | ForEach-Object {
            $flags = @()
            if ($_.isDefault) { $flags += 'default' }
            if ($_.isInitial) { $flags += 'initial' }
            $flags -join ', '
        })
    $default = [Math]::Max(0, [array]::IndexOf($domainNames, "$current"))
    $config.DefaultDomain = Read-SetupChoice -Prompt 'DefaultDomain' -Option $domainNames -Detail $details -Default $default
    $source.DefaultDomain = 'chosen'
    if ($domainNames -notcontains $config.DefaultDomain) {
        Show-SetupLine "WARNING: $($config.DefaultDomain) is not verified in this tenant. The joiners will refuse it."
    }
}
else {
    $config.DefaultDomain = Read-SetupValue -Prompt 'DefaultDomain' -Suggested "$current"; $source.DefaultDomain = 'typed'
}

# Users: read once, used for the UPN pattern and the departments.
$users = @(Invoke-IamGraphGetAll -Uri 'v1.0/users?$select=userPrincipalName,givenName,surname,department,accountEnabled&$top=999' |
        Where-Object { $_.accountEnabled -and "$($_.userPrincipalName)" -notlike '*#EXT#*' })

# UpnFormat: taken as found when at least half the named users follow it.
$guess = Get-IamUpnFormatGuess -User $users
$current = Get-SetupCurrent -Key UpnFormat
if ($guess -and $guess.Hits * 2 -ge $guess.Total) {
    $config.UpnFormat = $guess.Format; $source.UpnFormat = "found ($($guess.Hits) of $($guess.Total) users)"
}
else {
    Show-SetupHeading 'UPN pattern (UpnFormat)'
    if ($guess) { Show-SetupLine "Best match: $($guess.Format), only $($guess.Hits) of $($guess.Total) users." }
    else { Show-SetupLine 'No pattern found in existing UPNs.' }
    Show-SetupLine 'Tokens: {given}, {surname}, {g} (first initial), {s}.'
    $suggested = if ($guess) { $guess.Format } elseif ($current) { $current } else { '{given}.{surname}' }
    $config.UpnFormat = Read-SetupValue -Prompt 'UpnFormat' -Suggested $suggested; $source.UpnFormat = 'chosen'
}
try { $null = Get-IamUpnPrefix -GivenName 'Jane' -Surname 'Doe' -Format $config.UpnFormat }
catch { throw "UpnFormat: $($_.Exception.Message) Nothing was written." }

# UsageLocation: the tenant's country.
if ("$($org.countryLetterCode)" -match '^[A-Za-z]{2}$') {
    $config.UsageLocation = "$($org.countryLetterCode)".ToUpperInvariant(); $source.UsageLocation = 'found'
}
else {
    $suggested = if (Get-SetupCurrent -Key UsageLocation) { $existing.UsageLocation } else { 'GB' }
    $config.UsageLocation = (Read-SetupValue -Prompt 'UsageLocation (two-letter country code)' -Suggested $suggested).ToUpperInvariant()
    $source.UsageLocation = 'chosen'
}

# LicenseSkuPartNumber: user licences that are enabled.
$skus = @(Invoke-IamGraphGetAll -Uri 'v1.0/subscribedSkus' |
        Where-Object { $_.appliesTo -eq 'User' -and $_.capabilityStatus -eq 'Enabled' } |
        Sort-Object -Property @{ Expression = { $_.skuPartNumber } })
$noLicence = '(none: group-based licensing, run the joiners with -SkipLicense)'
$current = Get-SetupCurrent -Key LicenseSkuPartNumber
if ($skus.Count -gt 0) {
    Show-SetupHeading 'Licence the joiners assign (LicenseSkuPartNumber)'
    $skuNames = @($skus | ForEach-Object { "$($_.skuPartNumber)" }) + $noLicence
    $details = @($skus | ForEach-Object { "$($_.consumedUnits) of $($_.prepaidUnits.enabled) used" })
    $default = [Math]::Max(0, [array]::IndexOf($skuNames, "$current"))
    $picked = Read-SetupChoice -Prompt 'LicenseSkuPartNumber' -Option $skuNames -Detail $details -Default $default
    $config.LicenseSkuPartNumber = if ($picked -eq $noLicence) { '' } else { $picked }
    $source.LicenseSkuPartNumber = 'chosen'
}
else {
    Show-SetupLine 'No enabled user licences found.'
    $config.LicenseSkuPartNumber = "$current"; $source.LicenseSkuPartNumber = 'kept'
}

# StaleDays: policy, not data.
$suggested = if (Get-SetupCurrent -Key StaleDays) { "$($existing.StaleDays)" } else { '90' }
$days = 0
if (-not [int]::TryParse((Read-SetupValue -Prompt 'StaleDays (days without sign-in before an account is stale)' -Suggested $suggested), [ref]$days) -or $days -lt 1) {
    throw 'StaleDays must be a whole number above 0. Nothing was written.'
}
$config.StaleDays = $days; $source.StaleDays = 'chosen'

# AllowedDepartments: the departments in use. They must match the dynamic group rules exactly.
Show-SetupHeading 'Departments (AllowedDepartments)'
$inUse = @($users | Where-Object { "$($_.department)".Trim() } |
        Group-Object -Property { "$($_.department)".Trim() } | Sort-Object -Property Count -Descending)
$inUseNames = @($inUse | ForEach-Object { $_.Name })
if ($inUse.Count) { Show-SetupLine ('In use: ' + (($inUse | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')) }
else { Show-SetupLine 'No user has a department yet.' }
Show-SetupLine 'Keep only the names your dynamic groups key on.'
$suggestedDepts = if ($inUse.Count) { $inUseNames } else { @(Get-SetupCurrent -Key AllowedDepartments) }
$config.AllowedDepartments = Read-SetupList -Prompt 'AllowedDepartments' -Suggested $suggestedDepts
$source.AllowedDepartments = 'chosen'
$unused = @($config.AllowedDepartments | Where-Object { $inUseNames -notcontains $_ })
if ($unused.Count -and $inUse.Count) { Show-SetupLine "Not in use by any user yet: $($unused -join ', ')" }

# ReviewFallbackUpn: the signed-in admin unless the config already names someone.
$current = Get-SetupCurrent -Key ReviewFallbackUpn
$suggested = if ($current) { $current } else { "$($ctx.Account)" }
$config.ReviewFallbackUpn = Read-SetupValue -Prompt 'ReviewFallbackUpn (reviewer when a group has no owner)' -Suggested $suggested
$source.ReviewFallbackUpn = 'chosen'

# BreakGlassUpns: Global Administrators that no enabled Conditional Access policy covers.
Show-SetupHeading 'Emergency access accounts (BreakGlassUpns)'
$assignments = @(Invoke-IamGraphGetAll -Uri "v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&`$expand=principal")
$admins = @{}
foreach ($a in $assignments) {
    if ($a.principal.'@odata.type' -eq '#microsoft.graph.user') {
        $admins[$a.principal.id] = @{ id = $a.principal.id; userPrincipalName = $a.principal.userPrincipalName }
    }
}
$candidates = @()
try {
    $policies = @(Invoke-IamGraphGetAll -Uri 'v1.0/identity/conditionalAccess/policies')
    $groupIds = @{}
    foreach ($id in $admins.Keys) {
        $groupIds[$id] = @(Invoke-IamGraphGetAll -Uri "v1.0/users/$id/transitiveMemberOf/microsoft.graph.group?`$select=id" |
                ForEach-Object { $_.id })
    }
    $candidates = @(Get-IamBreakGlassCandidate -Admin @($admins.Values) -Policy $policies -GroupIdsByUserId $groupIds)
}
catch {
    Show-SetupLine "Could not read Conditional Access (needs Entra ID P1 and Policy.Read.All): $($_.Exception.Message)"
}
Show-SetupLine ('Global Administrators: ' + ((@($admins.Values | ForEach-Object { $_.userPrincipalName }) | Sort-Object) -join ', '))
if ($candidates.Count) { Show-SetupLine "Excluded from Conditional Access, likely break-glass: $($candidates -join ', ')" }
else { Show-SetupLine 'No Global Administrator is excluded from every Conditional Access policy that covers it.' }
$suggestedBg = if ($candidates.Count) { $candidates } else { @(Get-SetupCurrent -Key BreakGlassUpns) }
$config.BreakGlassUpns = Read-SetupList -Prompt 'BreakGlassUpns' -Suggested $suggestedBg
$source.BreakGlassUpns = if ($candidates.Count) { 'suggested, checked' } else { 'chosen' }
if (@($config.BreakGlassUpns).Count -eq 0) {
    Show-SetupLine 'WARNING: no break-glass accounts. The leavers and reports that need BreakGlassUpns will refuse to run.'
}

#endregion

#region AD and Entra Connect

$hybrid = (-not $SkipHybrid) -and [bool](Get-Module -ListAvailable -Name ActiveDirectory)
if (-not $hybrid) {
    $reason = if ($SkipHybrid) { '-SkipHybrid is set' } else { 'the ActiveDirectory module is not installed' }
    Show-SetupHeading 'Hybrid keys'
    Show-SetupLine "Skipped: $reason. The hybrid keys keep their current values."
    foreach ($k in $hybridKeys) {
        if ($existing.ContainsKey($k)) { $config[$k] = $existing[$k]; $source[$k] = 'kept' }
        else { $config[$k] = $example[$k]; $source[$k] = 'example' }
    }
}
else {
    Import-IamAdModule
    $ous = @(Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName)

    # DepartmentOUs: an OU with the same name as each department.
    Show-SetupHeading 'Department OUs (DepartmentOUs)'
    $currentMap = Get-SetupCurrent -Key DepartmentOUs
    $map = [ordered]@{}
    $noOu = @()
    foreach ($dept in $config.AllowedDepartments) {
        $hits = @($ous | Where-Object { $_.Name -eq $dept } | ForEach-Object { $_.DistinguishedName })
        $previous = if ($currentMap -and $currentMap.ContainsKey($dept)) { "$($currentMap[$dept])" } else { '' }
        if ($hits.Count -eq 1) { $map[$dept] = $hits[0] }
        elseif ($hits.Count -gt 1) {
            Show-SetupLine "More than one OU is named $dept."
            $map[$dept] = Read-SetupChoice -Prompt "OU for $dept" -Option $hits -Default ([Math]::Max(0, [array]::IndexOf($hits, $previous)))
        }
        elseif ($previous) { $map[$dept] = $previous }
        else { $noOu += $dept }
    }
    if ($noOu.Count) {
        Show-SetupLine "No OU named: $($noOu -join ', '). The hybrid joiner and mover refuse these departments until they are in DepartmentOUs."
    }
    foreach ($dept in $map.Keys) { Show-SetupLine "  $dept -> $($map[$dept])" }
    $config.DepartmentOUs = $map; $source.DepartmentOUs = 'found'

    # LeaversOU: an OU named like Leavers or Disabled.
    $previous = Get-SetupCurrent -Key LeaversOU
    $leaverOus = @($ous | Where-Object { $_.Name -like '*leaver*' -or $_.Name -like '*disabled*' } | ForEach-Object { $_.DistinguishedName })
    if ($leaverOus.Count -eq 1) { $config.LeaversOU = $leaverOus[0]; $source.LeaversOU = 'found' }
    elseif ($leaverOus.Count -gt 1) {
        Show-SetupHeading 'Leavers OU (LeaversOU)'
        $config.LeaversOU = Read-SetupChoice -Prompt 'LeaversOU' -Option $leaverOus -Default ([Math]::Max(0, [array]::IndexOf($leaverOus, "$previous")))
        $source.LeaversOU = 'chosen'
    }
    else {
        Show-SetupHeading 'Leavers OU (LeaversOU)'
        Show-SetupLine 'No OU named like Leavers or Disabled.'
        $config.LeaversOU = Read-SetupValue -Prompt 'LeaversOU (distinguished name)' -Suggested "$previous"
        $source.LeaversOU = 'typed'
    }
    if (@($ous | ForEach-Object { $_.DistinguishedName }) -notcontains $config.LeaversOU) {
        Show-SetupLine "WARNING: $($config.LeaversOU) does not exist in AD."
    }

    # EntraConnectServer: from the MSOL_ connector account, then checked over WinRM.
    $serverNames = @(Get-ADUser -Filter "SamAccountName -like 'MSOL_*'" -Properties Description |
            ForEach-Object { ConvertFrom-IamMsolDescription -Description $_.Description } |
            Where-Object { $_ } | Select-Object -Unique)
    $servers = @(foreach ($n in $serverNames) {
            $fqdn = $null
            try { $fqdn = (Get-ADComputer -Identity $n -Properties DNSHostName).DNSHostName }
            catch { Write-Verbose -Message "No AD computer named $n, using the name as found." }
            if ($fqdn) { $fqdn } else { $n }
        })
    $probe = @(foreach ($s in $servers) {
            try {
                $r = Invoke-Command -ComputerName $s -ErrorAction Stop -ScriptBlock {
                    Import-Module ADSync -ErrorAction Stop
                    $partitions = foreach ($connector in @(Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq 'AD' })) {
                        foreach ($p in @($connector.Partitions)) {
                            [pscustomobject]@{
                                Partition = $p.Name
                                Include   = @($p.ConnectorPartitionScope.ContainerInclusionList)
                                Exclude   = @($p.ConnectorPartitionScope.ContainerExclusionList)
                            }
                        }
                    }
                    [pscustomobject]@{ Staging = [bool](Get-ADSyncScheduler).StagingModeEnabled; Partitions = @($partitions) }
                }
                [pscustomobject]@{ Server = $s; Reachable = $true; Staging = $r.Staging; Partitions = @($r.Partitions); Error = '' }
            }
            catch {
                [pscustomobject]@{ Server = $s; Reachable = $false; Staging = $null; Partitions = @(); Error = $_.Exception.Message }
            }
        })
    $active = @($probe | Where-Object { $_.Reachable -and -not $_.Staging })
    $previous = Get-SetupCurrent -Key EntraConnectServer
    if ($active.Count -eq 1) {
        $config.EntraConnectServer = $active[0].Server; $source.EntraConnectServer = 'found'
    }
    else {
        Show-SetupHeading 'Entra Connect server (EntraConnectServer)'
        if ($probe.Count) {
            $details = @($probe | ForEach-Object {
                    if (-not $_.Reachable) { "not reachable: $($_.Error)" } elseif ($_.Staging) { 'staging mode' } else { 'active' }
                })
            $options = @($probe | ForEach-Object { $_.Server })
            $config.EntraConnectServer = Read-SetupChoice -Prompt 'EntraConnectServer' -Option $options -Detail $details -Default ([Math]::Max(0, [array]::IndexOf($options, "$previous")))
            $source.EntraConnectServer = 'chosen'
        }
        else {
            Show-SetupLine 'No MSOL_ account with a server name in its description.'
            $config.EntraConnectServer = Read-SetupValue -Prompt 'EntraConnectServer (FQDN)' -Suggested "$previous"
            $source.EntraConnectServer = 'typed'
        }
    }

    # LeaversOUInSyncScope: read from the server's OU filtering. $true needs a yes.
    Show-SetupHeading 'Leavers OU sync scope (LeaversOUInSyncScope)'
    $scope = $probe | Where-Object { $_.Server -eq $config.EntraConnectServer -and $_.Reachable } | Select-Object -First 1
    $include = @($scope.Partitions | ForEach-Object { $_.Include } | Where-Object { $_ })
    $exclude = @($scope.Partitions | ForEach-Object { $_.Exclude } | Where-Object { $_ })
    if ($scope -and $include.Count) {
        $inScope = Test-IamOuInSyncScope -DistinguishedName $config.LeaversOU -Inclusion $include -Exclusion $exclude
        if ($inScope) {
            Show-SetupLine "$($config.LeaversOU) is inside the OU filtering scope on $($config.EntraConnectServer)."
            $config.LeaversOUInSyncScope = Read-SetupYesNo -Prompt 'Set LeaversOUInSyncScope to $true (lets the hybrid leaver use -ConvertMailbox)?' -Default $true
            $source.LeaversOUInSyncScope = 'found, confirmed'
        }
        else {
            Show-SetupLine "$($config.LeaversOU) is OUTSIDE the sync scope: the sync deletes a leaver's cloud account and soft-deletes the mailbox."
            $config.LeaversOUInSyncScope = $false; $source.LeaversOUInSyncScope = 'found'
        }
        foreach ($dept in $map.Keys) {
            if (-not (Test-IamOuInSyncScope -DistinguishedName $map[$dept] -Inclusion $include -Exclusion $exclude)) {
                Show-SetupLine "WARNING: the $dept OU is outside the sync scope. Moving a user into it deletes their cloud account."
            }
        }
    }
    else {
        Show-SetupLine 'Could not read the OU filtering scope. Check it by hand: README > Check the Leavers OU sync scope first.'
        $config.LeaversOUInSyncScope = $existing.LeaversOUInSyncScope -eq $true; $source.LeaversOUInSyncScope = 'kept'
    }

    # ProtectedAdGroups: policy, checked against AD.
    $current = Get-SetupCurrent -Key ProtectedAdGroups
    $suggestedGroups = if ($current) { @($current) } else { @('Domain Users') }
    $config.ProtectedAdGroups = Read-SetupList -Prompt 'ProtectedAdGroups (AD groups the leaver never removes)' -Suggested $suggestedGroups
    $source.ProtectedAdGroups = 'chosen'
    foreach ($g in $config.ProtectedAdGroups) {
        try { $null = Get-ADGroup -Identity $g } catch { Show-SetupLine "WARNING: AD group '$g' not found." }
    }
}

#endregion

# Keys this script does not know stay as they were.
foreach ($k in $existing.Keys) {
    if (-not $config.Contains($k)) { $config[$k] = $existing[$k]; $source[$k] = 'kept' }
}

$comment = @{
    TenantId             = 'Notes for every key: config.example.psd1 and the README config reference.'
    DefaultDomain        = 'Verified domain new users are created in.'
    UpnFormat            = 'Tokens: {given}, {surname}, {g} (first initial), {s}.'
    LicenseSkuPartNumber = 'Empty: run the joiners with -SkipLicense (group-based licensing).'
    BreakGlassUpns       = 'Emergency access accounts. The leavers refuse to touch them.'
    AllowedDepartments   = 'Exact department names your dynamic groups key on.'
    DepartmentOUs        = '---- Hybrid scripts only ----'
    LeaversOUInSyncScope = '$true only when LeaversOU is inside the Entra Connect sync scope.'
}
$header = "# Written by Setup\New-IamConfig.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm'). Never commit this file."
$text = $header + [Environment]::NewLine + (ConvertTo-IamConfigText -Config $config -Comment $comment)

Show-SetupHeading 'Result'
$summary = foreach ($k in $config.Keys) {
    [pscustomobject]@{ Key = $k; Source = $source[$k]; Value = (Format-SetupValue -Value $config[$k]) }
}
Show-SetupLine ($summary | Format-Table -AutoSize -Wrap | Out-String)

if ($PSCmdlet.ShouldProcess($Path, 'Write config')) {
    $backup = $null
    if (Test-Path -Path $Path) {
        $backup = '{0}.{1}.bak' -f $Path, (Get-Date -Format 'yyyyMMdd-HHmmss')
        Copy-Item -Path $Path -Destination $backup
    }
    try {
        Set-Content -Path $Path -Value $text -Encoding utf8
        $null = Import-PowerShellDataFile -Path $Path
    }
    catch {
        if ($backup) { Copy-Item -Path $backup -Destination $Path -Force }
        throw "Writing $Path failed, the previous file is back in place: $($_.Exception.Message)"
    }
    $by = $source.Values | ForEach-Object { ("$_" -split '[ ,]')[0] } | Group-Object | ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-IamLog -Message "Config written to $Path (backup: $(if ($backup) { $backup } else { 'none' })). Keys by source: $($by -join ', ')"
    Show-SetupLine 'Next: run a read-only report to prove sign-in and consent, e.g. .\Reports\Get-RiskyAppPermissions.ps1'
}
else {
    Show-SetupLine 'Nothing written. This is the file it would write:'
    Show-SetupLine $text
}
