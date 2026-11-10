<#
.SYNOPSIS
    Starts an access review campaign: one CSV per reviewer listing who is in the groups they own,
    with a Decision column (Keep or Revoke) to fill in.

.DESCRIPTION
    For each group in scope, the reviewer is the group's first enabled user owner. Groups with
    no enabled owner go to ReviewFallbackUpn from config, and so do rows where the owner would
    be reviewing their own membership (nobody approves their own access).

    Rows are flagged to help the reviewer decide:
      - Disabled account, Guest, Non-user member, Nested group
      - External account (user type Member): an #EXT# account that a guest-only review would miss,
        such as the personal account that created the tenant
      - Outside the group's main department: the member's department differs from the one
        at least half the group's users share (groups of 3 users or more)
      - No sign-in for N days / Never signed in (with -IncludeSignIn, needs Entra ID P1)
      - Expected (break-glass)
    A Keep on a flagged row needs a Reason. Invoke-AccessReviewDecisions.ps1 enforces it.

    Skipped: dynamic groups (membership follows an attribute, so the fix for a wrong member is
    the mover or HR data, not a removal) and distribution groups (no access attached).
    Listed but marked for manual action: role-assignable groups, groups synced from AD and
    mail-enabled security groups. Graph cannot change their membership through this path.

    Output, in output\AccessReview-<Campaign>\:
      _master.csv          every row; the decisions script checks returned files against it.
                           Do not send it out or edit it.
      <reviewer-upn>.csv   one per reviewer. Send it, and save the returned copy over it.

    Read-only. Graph scopes (delegated): GroupMember.Read.All, User.Read.All
      plus AuditLog.Read.All with -IncludeSignIn

.PARAMETER GroupName
    Exact display names of the groups to review.

.PARAMETER AllAssignedGroups
    Review every assigned security and Microsoft 365 group in the tenant.

.PARAMETER Campaign
    Campaign name, used for the folder. Letters, digits, dot, hyphen, underscore.
    Default: AR-<yyyyMMdd>.

.PARAMETER IncludeSignIn
    Add each user's last sign-in and flag inactive accounts. Needs Entra ID P1.

.PARAMETER InactiveDays
    Days without sign-in before a row is flagged. Default: StaleDays in config.

.EXAMPLE
    .\Governance\Get-AccessReviewExtract.ps1 -GroupName 'Finance Share', 'Payroll App' -Campaign Q4-2026
.EXAMPLE
    .\Governance\Get-AccessReviewExtract.ps1 -AllAssignedGroups -IncludeSignIn -Campaign Q4-2026
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName')][string[]]$GroupName,
    [Parameter(Mandatory, ParameterSetName = 'All')][switch]$AllAssignedGroups,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$')][string]$Campaign = ('AR-{0:yyyyMMdd}' -f (Get-Date)),
    [switch]$IncludeSignIn,
    [ValidateRange(1, 730)][int]$InactiveDays
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$required = @('BreakGlassUpns', 'ReviewFallbackUpn')
if ($IncludeSignIn -and -not $PSBoundParameters.ContainsKey('InactiveDays')) { $required += 'StaleDays' }
$cfg = Import-IamConfig -Require $required
if ($IncludeSignIn -and -not $PSBoundParameters.ContainsKey('InactiveDays')) { $InactiveDays = $cfg.StaleDays }
$breakGlass = @($cfg.BreakGlassUpns)
$fallback = "$($cfg.ReviewFallbackUpn)".Trim()

$folder = Get-IamOutputFolder -Name "AccessReview-$Campaign"
$masterPath = Join-Path -Path $folder -ChildPath '_master.csv'
if (Test-Path -Path $masterPath) {
    throw "Campaign $Campaign already has an extract in $folder. Use a new -Campaign name, or delete that folder first."
}

$scopes = @('GroupMember.Read.All', 'User.Read.All')
if ($IncludeSignIn) { $scopes += 'AuditLog.Read.All' }
Connect-IamGraph -TenantId $cfg.TenantId -Scopes $scopes

# The fallback reviewer gets every ownerless group, so check it before doing anything else.
$fb = $null
try { $fb = Get-MgUser -UserId $fallback -Property Id, UserPrincipalName, AccountEnabled -ErrorAction Stop } catch { $fb = $null }
if (-not $fb) { throw "ReviewFallbackUpn $fallback not found in Entra ID." }
if (-not $fb.AccountEnabled) { throw "ReviewFallbackUpn $fallback is disabled. Set an active reviewer in config.local.psd1." }

# ---- Groups in scope ----
$groupSelect = '$select=id,displayName,groupTypes,securityEnabled,mailEnabled,isAssignableToRole,onPremisesSyncEnabled'
$candidates = @()
if (-not $AllAssignedGroups) {
    foreach ($name in $GroupName) {
        # OData escapes a quote by doubling it. URL-encode the rest, so '&' or '#' in a name cannot break the query.
        $escaped = [uri]::EscapeDataString($name.Trim().Replace("'", "''"))
        $found = @(Invoke-IamGraphGetAll -Uri "v1.0/groups?`$filter=displayName eq '$escaped'&$groupSelect")
        if ($found.Count -eq 0) { throw "Group '$name' not found. Names must match exactly. Nothing was written." }
        if ($found.Count -gt 1) { throw "$($found.Count) groups are called '$name'. Rename one, then rerun. Nothing was written." }
        $candidates += $found[0]
    }
}
else {
    $candidates = @(Invoke-IamGraphGetAll -Uri "v1.0/groups?$groupSelect")
}

$groups = @()
foreach ($g in $candidates) {
    $isUnified = @($g.groupTypes) -contains 'Unified'
    if (@($g.groupTypes) -contains 'DynamicMembership') {
        if (-not $AllAssignedGroups) { Write-IamLog -Level WARN -Message "Skipped $($g.displayName): dynamic group. Review the attribute it is based on instead." }
        continue
    }
    if (-not $g.securityEnabled -and -not $isUnified) {
        if (-not $AllAssignedGroups) { Write-IamLog -Level WARN -Message "Skipped $($g.displayName): distribution group, no access attached." }
        continue
    }
    $manualReason = ''
    if ($g.isAssignableToRole -eq $true) { $manualReason = 'Role-assignable group: remove by hand (Privileged Role Administrator)' }
    elseif ($g.onPremisesSyncEnabled -eq $true) { $manualReason = 'Group synced from AD: remove in AD' }
    elseif ($g.mailEnabled -eq $true -and -not $isUnified) { $manualReason = 'Mail-enabled security group: remove in Exchange' }
    $groups += [pscustomobject]@{ Id = $g.id; Name = $g.displayName; ManualReason = $manualReason }
}
if ($groups.Count -eq 0) { throw 'No reviewable groups in scope. Nothing was written.' }

# ---- Sign-in data (optional) ----
$signIns = @{}
$now = (Get-Date).ToUniversalTime()
if ($IncludeSignIn) {
    $cutoff = $now.AddDays(-$InactiveDays)
    try { $all = Get-MgUser -All -Property Id, CreatedDateTime, SignInActivity -ErrorAction Stop }
    catch {
        if ($_.Exception.Message -match 'NonPremiumTenant|premium license') { throw '-IncludeSignIn needs Entra ID P1 or P2. Rerun without it.' }
        throw
    }
    foreach ($u in $all) {
        $s = $u.SignInActivity
        $last = @($s.LastSignInDateTime, $s.LastNonInteractiveSignInDateTime, $s.LastSuccessfulSignInDateTime) |
            Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        $signIns[$u.Id] = [pscustomobject]@{ Last = $last; Created = $u.CreatedDateTime }
    }
}

# ---- Rows ----
$memberSelect = '$select=id,displayName,userPrincipalName,accountEnabled,department,jobTitle,userType'
$ownerSelect = '$select=id,userPrincipalName,accountEnabled'
$extractedAt = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
$rows = [System.Collections.Generic.List[object]]::new()
$ownerless = @()
$n = 0

foreach ($g in $groups) {
    $owners = @(Invoke-IamGraphGetAll -Uri "v1.0/groups/$($g.Id)/owners?$ownerSelect" |
            Where-Object { $_.userPrincipalName -and $_.accountEnabled -eq $true } |
            Sort-Object -Property @{ Expression = { $_.userPrincipalName } })
    # Graph returns hashtables here: sort and group with script blocks, not property names.
    $ownerUpns = @($owners | ForEach-Object { $_.userPrincipalName })
    $groupReviewer = if ($ownerUpns.Count) { $ownerUpns[0] } else { $fallback }
    if (-not $ownerUpns.Count) { $ownerless += $g.Name }

    $members = @(Invoke-IamGraphGetAll -Uri "v1.0/groups/$($g.Id)/members?$memberSelect")
    if ($members.Count -eq 0) { Write-IamLog -Message "No members: $($g.Name)"; continue }

    $users = @($members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' })
    $mainDept = $null
    $byDept = @($users | Where-Object { "$($_.department)".Trim() } | Group-Object -Property { $_.department } | Sort-Object -Property Count -Descending)
    if ($users.Count -ge 3 -and $byDept.Count -and ($byDept[0].Count / $users.Count) -ge 0.5) { $mainDept = $byDept[0].Name }

    foreach ($m in $members) {
        $n++
        $type = "$($m.'@odata.type')" -replace '^#microsoft\.graph\.', ''
        $flags = @()
        $reviewer = $groupReviewer
        $lastSignIn = $null

        if ($type -eq 'user') {
            if ($m.userPrincipalName -and $breakGlass -contains $m.userPrincipalName) { $flags += 'Expected (break-glass)' }
            if ($m.accountEnabled -ne $true) { $flags += 'Disabled account' }
            if ($m.userType -eq 'Guest') { $flags += 'Guest' }
            elseif ("$($m.userPrincipalName)" -like '*#EXT#*') { $flags += 'External account (user type Member)' }
            if ($mainDept -and "$($m.department)".Trim() -ne $mainDept) {
                $flags += "Outside the group's main department ($mainDept)"
            }
            if ($IncludeSignIn -and $signIns.ContainsKey($m.id)) {
                $si = $signIns[$m.id]
                $lastSignIn = $si.Last
                if (-not $si.Last -and $si.Created -and $si.Created -lt $cutoff) { $flags += 'Never signed in' }
                elseif ($si.Last -and $si.Last -lt $cutoff) { $flags += "No sign-in for $([math]::Floor(($now - $si.Last).TotalDays)) days" }
            }
            if ($m.userPrincipalName -and $m.userPrincipalName -eq $groupReviewer) {
                $reviewer = $fallback
                $flags += 'Owner is the member: sent to the fallback reviewer'
                if ($m.userPrincipalName -eq $fallback) { $flags += 'Fallback reviewer is the member: needs a second reviewer' }
            }
        }
        elseif ($type -eq 'group') { $flags += 'Nested group: review its members separately' }
        else { $flags += "Non-user member ($type)" }

        $rows.Add([pscustomobject]@{
                ReviewId     = 'R{0:D5}' -f $n
                Group        = $g.Name
                Member       = if ($m.userPrincipalName) { $m.userPrincipalName } else { $m.displayName }
                DisplayName  = $m.displayName
                MemberType   = $type
                Department   = $m.department
                JobTitle     = $m.jobTitle
                Enabled      = $m.accountEnabled
                LastSignIn   = $lastSignIn
                Flags        = $flags -join '; '
                Decision     = ''
                Reason       = ''
                GroupId      = $g.Id
                MemberId     = $m.id
                Reviewer     = $reviewer
                Owners       = ($ownerUpns -join '; ')
                ManualReason = $g.ManualReason
                Campaign     = $Campaign
                ExtractedAt  = $extractedAt
            })
    }
}
if ($rows.Count -eq 0) { throw 'The groups in scope have no members. Nothing was written.' }

# ---- Write files ----
Export-IamCsv -InputObject $rows -Path $masterPath
$reviewerColumns = 'ReviewId', 'Group', 'Member', 'DisplayName', 'MemberType', 'Department', 'JobTitle', 'Enabled',
'LastSignIn', 'Flags', 'Decision', 'Reason', 'GroupId', 'MemberId'
$perReviewer = @($rows | Group-Object -Property Reviewer | Sort-Object -Property Name)
foreach ($r in $perReviewer) {
    $path = Join-Path -Path $folder -ChildPath "$($r.Name).csv"
    Export-IamCsv -InputObject @($r.Group | Select-Object -Property $reviewerColumns) -Path $path
}

$flagged = @($rows | Where-Object { $_.Flags -and $_.Flags -ne 'Expected (break-glass)' }).Count
$manualGroups = @($groups | Where-Object { $_.ManualReason }).Count
foreach ($o in $ownerless) { Write-IamLog -Level WARN -Message "No enabled owner, sent to ${fallback}: $o" }
Write-IamLog -Message ("Access review $Campaign extracted: $($groups.Count) group(s), $($rows.Count) row(s), $flagged flagged, " +
    "$($perReviewer.Count) reviewer(s), $($ownerless.Count) group(s) with no owner, $manualGroups for manual removal. Folder: $folder")

$perReviewer | ForEach-Object {
    [pscustomobject]@{
        Reviewer = $_.Name
        Rows     = $_.Count
        Flagged  = @($_.Group | Where-Object { $_.Flags -and $_.Flags -ne 'Expected (break-glass)' }).Count
        File     = "$($_.Name).csv"
    }
} | Format-Table -AutoSize
