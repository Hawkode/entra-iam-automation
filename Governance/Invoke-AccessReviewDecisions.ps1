<#
.SYNOPSIS
    Checks the returned access review files, then removes the memberships reviewers marked Revoke,
    and writes the evidence for the campaign.

.DESCRIPTION
    Reads output\AccessReview-<Campaign>\: _master.csv from Get-AccessReviewExtract.ps1, and every
    <reviewer-upn>.csv saved back by the reviewers.

    Validate first, offline, before signing in. One problem and nothing changes:
      - every row must exist in _master.csv, in the file of the reviewer it was sent to,
        with its GroupId and MemberId unchanged, and appear only once
      - Decision must be Keep, Revoke or empty (empty = not reviewed)
      - Keep on a flagged row needs a Reason (break-glass rows excepted)
      - the extract must be no older than -MaxExtractAgeDays (default 30)
    Problems go to _validation-<timestamp>.csv.

    Then: re-reads current membership, lists the plan, asks for confirmation once and removes
    each Revoke. Already gone counts as done, so a rerun after a failure is safe.

    Not removed, listed for manual action instead:
      - rows in role-assignable, AD-synced or mail-enabled security groups
      - break-glass accounts, and the signed-in admin's own access
    Unreviewed rows are never removed automatically: they are reported for follow-up.

    The script records which file each decision came from. It cannot prove who edited that
    file: keep the reviewer's reply (email or ticket) as the proof of who decided.

    Evidence, in the campaign folder:
      _evidence-<timestamp>.csv  every row: decision, reason, outcome, ticket, applied by, when
      _summary-<timestamp>.csv   completion and outcomes per reviewer, plus a total row

    Graph scopes (delegated): GroupMember.ReadWrite.All
    Role: Groups Administrator or User Administrator (or owner of every group in scope).

.PARAMETER Campaign
    Campaign name used with Get-AccessReviewExtract.ps1.

.PARAMETER Ticket
    Change or ticket reference, written to the evidence.

.PARAMETER StatusOnly
    Validate and report completion per reviewer. No sign-in, no changes. Use it to chase reviewers.

.PARAMETER MaxExtractAgeDays
    Refuse an extract older than this. Default 30.

.EXAMPLE
    .\Governance\Invoke-AccessReviewDecisions.ps1 -Campaign Q4-2026 -StatusOnly
.EXAMPLE
    .\Governance\Invoke-AccessReviewDecisions.ps1 -Campaign Q4-2026 -Ticket CHG12345 -WhatIf
.EXAMPLE
    .\Governance\Invoke-AccessReviewDecisions.ps1 -Campaign Q4-2026 -Ticket CHG12345
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Apply')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$')][string]$Campaign,
    [Parameter(Mandatory, ParameterSetName = 'Apply')][ValidateNotNullOrEmpty()][string]$Ticket,
    [Parameter(Mandatory, ParameterSetName = 'Status')][switch]$StatusOnly,
    [ValidateRange(1, 90)][int]$MaxExtractAgeDays = 30
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

$cfg = Import-IamConfig -Require BreakGlassUpns
$breakGlass = @($cfg.BreakGlassUpns)

$folder = Get-IamOutputFolder -Name "AccessReview-$Campaign"
$masterPath = Join-Path -Path $folder -ChildPath '_master.csv'
if (-not (Test-Path -Path $masterPath)) { throw "No extract for campaign $Campaign in $folder. Run Get-AccessReviewExtract.ps1 first." }
$stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)

# ---- Master ----
$master = @(Import-Csv -Path $masterPath)
$byId = @{}
foreach ($m in $master) {
    if ($byId.ContainsKey($m.ReviewId)) { throw "_master.csv has ReviewId $($m.ReviewId) twice. It was edited: run a new extract." }
    $byId[$m.ReviewId] = $m
}
$extractedAt = [datetime]::Parse($master[0].ExtractedAt, [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AdjustToUniversal)
$age = ((Get-Date).ToUniversalTime() - $extractedAt).TotalDays
if ($age -gt $MaxExtractAgeDays) {
    throw ("The extract is $([math]::Floor($age)) days old (limit $MaxExtractAgeDays). Access has changed since: " +
        'run a new extract and send it out again. Nothing changed.')
}

# ---- Returned files: validate offline ----
$problems = [System.Collections.Generic.List[object]]::new()
$decided = @{}
$seenIn = @{}
$files = @(Get-ChildItem -Path $folder -Filter '*.csv' -File | Where-Object { $_.Name -notlike '_*' })
$needed = 'ReviewId', 'Decision', 'Reason', 'GroupId', 'MemberId'

foreach ($f in $files) {
    $reviewer = $f.BaseName
    $content = @(Import-Csv -Path $f.FullName)
    $columns = if ($content.Count) { @($content[0].PSObject.Properties.Name) } else { @() }
    $missing = @($needed | Where-Object { $columns -notcontains $_ })
    if ($content.Count -and $missing.Count) {
        $problems.Add([pscustomobject]@{ File = $f.Name; ReviewId = ''; Problem = "Missing column(s): $($missing -join ', ')" })
        continue
    }
    foreach ($row in $content) {
        $id = "$($row.ReviewId)".Trim()
        $decision = "$($row.Decision)".Trim()
        $reason = "$($row.Reason)".Trim()
        if (-not $id -and -not $decision -and -not $reason) { continue }   # blank line left by Excel
        $add = { param($p) $problems.Add([pscustomobject]@{ File = $f.Name; ReviewId = $id; Problem = $p }) }

        if (-not $byId.ContainsKey($id)) { & $add 'Row is not in the extract (added or ReviewId changed)'; continue }
        $m = $byId[$id]
        if ($m.Reviewer -ne $reviewer) { & $add "Row belongs to $($m.Reviewer)'s file"; continue }
        if ("$($row.GroupId)".Trim() -ne $m.GroupId -or "$($row.MemberId)".Trim() -ne $m.MemberId) {
            & $add 'GroupId or MemberId was edited'; continue
        }
        if ($seenIn.ContainsKey($id)) { & $add "Row appears twice (also in $($seenIn[$id]))"; continue }
        $seenIn[$id] = $f.Name

        switch -Regex ($decision) {
            '^$' { $decision = ''; break }
            '^keep$' { $decision = 'Keep'; break }
            '^revoke$' { $decision = 'Revoke'; break }
            default { & $add "Decision '$decision' is not Keep, Revoke or empty"; $decision = $null }
        }
        if ($null -eq $decision) { continue }
        $needsReason = $m.Flags -and $m.Flags -ne 'Expected (break-glass)'
        if ($decision -eq 'Keep' -and $needsReason -and -not $reason) {
            & $add "Keep on a flagged row needs a Reason ($($m.Flags))"; continue
        }
        if ($decision) { $decided[$id] = [pscustomobject]@{ Decision = $decision; Reason = $reason; File = $f.Name } }
    }
}

$returned = @($files | ForEach-Object { $_.BaseName })
foreach ($r in @($master | ForEach-Object { $_.Reviewer } | Sort-Object -Unique)) {
    if ($returned -notcontains $r) { Write-IamLog -Level WARN -Message "No file for reviewer $r in $folder. Their rows count as not reviewed." }
}

if ($problems.Count) {
    $vPath = Join-Path -Path $folder -ChildPath "_validation-$stamp.csv"
    Export-IamCsv -InputObject $problems -Path $vPath
    $problems | Format-Table -AutoSize -Wrap
    throw "$($problems.Count) problem(s) in the returned files. Nothing changed. Fix them with the reviewer, then rerun. List: $vPath"
}

# ---- Summary helper ----
function Get-ReviewSummary {
    param([object[]]$Rows)
    $lines = foreach ($grp in @($Rows | Group-Object -Property Reviewer | Sort-Object -Property Name)) {
        $total = $grp.Count
        $done = @($grp.Group | Where-Object { $_.Decision }).Count
        [pscustomobject]@{
            Reviewer    = $grp.Name
            Rows        = $total
            Reviewed    = $done
            Complete    = '{0:P0}' -f ($done / $total)
            Keep        = @($grp.Group | Where-Object { $_.Decision -eq 'Keep' }).Count
            Revoke      = @($grp.Group | Where-Object { $_.Decision -eq 'Revoke' }).Count
            Removed     = @($grp.Group | Where-Object { $_.Outcome -eq 'Removed' -or $_.Outcome -like 'Already removed*' }).Count
            Manual      = @($grp.Group | Where-Object { $_.Outcome -like 'Manual:*' }).Count
            Failed      = @($grp.Group | Where-Object { $_.Outcome -like 'Failed:*' }).Count
            NotReviewed = $total - $done
        }
    }
    $lines = @($lines)
    $all = @($Rows).Count
    $allDone = @($Rows | Where-Object { $_.Decision }).Count
    $lines + [pscustomobject]@{
        Reviewer    = 'TOTAL'
        Rows        = $all
        Reviewed    = $allDone
        Complete    = '{0:P0}' -f ($allDone / [math]::Max($all, 1))
        Keep        = ($lines | Measure-Object -Property Keep -Sum).Sum
        Revoke      = ($lines | Measure-Object -Property Revoke -Sum).Sum
        Removed     = ($lines | Measure-Object -Property Removed -Sum).Sum
        Manual      = ($lines | Measure-Object -Property Manual -Sum).Sum
        Failed      = ($lines | Measure-Object -Property Failed -Sum).Sum
        NotReviewed = $all - $allDone
    }
}

$rows = foreach ($m in $master) {
    $d = $decided[$m.ReviewId]
    [pscustomobject]@{
        ReviewId     = $m.ReviewId
        Group        = $m.Group
        Member       = $m.Member
        MemberType   = $m.MemberType
        Flags        = $m.Flags
        Reviewer     = $m.Reviewer
        Decision     = if ($d) { $d.Decision } else { '' }
        Reason       = if ($d) { $d.Reason } else { '' }
        DecisionFile = if ($d) { $d.File } else { '' }
        Outcome      = if (-not $d) { 'Not reviewed' } elseif ($d.Decision -eq 'Keep') { 'Kept' } else { 'Pending' }
        GroupId      = $m.GroupId
        MemberId     = $m.MemberId
        ManualReason = $m.ManualReason
        Ticket       = $Ticket
        AppliedBy    = ''
        AppliedAt    = ''
    }
}
$rows = @($rows)

if ($StatusOnly) {
    $summary = @(Get-ReviewSummary -Rows $rows)
    Export-IamCsv -InputObject $summary -Path (Join-Path -Path $folder -ChildPath "_status-$stamp.csv")
    $total = $summary[-1]
    Write-IamLog -Message "Access review $Campaign status: $($total.Reviewed) of $($total.Rows) rows reviewed ($($total.Complete)). Files valid."
    $summary | Format-Table Reviewer, Rows, Reviewed, Complete, Keep, Revoke, NotReviewed -AutoSize
    return
}

# ---- Plan ----
Connect-IamGraph -TenantId $cfg.TenantId -Scopes 'GroupMember.ReadWrite.All'
$me = (Get-MgContext).Account

$toRevoke = @($rows | Where-Object { $_.Decision -eq 'Revoke' })
foreach ($r in $toRevoke) {
    if ($r.ManualReason) { $r.Outcome = "Manual: $($r.ManualReason)" }
    elseif ($breakGlass -contains $r.Member) { $r.Outcome = 'Manual: break-glass account, check the emergency access process before removing' }
    elseif ($r.Member -eq $me) { $r.Outcome = 'Manual: your own access, ask another admin' }
}

$current = @{}
foreach ($gid in @($toRevoke | Where-Object { $_.Outcome -eq 'Pending' } | ForEach-Object { $_.GroupId } | Sort-Object -Unique)) {
    try { $current[$gid] = @(Invoke-IamGraphGetAll -Uri "v1.0/groups/$gid/members?`$select=id" | ForEach-Object { $_.id }) }
    catch {
        if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist|NotFound|404') { $current[$gid] = $null }
        else { throw }
    }
}
foreach ($r in @($toRevoke | Where-Object { $_.Outcome -eq 'Pending' })) {
    if (-not $current.ContainsKey($r.GroupId) -or $null -eq $current[$r.GroupId]) { $r.Outcome = 'Already removed (group no longer exists)' }
    elseif ($current[$r.GroupId] -notcontains $r.MemberId) { $r.Outcome = 'Already removed' }
}

$pending = @($toRevoke | Where-Object { $_.Outcome -eq 'Pending' })
$manual = @($toRevoke | Where-Object { $_.Outcome -like 'Manual:*' })
$notReviewed = @($rows | Where-Object { $_.Outcome -eq 'Not reviewed' }).Count
$planText = "remove $($pending.Count) membership(s)"
if ($pending.Count) { $planText += ': ' + (($pending | ForEach-Object { "$($_.Member) from $($_.Group)" }) -join '; ') }

Write-IamLog -Message "Access review $Campaign plan ($Ticket): $planText. Kept: $(@($rows | Where-Object Outcome -EQ 'Kept').Count). Not reviewed: $notReviewed."
foreach ($r in $manual) { Write-IamLog -Level WARN -Message "Manual follow-up: $($r.Member) in $($r.Group). $($r.Outcome)" }

if ($pending.Count -and -not $PSCmdlet.ShouldProcess("Access review $Campaign", $planText)) { return }
if ($WhatIfPreference) { return }   # -WhatIf with nothing to remove: still no evidence, nothing was applied

# ---- Execute ----
foreach ($r in $pending) {
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "v1.0/groups/$($r.GroupId)/members/$($r.MemberId)/`$ref" -ErrorAction Stop | Out-Null
        $r.Outcome = 'Removed'
        Write-IamLog -Message "Access review ${Campaign}: removed $($r.Member) from $($r.Group) ($Ticket)"
    }
    catch {
        if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist|NotFound|404') { $r.Outcome = 'Already removed' }
        else {
            $r.Outcome = "Failed: $($_.Exception.Message)"
            Write-IamLog -Level ERROR -Message "Could not remove $($r.Member) from $($r.Group): $($_.Exception.Message)"
        }
    }
}

$appliedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
foreach ($r in $rows) { $r.AppliedBy = $me; $r.AppliedAt = $appliedAt }

$evidence = Join-Path -Path $folder -ChildPath "_evidence-$stamp.csv"
Export-IamCsv -InputObject $rows -Path $evidence
$summary = @(Get-ReviewSummary -Rows $rows)
Export-IamCsv -InputObject $summary -Path (Join-Path -Path $folder -ChildPath "_summary-$stamp.csv")

$t = $summary[-1]
Write-IamLog -Message ("Access review $Campaign applied ($Ticket): $($t.Reviewed) of $($t.Rows) reviewed ($($t.Complete)), " +
    "$($t.Keep) kept, $($t.Removed) removed, $($t.Manual) manual, $($t.Failed) failed, $($t.NotReviewed) not reviewed. Evidence: $evidence")
if ($t.NotReviewed) { Write-IamLog -Level WARN -Message "$($t.NotReviewed) row(s) not reviewed. Chase the reviewers below; unreviewed access is not removed automatically." }
$summary | Format-Table Reviewer, Rows, Reviewed, Complete, Keep, Removed, Manual, Failed, NotReviewed -AutoSize
