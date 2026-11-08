# Shared functions for the Cloud, Hybrid and Reports scripts.
# Requires: Install-Module Microsoft.Graph -Scope CurrentUser

$script:RepoRoot = Split-Path -Path $PSScriptRoot -Parent

function Write-IamLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $outDir = Join-Path -Path $script:RepoRoot -ChildPath 'output'
    if (-not (Test-Path -Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force -WhatIf:$false | Out-Null }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Add-Content -Path (Join-Path -Path $outDir -ChildPath 'iam-automation.log') -Value $line -WhatIf:$false
    Write-Information -MessageData $line -InformationAction Continue
}

function Import-IamConfig {
    <#
    .SYNOPSIS
        Loads config.local.psd1 and stops early if it is not filled in.
    .DESCRIPTION
        Always checks TenantId. Each script passes the other keys it needs with -Require.
        A required key fails if it is missing, empty, or still holds an example value
        (anything containing "contoso"), so a half-edited copy of config.example.psd1
        never reaches a tenant.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Require = @(),
        [string]$Path = (Join-Path -Path $script:RepoRoot -ChildPath 'config.local.psd1')
    )
    if (-not (Test-Path -Path $Path)) {
        throw "Config not found: $Path. Copy config.example.psd1 to config.local.psd1 and fill it in."
    }
    $cfg = Import-PowerShellDataFile -Path $Path

    $problems = @()
    $tenant = [guid]::Empty
    if (-not [guid]::TryParse("$($cfg.TenantId)", [ref]$tenant) -or $tenant -eq [guid]::Empty) {
        $problems += 'TenantId must be your tenant ID (Entra admin center > Overview > Tenant ID).'
    }
    foreach ($key in $Require) {
        $raw = $cfg[$key]
        if ($raw -is [System.Collections.IDictionary]) { $raw = @($raw.Values) }
        $values = @($raw | Where-Object { "$_".Trim() })
        if (-not $cfg.ContainsKey($key) -or $values.Count -eq 0) { $problems += "$key is missing or empty." }
        elseif ("$values" -match 'contoso') { $problems += "$key still has the example value from config.example.psd1." }
    }
    if ($problems.Count) {
        throw ("config.local.psd1 is not ready:`n - " + ($problems -join "`n - "))
    }
    $cfg
}

function Get-IamOutputPath {
    <#
    .SYNOPSIS
        Returns a timestamped CSV path in the repo's output folder (gitignored) and creates the folder.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Prefix)
    $outDir = Join-Path -Path $script:RepoRoot -ChildPath 'output'
    if (-not (Test-Path -Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force -WhatIf:$false | Out-Null }
    Join-Path -Path $outDir -ChildPath ('{0}-{1:yyyyMMdd-HHmmss}.csv' -f $Prefix, (Get-Date))
}

function ConvertTo-IamUpnPart {
    # Strip accents (S-comma to S, a-breve to a), then keep only a-z, 0-9 and hyphen.
    param([Parameter(Mandatory)][string]$Text)
    $decomposed = $Text.Trim().Normalize([Text.NormalizationForm]::FormD)
    $plain = -join ($decomposed.ToCharArray() | Where-Object {
            [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark
        })
    $plain.ToLowerInvariant() -replace '[^a-z0-9-]', ''
}

function Get-IamUpnPrefix {
    <#
    .SYNOPSIS
        Builds the UPN prefix (the part before @) from a name and the UpnFormat config value.
    .DESCRIPTION
        Tokens: {given}, {surname}, {g} (first initial), {s}. Accents are removed and the
        result is lower case. Throws on unknown tokens or a result that is not a valid prefix.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GivenName,
        [Parameter(Mandatory)][string]$Surname,
        [string]$Format = '{given}.{surname}'
    )
    $first = ConvertTo-IamUpnPart -Text $GivenName
    $last = ConvertTo-IamUpnPart -Text $Surname
    if (-not $first -or -not $last) { throw "'$GivenName $Surname' has no characters usable in a UPN." }
    $nick = $Format.Replace('{given}', $first).Replace('{surname}', $last)
    $nick = $nick.Replace('{g}', $first.Substring(0, 1)).Replace('{s}', $last.Substring(0, 1))
    if ($nick -match '[{}]') { throw "UpnFormat '$Format' has an unknown token. Use {given}, {surname}, {g} or {s}." }
    if ($nick -cnotmatch '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$' -or $nick -match '\.\.') {
        throw "UPN prefix '$nick' from UpnFormat '$Format' is not valid."
    }
    $nick
}

function Get-IamRandomPassword {
    <#
    .SYNOPSIS
        Random password from a cryptographic RNG, with upper, lower, digit and symbol.
        No I, O, l, o, 0, 1, so it survives being read out or retyped.
    #>
    [CmdletBinding()]
    param([ValidateRange(14, 128)][int]$Length = 20)
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

function ConvertTo-IamSecureString {
    # Builds a SecureString one character at a time (avoids ConvertTo-SecureString -AsPlainText).
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param([Parameter(Mandatory)][string]$Text)
    $secure = New-Object -TypeName System.Security.SecureString
    foreach ($c in $Text.ToCharArray()) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    $secure
}

function Import-IamAdModule {
    [CmdletBinding()]
    param()
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw ('ActiveDirectory module not found. On Windows 11: Settings > System > Optional features > ' +
            'View features > "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools".')
    }
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
}

function Invoke-IamDeltaSync {
    <#
    .SYNOPSIS
        Runs an Entra Connect delta sync on the sync server and waits for it to finish.
    .DESCRIPTION
        Needs WinRM to the server and membership of ADSyncOperators (or local admin) there.
        Refuses a server in staging mode, which imports but never exports changes.
        If a cycle is already running, waits for it, then starts a new one so the
        latest AD change is included.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [int]$TimeoutSeconds = 600
    )
    $deadlineUtc = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
    $result = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
        Import-Module ADSync -ErrorAction Stop
        $deadline = $using:deadlineUtc
        $scheduler = Get-ADSyncScheduler
        if ($scheduler.StagingModeEnabled) { throw "$env:COMPUTERNAME is in staging mode. Use the active Entra Connect server." }
        while ((Get-ADSyncScheduler).SyncCycleInProgress) {
            if ((Get-Date).ToUniversalTime() -gt $deadline) { throw 'A sync cycle was already running and did not finish in time.' }
            Start-Sleep -Seconds 10
        }
        $start = Start-ADSyncSyncCycle -PolicyType Delta
        Start-Sleep -Seconds 5
        while ((Get-ADSyncScheduler).SyncCycleInProgress) {
            if ((Get-Date).ToUniversalTime() -gt $deadline) { return "Started ($($start.Result)), still running at timeout" }
            Start-Sleep -Seconds 10
        }
        "Completed ($($start.Result))"
    }
    Write-IamLog -Message "Delta sync on ${Server}: $result"
    $result
}

function Wait-IamCloudUser {
    <#
    .SYNOPSIS
        Polls Graph until a user matches a condition, or returns $null at timeout.
        Returns 'Deleted' if the object no longer exists (for example, moved out of sync scope).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Upn')][string]$UserPrincipalName,
        [Parameter(Mandatory, ParameterSetName = 'Id')][string]$UserId,
        [scriptblock]$Until = { param($u) $null -ne $u },
        [int]$TimeoutSeconds = 600,
        [int]$IntervalSeconds = 15
    )
    $props = 'Id', 'UserPrincipalName', 'AccountEnabled', 'OnPremisesSyncEnabled'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $u = $null
        if ($PSCmdlet.ParameterSetName -eq 'Upn') {
            $u = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property $props -ErrorAction Stop
        }
        else {
            try { $u = Get-MgUser -UserId $UserId -Property $props -ErrorAction Stop }
            catch {
                if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist|NotFound') { return 'Deleted' }
                throw
            }
        }
        if ($u -and (& $Until $u)) { return $u }
        if ((Get-Date) -gt $deadline) { return $null }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Connect-IamGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string[]]$Scopes
    )
    Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    Write-IamLog -Message "Connected to $($ctx.TenantId) as $($ctx.Account). Scopes: $($ctx.Scopes -join ', ')"
}

function Assert-IamSyncState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][ValidateSet('Cloud', 'Hybrid')][string]$Expected
    )
    $user = Get-MgUser -UserId $UserPrincipalName -Property Id, UserPrincipalName, OnPremisesSyncEnabled -ErrorAction Stop
    $isSynced = $user.OnPremisesSyncEnabled -eq $true   # cloud-only users return null, not false
    if ($Expected -eq 'Cloud' -and $isSynced) { throw "$UserPrincipalName is synced from AD. Use the Hybrid script." }
    if ($Expected -eq 'Hybrid' -and -not $isSynced) { throw "$UserPrincipalName is cloud-only. Use the Cloud script." }
    $user
}

function Revoke-IamUserSession {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$UserId)
    if ($PSCmdlet.ShouldProcess($UserId, 'Revoke all sign-in sessions')) {
        Revoke-MgUserSignInSession -UserId $UserId -ErrorAction Stop | Out-Null
        Write-IamLog -Message "Sessions revoked: $UserId"
    }
}

function Remove-IamUserLicense {
    # Direct assignments only. Group-assigned licences go when the user leaves the group,
    # and trying to remove them directly makes the whole call fail.
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$UserId)
    $user = Get-MgUser -UserId $UserId -Property LicenseAssignmentStates -ErrorAction Stop
    $skuIds = @($user.LicenseAssignmentStates | Where-Object { -not $_.AssignedByGroup } |
        Select-Object -ExpandProperty SkuId -Unique)
    if ($skuIds.Count -eq 0) { Write-IamLog -Message "No direct licences assigned: $UserId"; return }
    if ($PSCmdlet.ShouldProcess($UserId, "Remove $($skuIds.Count) direct licence(s)")) {
        Set-MgUserLicense -UserId $UserId -AddLicenses @() -RemoveLicenses $skuIds -ErrorAction Stop | Out-Null
        Write-IamLog -Message "Removed $($skuIds.Count) direct licence(s): $UserId"
    }
}

Export-ModuleMember -Function Write-IamLog, Import-IamConfig, Get-IamOutputPath, Get-IamUpnPrefix, Get-IamRandomPassword,
    ConvertTo-IamSecureString, Import-IamAdModule, Invoke-IamDeltaSync, Wait-IamCloudUser, Connect-IamGraph,
    Assert-IamSyncState, Revoke-IamUserSession, Remove-IamUserLicense
