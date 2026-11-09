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

# ---- Authentication methods ----

$script:AuthMethodSegments = @{
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' = 'microsoftAuthenticatorMethods'
    '#microsoft.graph.phoneAuthenticationMethod'                  = 'phoneMethods'
    '#microsoft.graph.fido2AuthenticationMethod'                  = 'fido2Methods'
    '#microsoft.graph.softwareOathAuthenticationMethod'           = 'softwareOathMethods'
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'    = 'temporaryAccessPassMethods'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' = 'windowsHelloForBusinessMethods'
    '#microsoft.graph.emailAuthenticationMethod'                  = 'emailMethods'
    '#microsoft.graph.platformCredentialAuthenticationMethod'     = 'platformCredentialMethods'
}

function Get-IamUserAuthMethod {
    <#
    .SYNOPSIS
        Lists a user's registered authentication methods, except the password.
        Needs UserAuthenticationMethod.Read.All (or ReadWrite.All).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$UserId)
    $resp = Invoke-MgGraphRequest -Method GET -Uri "v1.0/users/$UserId/authentication/methods" -ErrorAction Stop
    foreach ($m in @($resp.value)) {
        $type = $m.'@odata.type'
        if ($type -eq '#microsoft.graph.passwordAuthenticationMethod') { continue }
        [pscustomobject]@{
            Id      = $m.id
            Type    = $type -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
            Segment = $script:AuthMethodSegments[$type]
        }
    }
}

function Remove-IamUserAuthMethod {
    <#
    .SYNOPSIS
        Removes every registered authentication method except the password.
    .DESCRIPTION
        Graph refuses to delete the default method while other methods exist, so this runs
        two passes: everything it can, then whatever failed (usually the default, now alone).
        Returns the removed and failed method types.
        Needs UserAuthenticationMethod.ReadWrite.All and Authentication Administrator.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$UserId)
    $methods = @(Get-IamUserAuthMethod -UserId $UserId)
    $removed = @()
    $failed = @()
    if ($methods.Count -eq 0) {
        Write-IamLog -Message "No authentication methods to remove: $UserId"
        return [pscustomobject]@{ Removed = $removed; Failed = $failed }
    }
    if (-not $PSCmdlet.ShouldProcess($UserId, "Remove $($methods.Count) authentication method(s)")) { return }

    $pending = @($methods | Where-Object { $_.Segment })
    $failed += @($methods | Where-Object { -not $_.Segment } | ForEach-Object { "$($_.Type) (unsupported type)" })
    for ($pass = 1; $pass -le 2 -and $pending.Count; $pass++) {
        $retry = @()
        foreach ($m in $pending) {
            try {
                Invoke-MgGraphRequest -Method DELETE -Uri "v1.0/users/$UserId/authentication/$($m.Segment)/$($m.Id)" -ErrorAction Stop | Out-Null
                $removed += $m.Type
            }
            catch {
                if ($pass -eq 1) { $retry += $m }
                else { $failed += "$($m.Type) ($($_.Exception.Message))" }
            }
        }
        $pending = $retry
    }
    Write-IamLog -Message "Authentication methods removed for ${UserId}: $($removed.Count) ($($removed -join ', '))"
    foreach ($f in $failed) { Write-IamLog -Level WARN -Message "Authentication method not removed for ${UserId}: $f" }
    [pscustomobject]@{ Removed = $removed; Failed = $failed }
}

# ---- Exchange Online ----

function Connect-IamExchange {
    <#
    .SYNOPSIS
        Connects to Exchange Online (ExchangeOnlineManagement module), reusing an open session.
        Least-privilege role for the mailbox steps: Recipient Management.
    #>
    [CmdletBinding()]
    param()
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'ExchangeOnlineManagement module not found. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop -Verbose:$false
    $open = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' })
    if ($open.Count -eq 0) {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        $open = @(Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' })
    }
    Write-IamLog -Message "Exchange Online connected as $($open[0].UserPrincipalName)"
}

function Get-IamMailboxState {
    <#
    .SYNOPSIS
        Reads what the leaver needs to know about a mailbox before converting it.
    .DESCRIPTION
        NeedsLicence is true when a shared mailbox would still need a licence:
        over 50 GB, litigation hold, or an active archive. Removing the licence then
        would put the mailbox at risk, so the leaver keeps it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Identity)
    $mbx = Get-EXOMailbox -Identity $Identity -Properties RecipientTypeDetails, LitigationHoldEnabled, ArchiveStatus -ErrorAction SilentlyContinue
    if (-not $mbx) { return [pscustomobject]@{ Exists = $false } }
    $stats = Get-EXOMailboxStatistics -Identity $Identity -ErrorAction SilentlyContinue
    $bytes = 0
    if ($stats -and "$($stats.TotalItemSize)" -match '\(([\d,]+) bytes\)') { $bytes = [int64]($Matches[1] -replace ',', '') }
    $sizeGB = [math]::Round($bytes / 1GB, 2)
    $reasons = @()
    if ($sizeGB -ge 50) { $reasons += "over 50 GB ($sizeGB GB)" }
    if ($mbx.LitigationHoldEnabled) { $reasons += 'litigation hold' }
    if ($mbx.ArchiveStatus -eq 'Active') { $reasons += 'archive enabled' }
    [pscustomobject]@{
        Exists         = $true
        Type           = "$($mbx.RecipientTypeDetails)"
        SizeGB         = $sizeGB
        NeedsLicence   = [bool]$reasons.Count
        LicenceReasons = $reasons -join ', '
    }
}

function Convert-IamMailboxToShared {
    <#
    .SYNOPSIS
        Converts a user mailbox to shared, then optionally grants Full Access,
        sets an automatic reply and hides it from the address list.
    .DESCRIPTION
        -HideFromGal only works for cloud-only users. For synced users the setting
        belongs to AD (msExchHideFromAddressLists).
        With an on-prem Exchange server still used for management, also run
        Set-RemoteMailbox -Type Shared on-prem.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [string]$DelegateTo,
        [string]$AutoReplyMessage,
        [switch]$HideFromGal,
        [int]$TimeoutSeconds = 120
    )
    if (-not $PSCmdlet.ShouldProcess($Identity, 'Convert mailbox to shared')) { return }
    $current = Get-EXOMailbox -Identity $Identity -Properties RecipientTypeDetails -ErrorAction Stop
    if ("$($current.RecipientTypeDetails)" -ne 'SharedMailbox') {
        Set-Mailbox -Identity $Identity -Type Shared -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do {
            Start-Sleep -Seconds 10
            $current = Get-EXOMailbox -Identity $Identity -Properties RecipientTypeDetails -ErrorAction Stop
        } until ("$($current.RecipientTypeDetails)" -eq 'SharedMailbox' -or (Get-Date) -gt $deadline)
        if ("$($current.RecipientTypeDetails)" -ne 'SharedMailbox') {
            throw "Mailbox for $Identity did not show as shared within $TimeoutSeconds seconds. Licence not removed. Check it, then remove the licence by hand."
        }
    }
    Write-IamLog -Message "Mailbox converted to shared: $Identity"
    if ($DelegateTo) {
        Add-MailboxPermission -Identity $Identity -User $DelegateTo -AccessRights FullAccess -InheritanceType All -AutoMapping $true -ErrorAction Stop | Out-Null
        Write-IamLog -Message "Full Access on $Identity granted to $DelegateTo"
    }
    if ($AutoReplyMessage) {
        Set-MailboxAutoReplyConfiguration -Identity $Identity -AutoReplyState Enabled -InternalMessage $AutoReplyMessage `
            -ExternalMessage $AutoReplyMessage -ExternalAudience All -ErrorAction Stop
        Write-IamLog -Message "Automatic reply set on $Identity"
    }
    if ($HideFromGal) {
        Set-Mailbox -Identity $Identity -HiddenFromAddressListsEnabled $true -ErrorAction Stop
        Write-IamLog -Message "Hidden from the address list: $Identity"
    }
}

# ---- Manager ----

function Get-IamCloudManager {
    <#
    .SYNOPSIS
        Returns the user's manager from Entra ID (Id, UserPrincipalName, AccountEnabled), or $null.
        Needs User.Read.All.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$UserId)
    try {
        $m = Invoke-MgGraphRequest -Method GET -Uri "v1.0/users/$UserId/manager?`$select=id,userPrincipalName,accountEnabled" -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist|NotFound|404') { return $null }
        throw
    }
    [pscustomobject]@{ Id = $m.id; UserPrincipalName = $m.userPrincipalName; AccountEnabled = $m.accountEnabled }
}

function Test-IamExchangePlan {
    # True if the user's assigned plans include an enabled Exchange Online service plan
    # (so licence removal would start the mailbox deletion clock). Pass a user with AssignedPlans.
    param([Parameter(Mandatory)]$User)
    [bool](@($User.AssignedPlans) | Where-Object { $_.Service -eq 'exchange' -and $_.CapabilityStatus -eq 'Enabled' })
}

function Resolve-IamDelegate {
    <#
    .SYNOPSIS
        Picks who gets Full Access to a leaver's shared mailbox and returns a plan line.
    .DESCRIPTION
        -DelegateTo wins. Otherwise the manager passed in. A disabled or missing delegate
        returns $null with the reason, so the leaver delegates nothing and lists a manual item.
    #>
    [CmdletBinding()]
    param(
        [string]$DelegateTo,
        $Manager
    )
    if ($DelegateTo) {
        $u = $null
        try { $u = Get-MgUser -UserId $DelegateTo -Property Id, UserPrincipalName, AccountEnabled -ErrorAction Stop } catch { $u = $null }
        if (-not $u) { throw "-DelegateTo $DelegateTo not found in Entra ID." }
        if (-not $u.AccountEnabled) { throw "-DelegateTo $DelegateTo is disabled. Choose someone else." }
        return [pscustomobject]@{ Upn = $u.UserPrincipalName; Source = 'DelegateTo'; Problem = $null }
    }
    if (-not $Manager) { return [pscustomobject]@{ Upn = $null; Source = 'Manager'; Problem = 'No manager set' } }
    if (-not $Manager.AccountEnabled) {
        return [pscustomobject]@{ Upn = $null; Source = 'Manager'; Problem = "Manager $($Manager.UserPrincipalName) is disabled" }
    }
    [pscustomobject]@{ Upn = $Manager.UserPrincipalName; Source = 'Manager'; Problem = $null }
}

function Get-IamLeaverMailboxPlan {
    <#
    .SYNOPSIS
        Works out the mailbox part of a leaver plan: convert or not, who gets Full Access,
        and whether the licence has to stay. Read-only; connects to Exchange Online if needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [switch]$ConvertMailbox,
        [string]$DelegateTo,
        [switch]$NoDelegate,
        $Manager,
        [bool]$HasExchangePlan,
        [bool]$WillRemoveLicence
    )
    $plan = [pscustomobject]@{
        Lines = @(); Manual = @(); Convert = $false; Delegate = $null; ForceKeepLicence = $false; SizeGB = $null
    }
    if (-not $ConvertMailbox) {
        if ($HasExchangePlan -and $WillRemoveLicence) {
            $plan.Manual += 'Mailbox not converted: it is deleted 30 days after the licence goes. Use -ConvertMailbox or -KeepLicense if it must be kept'
        }
        return $plan
    }
    Connect-IamExchange
    $state = Get-IamMailboxState -Identity $UserPrincipalName
    if (-not $state.Exists) {
        $plan.Manual += 'No Exchange Online mailbox found: nothing to convert'
        return $plan
    }
    $plan.Convert = $true
    $plan.SizeGB = $state.SizeGB
    if ($state.Type -eq 'SharedMailbox') { $plan.Lines += 'mailbox already shared' }
    else { $plan.Lines += "convert mailbox to shared ($($state.SizeGB) GB)" }
    if ($NoDelegate) { $plan.Lines += 'no Full Access (-NoDelegate)' }
    else {
        $d = Resolve-IamDelegate -DelegateTo $DelegateTo -Manager $Manager
        if ($d.Upn) {
            $plan.Delegate = $d.Upn
            $how = if ($d.Source -eq 'Manager') { 'manager' } else { '-DelegateTo' }
            $plan.Lines += "Full Access to $($d.Upn) ($how)"
        }
        else { $plan.Manual += "$($d.Problem): grant mailbox access by hand, or rerun with -DelegateTo" }
    }
    if ($state.NeedsLicence) {
        $plan.ForceKeepLicence = $true
        $plan.Lines += "keep licence: the shared mailbox still needs one ($($state.LicenceReasons))"
    }
    $plan
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
    Assert-IamSyncState, Revoke-IamUserSession, Remove-IamUserLicense, Get-IamUserAuthMethod, Remove-IamUserAuthMethod,
    Connect-IamExchange, Get-IamMailboxState, Convert-IamMailboxToShared, Get-IamCloudManager, Test-IamExchangePlan,
    Resolve-IamDelegate, Get-IamLeaverMailboxPlan
