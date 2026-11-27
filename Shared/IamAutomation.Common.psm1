# Shared functions for the Cloud, Hybrid and Reports scripts.
# Requires: PowerShell 7 for anything that signs in to Graph. Install-Module Microsoft.Graph -Scope CurrentUser

$script:RepoRoot = Split-Path -Path $PSScriptRoot -Parent

$script:IamGraphClientId = $null   # set by Import-IamConfig from GraphClientId

# Windows Event Log copy of every log line (Setup\Register-IamEventSource.ps1 registers the source).
$script:IamEventSource = 'IamAutomation'
$script:IamEventLogOn = $null      # $null until the first line checks the source
$script:IamEventWriter = {
    param($Source, $Message, $Type, $Id)
    [System.Diagnostics.EventLog]::WriteEntry($Source, $Message, $Type, $Id)
}

function Write-IamLog {
    <#
    .SYNOPSIS
        Writes a timestamped line to output\iam-automation.log, to the console and, on Windows with
        the IamAutomation event source registered, to the Application event log.
    .DESCRIPTION
        The log file is a working copy anyone with access to the folder can edit. The event log copy
        is the audit record: a user cannot edit or delete single events, and clearing the log is
        itself logged (event 104 in the System log). Forward it to a collector or SIEM for a record
        a local admin cannot touch either.

        Event IDs: 1000 INFO, 2000 WARN, 3000 ERROR. Each event also names the Windows account and
        computer. Without the source registered, the line goes to the file only, with one warning
        per run.
    #>
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

    if ($null -eq $script:IamEventLogOn) {
        $script:IamEventLogOn = Test-IamEventSource
        if (-not $script:IamEventLogOn -and ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) {
            Write-Warning "Event log source '$script:IamEventSource' is not registered, so this run is logged to the file only. Register it once, as admin: .\Setup\Register-IamEventSource.ps1"
        }
    }
    if ($script:IamEventLogOn) {
        $type = @{ INFO = 'Information'; WARN = 'Warning'; ERROR = 'Error' }[$Level]
        $id = @{ INFO = 1000; WARN = 2000; ERROR = 3000 }[$Level]
        $text = "$Message`r`n`r`nWindows account: $([Environment]::UserDomainName)\$([Environment]::UserName)`r`nComputer: $env:COMPUTERNAME"
        if ($text.Length -gt 31000) { $text = $text.Substring(0, 31000) }
        try { & $script:IamEventWriter $script:IamEventSource $text $type $id }
        catch {
            $script:IamEventLogOn = $false
            Write-Warning "Could not write to the event log, so the rest of this run is logged to the file only: $($_.Exception.Message)"
        }
    }
}

function Test-IamEventSource {
    <#
    .SYNOPSIS
        True when the IamAutomation event source is registered on this Windows machine.
    .DESCRIPTION
        Never registers it: that needs admin rights, once (Setup\Register-IamEventSource.ps1).
        False on Linux and macOS, and when the check itself is refused.
    #>
    [CmdletBinding()]
    param([string]$Source = $script:IamEventSource)
    if (-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) { return $false }
    try { [System.Diagnostics.EventLog]::SourceExists($Source) }
    catch { $false }
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

        GraphClientId is optional: the Application (client) ID of your own app registration
        (Setup\New-IamAppRegistration.ps1). When set, Connect-IamGraph signs in through it
        instead of Microsoft Graph Command Line Tools.
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
    $script:IamGraphClientId = $null
    if ("$($cfg.GraphClientId)".Trim()) {
        $app = [guid]::Empty
        if (-not [guid]::TryParse("$($cfg.GraphClientId)", [ref]$app) -or $app -eq [guid]::Empty) {
            $problems += 'GraphClientId must be the Application (client) ID of your app registration, or left empty.'
        }
        else { $script:IamGraphClientId = "$app" }
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

function Get-IamOutputFolder {
    <#
    .SYNOPSIS
        Returns a folder under the repo's output folder (gitignored) and creates it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -match '[\\/:*?"<>|]' -or $Name -match '^\.') { throw "Folder name '$Name' has characters Windows does not allow." }
    $dir = Join-Path -Path (Join-Path -Path $script:RepoRoot -ChildPath 'output') -ChildPath $Name
    if (-not (Test-Path -Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    $dir
}

function Export-IamCsv {
    <#
    .SYNOPSIS
        Writes a CSV as UTF-8 with a byte order mark, so Excel shows accented names correctly
        in Windows PowerShell 5.1 and PowerShell 7 alike.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )
    $csvArgs = @{ Path = $Path; Encoding = 'utf8BOM'; WhatIf = $false }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # PowerShell 7 never writes the #TYPE line, and 7.6 warns that -NoTypeInformation is obsolete.
        $csvArgs.Encoding = 'UTF8'
        $csvArgs.NoTypeInformation = $true
    }
    $InputObject | Export-Csv @csvArgs
}

function Invoke-IamGraphGetAll {
    <#
    .SYNOPSIS
        GET a Graph collection and follow @odata.nextLink until the last page. Returns the items.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)
    $next = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        foreach ($item in @($resp.value)) { $item }
        $next = $resp.'@odata.nextLink'
    }
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
    <#
    .SYNOPSIS
        Builds a SecureString one character at a time (avoids ConvertTo-SecureString -AsPlainText).
    #>
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param([Parameter(Mandatory)][string]$Text)
    $secure = New-Object -TypeName System.Security.SecureString
    foreach ($c in $Text.ToCharArray()) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    $secure
}

function Import-IamAdModule {
    <#
    .SYNOPSIS
        Loads the ActiveDirectory module, or throws with the RSAT install path.
    #>
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

# ---- Managers ----

function Get-IamValidManager {
    <#
    .SYNOPSIS
        Looks up a manager by UPN and checks it exists and is enabled. Throws otherwise.
        Returns UserPrincipalName, Id (cloud), DistinguishedName (AD) and AccountEnabled.
    .PARAMETER Source
        Cloud: Entra ID (needs User.Read.All). AD: Active Directory (needs the AD module loaded).
    .PARAMETER OnFail
        Appended to the error, e.g. 'Nothing was created.'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][ValidateSet('Cloud', 'AD')][string]$Source,
        [string]$OnFail = 'Nothing changed.'
    )
    $upn = $UserPrincipalName.Trim()
    if ($Source -eq 'Cloud') {
        $u = $null
        try { $u = Get-MgUser -UserId $upn -Property Id, UserPrincipalName, AccountEnabled -ErrorAction Stop } catch { $u = $null }
        if (-not $u) { throw "Manager $upn not found in Entra ID. $OnFail" }
        if (-not $u.AccountEnabled) { throw "Manager $upn is disabled. $OnFail" }
        return [pscustomobject]@{ UserPrincipalName = $upn; Id = $u.Id; DistinguishedName = $null; AccountEnabled = $true }
    }
    $a = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -Properties Enabled, UserPrincipalName
    if (-not $a) { throw "Manager $upn not found in AD. $OnFail" }
    if (-not $a.Enabled) { throw "Manager $upn is disabled in AD. $OnFail" }
    [pscustomobject]@{ UserPrincipalName = $upn; Id = $null; DistinguishedName = $a.DistinguishedName; AccountEnabled = $true }
}

function Get-IamAdManager {
    <#
    .SYNOPSIS
        Returns the AD manager behind a Manager attribute (UserPrincipalName, AccountEnabled,
        DistinguishedName), or $null if the attribute is empty or the object cannot be read.
    #>
    [CmdletBinding()]
    param([string]$DistinguishedName)
    if (-not $DistinguishedName) { return $null }
    try { $m = Get-ADUser -Identity $DistinguishedName -Properties Enabled, UserPrincipalName -ErrorAction Stop }
    catch { return $null }
    if (-not $m) { return $null }
    [pscustomobject]@{ UserPrincipalName = $m.UserPrincipalName; AccountEnabled = [bool]$m.Enabled; DistinguishedName = $m.DistinguishedName }
}

function Set-IamCloudManager {
    <#
    .SYNOPSIS
        Sets a user's manager in Entra ID. Retries for a user created seconds ago, which Graph
        may not find yet. Throws after the last attempt. Needs User.ReadWrite.All.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$ManagerId,
        [ValidateRange(1, 10)][int]$Attempts = 1
    )
    if (-not $PSCmdlet.ShouldProcess($UserId, "Set manager $ManagerId")) { return }
    $ref = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$ManagerId" } | ConvertTo-Json
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Invoke-MgGraphRequest -Method PUT -Uri "v1.0/users/$UserId/manager/`$ref" -Body $ref -ContentType 'application/json' -ErrorAction Stop | Out-Null
            return
        }
        catch {
            if ($i -eq $Attempts) { throw }
            Start-Sleep -Seconds 5
        }
    }
}

function Write-IamManagerWarning {
    <#
    .SYNOPSIS
        Mover warning when the department changes without -Manager: no manager, a disabled
        manager, or a manager that stays from the old department.
    .PARAMETER CurrentManager
        Object with UserPrincipalName and AccountEnabled (Get-IamCloudManager, Get-IamAdManager), or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        $CurrentManager,
        [string]$Where = ''
    )
    if (-not $CurrentManager) {
        $msg = "$UserPrincipalName has no manager$Where. Add -Manager so the leaver can hand over the mailbox later."
    }
    elseif (-not $CurrentManager.AccountEnabled) {
        $msg = "Manager $($CurrentManager.UserPrincipalName) is disabled$Where. Add -Manager with the new manager."
    }
    else {
        $msg = "Department changes but manager stays $($CurrentManager.UserPrincipalName). Add -Manager if that is wrong."
    }
    Write-IamLog -Level WARN -Message $msg
}

function Test-IamExchangePlan {
    <#
    .SYNOPSIS
        True if the user's assigned plans include an enabled Exchange Online service plan
        (so licence removal would start the mailbox deletion clock). Pass a user with AssignedPlans.
    #>
    param([Parameter(Mandatory)]$User)
    [bool](@($User.AssignedPlans) | Where-Object { $_.Service -eq 'exchange' -and $_.CapabilityStatus -eq 'Enabled' })
}

function Test-IamOneDrivePlan {
    <#
    .SYNOPSIS
        True if the user's assigned plans include an enabled SharePoint Online service plan,
        so the user has a OneDrive to hand over. Pass a user with AssignedPlans.
    #>
    param([Parameter(Mandatory)]$User)
    [bool](@($User.AssignedPlans) | Where-Object { $_.Service -eq 'SharePoint' -and $_.CapabilityStatus -eq 'Enabled' })
}

function Get-IamLeaverHandover {
    <#
    .SYNOPSIS
        Manual follow-up items for a leaver's devices and OneDrive. Read-only.
    .DESCRIPTION
        Lists the Entra devices the user registered or owns (Entra joined, hybrid joined,
        registered), each as one item: retire or wipe a joined device, remove company data from
        a registered one (usually personal, but retire it if the company owns it). Adds a OneDrive handover item for the manager when
        the user has a OneDrive. A failed device lookup becomes an item to check by hand, so
        the leaver plan never stops on it.
        Hybrid joined devices often have no registered owner and then do not show up here.
        Needs Directory.Read.All (or Device.Read.All): with User.ReadWrite.All alone, Graph
        returns the devices without their names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UserId,
        $Manager,
        [bool]$HasOneDrive
    )
    $items = @()
    $select = '$select=id,displayName,operatingSystem,trustType,approximateLastSignInDateTime'
    try {
        $seen = @{}
        $devices = @()
        foreach ($rel in 'registeredDevices', 'ownedDevices') {
            foreach ($d in (Invoke-IamGraphGetAll -Uri "v1.0/users/$UserId/$rel/microsoft.graph.device?$select")) {
                if ($seen.ContainsKey("$($d.id)")) { continue }
                $seen["$($d.id)"] = $true
                $devices += $d
            }
        }
        foreach ($d in ($devices | Sort-Object { "$($_.displayName)" })) {
            $trust = switch ("$($d.trustType)") {
                'AzureAd' { 'Entra joined' }
                'ServerAd' { 'hybrid joined' }
                'Workplace' { 'registered' }
                default { 'join type unknown' }
            }
            $last = if ($d.approximateLastSignInDateTime) {
                'last sign-in ' + ([datetime]$d.approximateLastSignInDateTime).ToString('dd MMM yyyy', [cultureinfo]::InvariantCulture)
            }
            else { 'no sign-in recorded' }
            $name = if ($d.displayName) { $d.displayName } else { "device $($d.id)" }
            $os = if ($d.operatingSystem) { $d.operatingSystem } else { 'OS unknown' }
            $action = if ("$($d.trustType)" -eq 'Workplace') { 'remove company data, or retire it if company-owned' } else { 'retire or wipe, collect the hardware' }
            $items += "Device ($action): $name - $os, $trust, $last"
        }
    }
    catch {
        # The reason goes to the log, not the item: a caller such as the IAM console reads words like
        # "failed" in a manual item as a failed offboarding step.
        Write-IamLog -Level WARN -Message "Device lookup for user ${UserId}: $($_.Exception.Message)"
        $items += "Devices: lookup did not complete, check the user's devices by hand (reason in the log)"
    }
    if ($HasOneDrive) {
        if ($Manager -and $Manager.UserPrincipalName) {
            $items += "OneDrive (hand over before the account is deleted): give $($Manager.UserPrincipalName) access or copy the files they need"
        }
        else {
            $items += 'OneDrive (hand over before the account is deleted): no manager set, agree who gets the files'
        }
    }
    $items
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

function Assert-IamGraphHost {
    <#
    .SYNOPSIS
        Stops on Windows PowerShell 5.1, where the Microsoft Graph SDK cannot sign in.
    .DESCRIPTION
        Graph SDK 2.34 and later fail on 5.1 at Connect-MgGraph with "Method 'RefreshCacheAsync'
        ... does not have an implementation" (assembly loading bug, still there in 2.41.2).
        Microsoft is ending Graph SDK support on 5.1. Connect-IamGraph runs this before sign-in,
        and every script signs in before it changes anything.
    #>
    [CmdletBinding()]
    param([string]$Edition = $PSVersionTable.PSEdition)
    if ($Edition -eq 'Desktop') {
        throw ('This script needs PowerShell 7 (pwsh). The Microsoft Graph SDK cannot sign in on ' +
            'Windows PowerShell 5.1. Nothing was changed.')
    }
}

function Assert-IamVerifiedDomain {
    <#
    .SYNOPSIS
        Stops if a domain is not a verified domain in the signed-in tenant.
    .DESCRIPTION
        Entra Connect keeps an AD UPN in the cloud only when its suffix is a verified domain.
        Otherwise the user syncs as @<tenant>.onmicrosoft.com and a lookup by the AD UPN finds
        nothing. Reads verifiedDomains from the organization object, which needs only User.Read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Domain)
    $verified = @(@(Get-MgOrganization -Property Id, VerifiedDomains -ErrorAction Stop).VerifiedDomains |
            ForEach-Object { "$($_.Name)".ToLowerInvariant() })
    if ($verified -notcontains $Domain.ToLowerInvariant()) {
        throw ("'$Domain' is not a verified domain in Entra ID, so users would sync as @<tenant>.onmicrosoft.com. " +
            "Verified domains: $($verified -join ', '). Nothing was created.")
    }
}

function ConvertTo-IamImmutableId {
    <#
    .SYNOPSIS
        Returns the onPremisesImmutableId that Entra Connect gives an AD user (the source anchor).
    .DESCRIPTION
        The default source anchor is mS-DS-ConsistencyGuid, which Entra Connect fills from
        objectGUID the first time the user syncs. The cloud account holds it in Base64 as
        onPremisesImmutableId. Uses mS-DS-ConsistencyGuid when it is set, objectGUID otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$ObjectGuid,
        [byte[]]$ConsistencyGuid
    )
    $bytes = if ($ConsistencyGuid -and $ConsistencyGuid.Length -eq 16) { $ConsistencyGuid } else { $ObjectGuid.ToByteArray() }
    [Convert]::ToBase64String($bytes)
}

function ConvertTo-IamAdAnchorMap {
    <#
    .SYNOPSIS
        Indexes AD users by the onPremisesImmutableId their cloud account holds (the source anchor).
    .DESCRIPTION
        For reports that start from Entra ID and need the matching AD account. One AD query up
        front, then a lookup per cloud user, instead of one AD search per user. Keys are Base64,
        which is case-sensitive, so the map compares keys exactly.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, object]])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$AdUser)
    $map = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($a in $AdUser) {
        $id = ConvertTo-IamImmutableId -ObjectGuid $a.ObjectGUID -ConsistencyGuid $a.'mS-DS-ConsistencyGuid'
        $map[$id] = $a
    }
    , $map
}

function Get-IamSyncedCloudUser {
    <#
    .SYNOPSIS
        Finds the Entra ID account linked to an AD user through the source anchor, not the UPN.
    .DESCRIPTION
        The AD UPN and the cloud UPN can differ: UPN suffix not verified, alternate login ID, or a
        UPN changed after the first sync. The source anchor does not change, so the lookup always
        finds the account Entra Connect manages. Stops if no account matches, or if the match is
        not synced from AD. Default source anchors only (mS-DS-ConsistencyGuid or objectGUID).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$ObjectGuid,
        [byte[]]$ConsistencyGuid,
        [Parameter(Mandatory)][string]$AdUserPrincipalName
    )
    $immutableId = ConvertTo-IamImmutableId -ObjectGuid $ObjectGuid -ConsistencyGuid $ConsistencyGuid
    $users = @(Get-MgUser -Filter "onPremisesImmutableId eq '$immutableId'" -Property Id, UserPrincipalName, AccountEnabled, OnPremisesSyncEnabled -ErrorAction Stop)
    if ($users.Count -eq 0) {
        throw ("$AdUserPrincipalName has no Entra ID account with source anchor $immutableId. " +
            'It has not synced yet, or its OU is outside the sync scope. Nothing changed.')
    }
    $user = $users[0]
    if ($user.OnPremisesSyncEnabled -ne $true) {
        throw "$AdUserPrincipalName matches $($user.UserPrincipalName) in Entra ID, but sync is off for that account. Nothing changed."
    }
    if ($user.UserPrincipalName -ne $AdUserPrincipalName) {
        Write-IamLog -Message "$AdUserPrincipalName signs in to Entra ID as $($user.UserPrincipalName) (matched by source anchor)."
    }
    $user
}

function Connect-IamGraph {
    <#
    .SYNOPSIS
        Signs in to Microsoft Graph with delegated scopes and logs the tenant, account, app and scopes.
    .DESCRIPTION
        Signs in through your own app registration when GraphClientId is set in config.local.psd1
        (Import-IamConfig reads it), otherwise through Microsoft Graph Command Line Tools.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string[]]$Scopes,
        [string]$ClientId = $script:IamGraphClientId
    )
    Assert-IamGraphHost
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw ('The Microsoft Graph PowerShell modules are not installed for this PowerShell 7. Run .\Setup\Install-IamAutomation.ps1 ' +
            'from a PowerShell 7 window opened directly (modules installed from Windows PowerShell only show up in a pwsh started from it). Nothing was changed.')
    }
    $connect = @{ TenantId = $TenantId; Scopes = $Scopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($ClientId) { $connect.ClientId = $ClientId }
    Connect-MgGraph @connect
    $ctx = Get-MgContext
    $via = if ($ClientId) { "app $ClientId" } else { 'Microsoft Graph Command Line Tools' }
    Write-IamLog -Message "Connected to $($ctx.TenantId) as $($ctx.Account) through $via. Scopes: $($ctx.Scopes -join ', ')"
}

function Get-IamGraphAppScope {
    <#
    .SYNOPSIS
        Every delegated Graph scope the scripts in this repo request: what your own app
        registration needs consented (Setup\New-IamAppRegistration.ps1).
    .DESCRIPTION
        A script signing in through your app can only use scopes the admin consented to, because
        Assignment required stops operators consenting for themselves. A delegated scope never
        lets the operator do more than their Entra role allows. Keep this list in step with the
        Connect-IamGraph calls: a test checks it.
    #>
    [CmdletBinding()]
    param()
    @(
        'User.Read', 'User.Read.All', 'User.ReadWrite.All', 'User-PasswordProfile.ReadWrite.All',
        'UserAuthenticationMethod.ReadWrite.All', 'GroupMember.Read.All', 'GroupMember.ReadWrite.All',
        'RoleManagement.Read.Directory', 'Directory.Read.All', 'LicenseAssignment.Read.All',
        'AuditLog.Read.All', 'Application.Read.All', 'DelegatedPermissionGrant.Read.All',
        'Organization.Read.All', 'Policy.Read.All'
    )
}

function Assert-IamSyncState {
    <#
    .SYNOPSIS
        Stops if a user is synced from AD when a cloud script runs, or cloud-only when a hybrid script runs.
    #>
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
    <#
    .SYNOPSIS
        Revokes all sign-in sessions and refresh tokens for a user.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$UserId)
    if ($PSCmdlet.ShouldProcess($UserId, 'Revoke all sign-in sessions')) {
        Revoke-MgUserSignInSession -UserId $UserId -ErrorAction Stop | Out-Null
        Write-IamLog -Message "Sessions revoked: $UserId"
    }
}

function Remove-IamUserLicense {
    <#
    .SYNOPSIS
        Removes directly assigned licences. Group-assigned licences go when the user leaves the
        group, and trying to remove them directly makes the whole call fail.
    #>
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

function ConvertTo-IamConfigText {
    <#
    .SYNOPSIS
        Turns a config table into the text of a .psd1 file that Import-PowerShellDataFile can read.
    .DESCRIPTION
        Values can be strings, numbers, booleans, $null, arrays of those, and one level of
        nested table (string keys, scalar values), which covers every key in config.example.psd1.
        Keys keep their order when the table is [ordered]. -Comment adds lines above a key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Config,
        [System.Collections.IDictionary]$Comment = @{}
    )
    $scalar = {
        param($Value)
        if ($null -eq $Value) { return '$null' }
        if ($Value -is [bool]) { if ($Value) { return '$true' } else { return '$false' } }
        if ($Value -is [string]) { return "'" + $Value.Replace("'", "''") + "'" }
        if ($Value -is [ValueType]) { return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture) }
        throw "Config values must be strings, numbers or booleans, not $($Value.GetType().Name)."
    }
    $keyText = {
        param($Key)
        if ("$Key" -match '^[A-Za-z_][A-Za-z0-9_]*$') { return "$Key" }
        "'" + "$Key".Replace("'", "''") + "'"
    }

    $width = (@(0) + @($Config.Keys | ForEach-Object { (& $keyText $_).Length }) | Measure-Object -Maximum).Maximum
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('@{')
    foreach ($key in $Config.Keys) {
        if ($Comment.Contains($key)) {
            foreach ($c in @($Comment[$key])) { $lines.Add("    # $c") }
        }
        $value = $Config[$key]
        $name = (& $keyText $key).PadRight($width)
        if ($value -is [System.Collections.IDictionary]) {
            if ($value.Count -eq 0) { $lines.Add("    $name = @{}"); continue }
            $lines.Add("    $name = @{")
            $innerWidth = (@($value.Keys | ForEach-Object { (& $keyText $_).Length }) | Measure-Object -Maximum).Maximum
            foreach ($innerKey in $value.Keys) {
                $lines.Add(('        {0} = {1}' -f (& $keyText $innerKey).PadRight($innerWidth), (& $scalar $value[$innerKey])))
            }
            $lines.Add('    }')
        }
        elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
            $items = @($value | ForEach-Object { & $scalar $_ })
            $lines.Add(('    {0} = @({1})' -f $name, ($items -join ', ')))
        }
        else {
            $lines.Add(('    {0} = {1}' -f $name, (& $scalar $value)))
        }
    }
    $lines.Add('}')
    $lines -join [Environment]::NewLine
}

function Test-IamOuInSyncScope {
    <#
    .SYNOPSIS
        True when a distinguished name is inside the Entra Connect OU filtering scope.
    .DESCRIPTION
        Takes the container inclusion and exclusion lists of the AD connector partitions
        (Get-ADSyncConnector > Partitions > ConnectorPartitionScope). The most specific
        matching container wins: an OU excluded under an included parent is out of scope.
        OU filtering only. Group-based and attribute filtering are not covered.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string[]]$Inclusion = @(),
        [string[]]$Exclusion = @()
    )
    $dn = $DistinguishedName.Trim()
    $longest = {
        param([string[]]$Container)
        $best = -1
        foreach ($c in @($Container | Where-Object { "$_".Trim() })) {
            $c = "$c".Trim()
            $inside = $dn.Equals($c, [StringComparison]::OrdinalIgnoreCase) -or
                $dn.EndsWith(",$c", [StringComparison]::OrdinalIgnoreCase)
            if ($inside -and $c.Length -gt $best) { $best = $c.Length }
        }
        $best
    }
    $included = & $longest $Inclusion
    $excluded = & $longest $Exclusion
    $included -ge 0 -and $included -gt $excluded
}

function ConvertFrom-IamMsolDescription {
    <#
    .SYNOPSIS
        Reads the Entra Connect server name from the description of its MSOL_ AD account.
    .DESCRIPTION
        Entra Connect creates the AD DS connector account MSOL_<id> with a description that
        includes "running on computer <name>". Returns the name, or nothing when it is not there.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Description)
    if ("$Description" -match 'running on computer\s+(?<name>[^\s,]+)') {
        $Matches['name'].TrimEnd('.')
    }
}

function Get-IamUpnFormatGuess {
    <#
    .SYNOPSIS
        Finds the UpnFormat that matches most existing users.
    .DESCRIPTION
        Builds the prefix for each candidate format with Get-IamUpnPrefix and compares it with
        the part of the UPN before @. A trailing number (jane.doe2) still counts as a match.
        Users without a given name or surname, and guests (#EXT#), are left out.
        Returns Format, Hits and Total for the best format, or nothing when none matches.
        On a tie, the format listed first wins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$User,
        [ValidateNotNullOrEmpty()][string[]]$Format = @('{given}.{surname}', '{g}{surname}', '{given}{surname}', '{g}.{surname}', '{given}{s}', '{surname}.{given}')
    )
    $named = @($User | Where-Object {
            $_.givenName -and $_.surname -and $_.userPrincipalName -and "$($_.userPrincipalName)" -notlike '*#EXT#*'
        })
    if ($named.Count -eq 0) { return }

    $results = foreach ($i in 0..($Format.Count - 1)) {
        $hits = 0
        foreach ($u in $named) {
            $prefix = ("$($u.userPrincipalName)" -split '@')[0].ToLowerInvariant()
            try { $expected = Get-IamUpnPrefix -GivenName $u.givenName -Surname $u.surname -Format $Format[$i] }
            catch { continue }
            if ($prefix -match ('^' + [regex]::Escape($expected) + '\d*$')) { $hits++ }
        }
        [pscustomobject]@{ Format = $Format[$i]; Hits = $hits; Total = $named.Count; Index = $i }
    }
    $results | Where-Object { $_.Hits -gt 0 } |
        Sort-Object -Property @{ Expression = 'Hits'; Descending = $true }, @{ Expression = 'Index'; Descending = $false } |
        Select-Object -First 1 -Property Format, Hits, Total
}

function Get-IamBreakGlassCandidate {
    <#
    .SYNOPSIS
        Lists Global Administrators that look like emergency access (break-glass) accounts.
    .DESCRIPTION
        A candidate is explicitly excluded from at least one enabled Conditional Access policy
        (by user, group or the Global Administrator role) and covered by none. Report-only and
        disabled policies are ignored. A suggestion only: the operator confirms the list.
        -Admin: objects with id and userPrincipalName. -Policy: policies as returned by Graph.
        -GroupIdsByUserId: user id -> ids of the groups the user is in (transitive).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Admin,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policy,
        [System.Collections.IDictionary]$GroupIdsByUserId = @{}
    )
    $globalAdminRole = '62e90394-69f5-4237-9190-012177145e10'
    $enabled = @($Policy | Where-Object { $_.state -eq 'enabled' })
    if ($enabled.Count -eq 0) { return }

    foreach ($a in $Admin) {
        $groups = @($GroupIdsByUserId[$a.id] | Where-Object { $_ })
        $excludedSomewhere = $false
        $covered = $false
        foreach ($p in $enabled) {
            $u = $p.conditions.users
            $excluded = (@($u.excludeUsers) -contains $a.id) -or
                (@(@($u.excludeGroups) | Where-Object { $groups -contains $_ }).Count -gt 0) -or
                (@($u.excludeRoles) -contains $globalAdminRole)
            if ($excluded) { $excludedSomewhere = $true; continue }
            $included = (@($u.includeUsers) -contains 'All') -or (@($u.includeUsers) -contains $a.id) -or
                (@(@($u.includeGroups) | Where-Object { $groups -contains $_ }).Count -gt 0) -or
                (@($u.includeRoles) -contains $globalAdminRole)
            if ($included) { $covered = $true; break }
        }
        if ($excludedSomewhere -and -not $covered) { $a.userPrincipalName }
    }
}

function Get-IamLicenceFinding {
    <#
    .SYNOPSIS
        One report row for a licensed user: which licences, how assigned, last sign-in, and
        whether the licence looks unused (Disabled, Never signed in, Inactive).
    .DESCRIPTION
        Pass a user from Get-MgUser with AssignedLicenses, LicenseAssignmentStates and, when the
        tenant has P1, SignInActivity. Without sign-in data (-NoSignInData) only disabled
        accounts are flagged. Break-glass accounts are marked as expected.
        Last sign-in is the latest of the interactive, non-interactive and successful sign-in.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$User,
        [hashtable]$SkuName = @{},
        [Parameter(Mandatory)][datetime]$Cutoff,
        [Parameter(Mandatory)][datetime]$Now,
        [string[]]$BreakGlass = @(),
        [switch]$NoSignInData
    )
    $skus = @($User.AssignedLicenses | ForEach-Object { "$($_.SkuId)" } | Where-Object { $_ })
    $names = @($skus | ForEach-Object { if ($SkuName.ContainsKey($_)) { $SkuName[$_] } else { $_ } } | Sort-Object)

    $states = @($User.LicenseAssignmentStates | Where-Object { $_ })
    $byGroup = @($states | Where-Object { $_.AssignedByGroup }).Count
    $assignedBy = if (-not $states.Count) { 'Unknown' }
    elseif ($byGroup -eq $states.Count) { 'Group' }
    elseif ($byGroup -eq 0) { 'Direct' }
    else { 'Direct and group' }

    $last = $null
    if (-not $NoSignInData) {
        $s = $User.SignInActivity
        $last = @($s.LastSignInDateTime, $s.LastNonInteractiveSignInDateTime, $s.LastSuccessfulSignInDateTime) |
            Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending | Select-Object -First 1
    }

    $finding = ''
    if ($BreakGlass -contains $User.UserPrincipalName) { $finding = 'Expected (break-glass)' }
    elseif (-not $User.AccountEnabled) { $finding = 'Disabled' }
    elseif ($NoSignInData) { $finding = '' }
    elseif (-not $last -and $User.CreatedDateTime -and [datetime]$User.CreatedDateTime -lt $Cutoff) { $finding = 'Never signed in' }
    elseif ($last -and $last -lt $Cutoff) { $finding = 'Inactive' }

    $action = switch ($finding) {
        'Disabled' {
            if ($assignedBy -eq 'Group') { 'Remove from the licensing group' }
            else { 'Remove the licence, unless a shared mailbox still needs it (over 50 GB, hold, archive)' }
        }
        { $_ -in 'Never signed in', 'Inactive' } { 'Check with the manager: offboard, or remove the licence' }
        default { '' }
    }

    [pscustomobject]@{
        DisplayName  = $User.DisplayName
        Upn          = $User.UserPrincipalName
        Source       = if ($User.OnPremisesSyncEnabled) { 'AD' } else { 'Cloud' }
        Enabled      = [bool]$User.AccountEnabled
        LastSignIn   = $last
        DaysInactive = if ($last) { [int][math]::Floor(($Now - $last).TotalDays) } else { $null }
        Licences     = ($names -join '; ')
        AssignedBy   = $assignedBy
        Finding      = $finding
        Action       = $action
    }
}

Export-ModuleMember -Function Write-IamLog, Test-IamEventSource, Import-IamConfig, Get-IamOutputPath, Get-IamUpnPrefix, Get-IamRandomPassword,
    ConvertTo-IamSecureString, Import-IamAdModule, Invoke-IamDeltaSync, Wait-IamCloudUser, Connect-IamGraph,
    Get-IamGraphAppScope, Assert-IamSyncState, Revoke-IamUserSession, Remove-IamUserLicense, Get-IamUserAuthMethod, Remove-IamUserAuthMethod,
    Connect-IamExchange, Get-IamMailboxState, Convert-IamMailboxToShared, Get-IamCloudManager, Test-IamExchangePlan,
    Test-IamOneDrivePlan, Get-IamLeaverHandover,
    Resolve-IamDelegate, Get-IamLeaverMailboxPlan, Get-IamValidManager, Get-IamAdManager, Set-IamCloudManager,
    Write-IamManagerWarning, Get-IamOutputFolder, Export-IamCsv, Invoke-IamGraphGetAll, Assert-IamGraphHost,
    Assert-IamVerifiedDomain, ConvertTo-IamImmutableId, Get-IamSyncedCloudUser, ConvertTo-IamAdAnchorMap,
    ConvertTo-IamConfigText, Test-IamOuInSyncScope, ConvertFrom-IamMsolDescription, Get-IamUpnFormatGuess,
    Get-IamBreakGlassCandidate, Get-IamLicenceFinding
