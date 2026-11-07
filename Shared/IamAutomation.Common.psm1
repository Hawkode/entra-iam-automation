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
    if (-not (Test-Path -Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Add-Content -Path (Join-Path -Path $outDir -ChildPath 'iam-automation.log') -Value $line
    Write-Information -MessageData $line -InformationAction Continue
}

function Import-IamConfig {
    [CmdletBinding()]
    param([string]$Path = (Join-Path -Path $script:RepoRoot -ChildPath 'config.local.psd1'))
    if (-not (Test-Path -Path $Path)) {
        throw "Config not found: $Path. Copy config.example.psd1 to config.local.psd1 and fill it in."
    }
    Import-PowerShellDataFile -Path $Path
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
    # Direct assignments only. Group-assigned licences go when the user leaves the group.
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$UserId)
    $skuIds = @(Get-MgUserLicenseDetail -UserId $UserId -ErrorAction Stop | Select-Object -ExpandProperty SkuId)
    if ($skuIds.Count -eq 0) { Write-IamLog -Message "No licences assigned: $UserId"; return }
    if ($PSCmdlet.ShouldProcess($UserId, "Remove $($skuIds.Count) licence(s)")) {
        Set-MgUserLicense -UserId $UserId -AddLicenses @() -RemoveLicenses $skuIds -ErrorAction Stop | Out-Null
        Write-IamLog -Message "Removed $($skuIds.Count) licence(s): $UserId"
    }
}

Export-ModuleMember -Function Write-IamLog, Import-IamConfig, Connect-IamGraph, Assert-IamSyncState, Revoke-IamUserSession, Remove-IamUserLicense