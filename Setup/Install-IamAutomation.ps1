<#
.SYNOPSIS
    Sets up a machine to run the scripts and the IAM console: checks PowerShell 7, installs the
    Microsoft Graph modules the scripts use, unblocks the files, registers the event log source
    and adds a Start menu shortcut for the console.

.DESCRIPTION
    Run it from the folder you will run the scripts from (a release copy, for example
    C:\Tools\entra-iam-automation), in PowerShell 7. It shows the plan and asks once.

    Changes, in order:
      1. Installs the Microsoft Graph submodules the scripts use, all at one version (the newest
         on the PowerShell Gallery, or -GraphVersion). Not the whole Microsoft.Graph roll-up, and
         never mixed versions, which break sign-in. Modules already at that version are skipped.
      2. With -IncludeExchange: ExchangeOnlineManagement, for -ConvertMailbox.
      3. Unblocks the files (downloaded zips are marked as coming from the internet).
      4. Registers the IamAutomation event log source, when run elevated.
      5. With -ConsolePath: a Start menu shortcut "Entra IAM Console".

    Reports, never changes: the ActiveDirectory module (RSAT, for the hybrid scripts), the
    execution policy, config.local.psd1 and GraphClientId. Those are decisions for you.

    Run it again to move every Graph module to a newer version together.

.PARAMETER Scope
    CurrentUser (default) or AllUsers. AllUsers needs an elevated PowerShell; use it on a shared
    jump box, so every operator gets the same module versions.

.PARAMETER GraphVersion
    Microsoft Graph module version to install. Default: the newest on the PowerShell Gallery.

.PARAMETER IncludeExchange
    Also install ExchangeOnlineManagement, for -ConvertMailbox on the leavers.

.PARAMETER ConsolePath
    Folder of the IAM console (entra-iam-console). Adds a Start menu shortcut that starts it with
    this automation folder.

.EXAMPLE
    .\Setup\Install-IamAutomation.ps1 -WhatIf
.EXAMPLE
    .\Setup\Install-IamAutomation.ps1 -Scope AllUsers -ConsolePath C:\Tools\entra-iam-console
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('CurrentUser', 'AllUsers')][string]$Scope = 'CurrentUser',
    [version]$GraphVersion,
    [switch]$IncludeExchange,
    [string]$ConsolePath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Path $PSScriptRoot -Parent

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Run this in PowerShell 7 (pwsh). Install it with: winget install --id Microsoft.PowerShell --source winget'
}
$isWin = $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows
$elevated = $false
if ($isWin) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if ($Scope -eq 'AllUsers' -and -not $elevated) { throw '-Scope AllUsers needs an elevated PowerShell (Run as administrator).' }

# The Graph submodules behind the cmdlets the scripts call. Invoke-MgGraphRequest and sign-in
# live in Microsoft.Graph.Authentication.
$graphModules = @(
    'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Users.Actions',
    'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Applications', 'Microsoft.Graph.DirectoryObjects'
)

# ---- Read and check first ----
if (-not $GraphVersion) {
    $GraphVersion = [version](Find-Module -Name 'Microsoft.Graph.Authentication' -Repository PSGallery).Version
}
$toInstall = @(foreach ($m in $graphModules) {
        $have = @(Get-Module -ListAvailable -Name $m | Where-Object { $_.Version -eq $GraphVersion })
        if (-not $have.Count) { $m }
    })
$exchangeMissing = $IncludeExchange -and -not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)
$eventSource = $false
if ($isWin) { try { $eventSource = [System.Diagnostics.EventLog]::SourceExists('IamAutomation') } catch { $eventSource = $false } }

$consoleScript = $null
if ($ConsolePath) {
    if (-not $isWin) { throw 'The IAM console runs on Windows only.' }
    $consoleScript = Join-Path -Path $ConsolePath -ChildPath 'Start-IamConsole.ps1'
    if (-not (Test-Path -LiteralPath $consoleScript)) { throw "Start-IamConsole.ps1 not found in $ConsolePath." }
}

$plan = @()
if ($toInstall.Count) { $plan += "install $($toInstall.Count) Microsoft Graph module(s) at $GraphVersion ($Scope)" }
if ($exchangeMissing) { $plan += "install ExchangeOnlineManagement ($Scope)" }
$plan += 'unblock the files'
if ($isWin -and -not $eventSource -and $elevated) { $plan += 'register the IamAutomation event log source' }
if ($consoleScript) { $plan += 'add the Start menu shortcut "Entra IAM Console"' }
Write-Output "Plan: $($plan -join '; ')."
if (-not $PSCmdlet.ShouldProcess($root, ($plan -join '; '))) { return }

# ---- Change ----
$results = [System.Collections.Generic.List[object]]::new()
function Add-IamResult { param([string]$Step, [string]$Result) $results.Add([pscustomobject]@{ Step = $Step; Result = $Result }) }

foreach ($m in $graphModules) {
    if ($toInstall -contains $m) {
        # -Force answers the untrusted-repository prompt for PSGallery; the version is pinned.
        Install-Module -Name $m -RequiredVersion $GraphVersion -Scope $Scope -Repository PSGallery -Force -AllowClobber
        Add-IamResult -Step $m -Result "Installed $GraphVersion"
    }
    else { Add-IamResult -Step $m -Result "Already $GraphVersion" }
}
if ($IncludeExchange) {
    if ($exchangeMissing) {
        Install-Module -Name ExchangeOnlineManagement -Scope $Scope -Repository PSGallery -Force
        Add-IamResult -Step 'ExchangeOnlineManagement' -Result 'Installed'
    }
    else { Add-IamResult -Step 'ExchangeOnlineManagement' -Result 'Already installed' }
}

$folders = @($root) + @($ConsolePath | Where-Object { $_ })
$all = @(Get-ChildItem -LiteralPath $folders -Recurse -File)
$all | Unblock-File -ErrorAction SilentlyContinue
Add-IamResult -Step 'Unblock files' -Result "$($all.Count) file(s) checked"

if (-not $isWin) { Add-IamResult -Step 'Event log' -Result 'Not on Windows: log file only' }
elseif ($eventSource) { Add-IamResult -Step 'Event log' -Result 'IamAutomation already registered' }
elseif ($elevated) {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Register-IamEventSource.ps1') -Confirm:$false | Out-Null
    Add-IamResult -Step 'Event log' -Result 'IamAutomation registered'
}
else { Add-IamResult -Step 'Event log' -Result 'Not registered: run .\Setup\Register-IamEventSource.ps1 once, elevated' }

if ($consoleScript) {
    $menu = if ($Scope -eq 'AllUsers') { [Environment]::GetFolderPath('CommonPrograms') } else { [Environment]::GetFolderPath('Programs') }
    $lnk = Join-Path -Path $menu -ChildPath 'Entra IAM Console.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($lnk)
    $sc.TargetPath = (Get-Command -Name pwsh.exe).Source
    $sc.Arguments = "-NoProfile -File `"$consoleScript`" -AutomationPath `"$root`""
    $sc.WorkingDirectory = $ConsolePath
    $sc.WindowStyle = 7   # minimised: the console window stays out of the way, start-up errors stay visible
    $sc.Description = 'Entra IAM Console'
    $sc.Save()
    Add-IamResult -Step 'Start menu' -Result $lnk
}

# ---- Report only ----
$ad = if (-not $isWin) { 'Not on Windows: cloud scripts only' }
elseif (Get-Module -ListAvailable -Name ActiveDirectory) { 'Present: hybrid scripts can run here (domain-joined machine needed)' }
else { 'Missing: cloud scripts only. Hybrid needs RSAT (Windows 11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0)' }
Add-IamResult -Step 'ActiveDirectory module' -Result $ad
if ($isWin) { Add-IamResult -Step 'Execution policy' -Result "$(Get-ExecutionPolicy) (RemoteSigned or AllSigned: see the README for signing)" }
$cfg = Join-Path -Path $root -ChildPath 'config.local.psd1'
Add-IamResult -Step 'config.local.psd1' -Result $(if (Test-Path -LiteralPath $cfg) { 'Present' } else { 'Missing: run .\Setup\New-IamConfig.ps1' })

$results
