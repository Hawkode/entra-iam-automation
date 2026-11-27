<#
.SYNOPSIS
    Registers the IamAutomation event source in the Windows Application log, once per machine,
    so every script and the IAM console also write their log lines to the event log.

.DESCRIPTION
    Needs an elevated PowerShell (local admin), once. After that the scripts write events as the
    operator without admin rights:
      ID 1000  Information   ID 2000  Warning   ID 3000  Error
    Each event holds the log line, the Windows account and the computer.

    Why: output\iam-automation.log is a working copy anyone with access to the folder can edit.
    A user cannot edit or delete single events, and clearing the Application log is itself logged
    (event 104 in the System log). For a record a local admin cannot touch either, forward the
    events to a collector (Windows Event Forwarding) or a SIEM.

    Read them:
      Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'IamAutomation' } -MaxEvents 20

.PARAMETER Remove
    Unregister the source. Events already written stay in the log.

.EXAMPLE
    .\Setup\Register-IamEventSource.ps1
.EXAMPLE
    .\Setup\Register-IamEventSource.ps1 -Remove
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$source = 'IamAutomation'

if (-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) { throw 'The Windows event log exists only on Windows.' }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this once from an elevated PowerShell (Run as administrator). The scripts themselves do not need admin rights afterwards.'
}

$exists = [System.Diagnostics.EventLog]::SourceExists($source)
if ($Remove) {
    if (-not $exists) { Write-Output "Event source '$source' is not registered. Nothing to remove."; return }
    if ($PSCmdlet.ShouldProcess($source, 'Unregister the event source')) {
        [System.Diagnostics.EventLog]::DeleteEventSource($source)
        Write-Output "Event source '$source' unregistered. Events already written stay in the Application log."
    }
    return
}

if ($exists) {
    $log = [System.Diagnostics.EventLog]::LogNameFromSourceName($source, '.')
    Write-Output "Event source '$source' is already registered (log: $log)."
    return
}
if ($PSCmdlet.ShouldProcess($source, 'Register the event source in the Application log')) {
    [System.Diagnostics.EventLog]::CreateEventSource($source, 'Application')
    $who = '{0}\{1}' -f [Environment]::UserDomainName, [Environment]::UserName
    [System.Diagnostics.EventLog]::WriteEntry($source, "Event source registered by $who on $env:COMPUTERNAME.", 'Information', 1000)
    Write-Output "Event source '$source' registered in the Application log. Check: Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = '$source' } -MaxEvents 1"
}
