<#
.SYNOPSIS
Installs pinned Pester and runs the test suite. Used by CI once per edition:
powershell.exe (Windows PowerShell 5.1) and pwsh (PowerShell 7). Exits with the
number of failed tests, so CI fails on any failure.

.EXAMPLE
powershell.exe -NoProfile -File .\build\Invoke-Tests.ps1
#>
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 can default to old TLS versions for the Gallery.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    # Install-Module needs the NuGet provider. Bootstrap it here so a
    # non-interactive run cannot stop on the install prompt.
    $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
}

$version = '5.9.1'
# SkipPublisherCheck: the inbox Pester 3.4 on Windows is signed by a different publisher.
Install-Module -Name Pester -RequiredVersion $version -Force -Scope CurrentUser -SkipPublisherCheck
Import-Module -Name Pester -RequiredVersion $version -Force
Write-Output "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), Pester $version"

$config = New-PesterConfiguration
$config.Run.Path = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'tests'
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
