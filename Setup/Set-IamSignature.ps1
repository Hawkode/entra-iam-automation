<#
.SYNOPSIS
    Signs every script and module in a folder with your code-signing certificate, so they run
    where the execution policy is AllSigned or AppLocker allows signed scripts only. -Verify
    checks the signatures and changes nothing.

.DESCRIPTION
    Signs *.ps1 and *.psm1 (Authenticode, SHA256, timestamped) under -Path, leaving out .git and
    output. A timestamp keeps the signature valid after the certificate expires.

    Sign a deployed copy, not your git working copy: signing appends a signature block to every
    file, which git sees as a change. Every later edit to a file breaks its signature, so sign
    again after each update and run -Verify.

    Graph and other modules from the PowerShell Gallery are signed by Microsoft. Under AllSigned,
    PowerShell asks once whether to trust that publisher.

    The certificate comes from Cert:\CurrentUser\My or Cert:\LocalMachine\My, and must be a code
    signing certificate with its private key. For the lab, a self-signed one works once it is
    trusted (README, "Code signing").

.PARAMETER Path
    Folder to sign or verify. Default: this repo.

.PARAMETER Thumbprint
    Thumbprint of the code-signing certificate. Not needed with -Verify.

.PARAMETER TimestampServer
    RFC 3161 timestamp server. Default: http://timestamp.digicert.com. Empty: no timestamp
    (the signature then stops validating when the certificate expires).

.PARAMETER Verify
    Only report each file's signature status.

.PARAMETER Force
    Sign even though -Path is a git working copy.

.EXAMPLE
    .\Setup\Set-IamSignature.ps1 -Path C:\Tools\entra-iam-automation -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
.EXAMPLE
    .\Setup\Set-IamSignature.ps1 -Path C:\Tools\entra-iam-console -Verify
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Sign')]
param(
    [string]$Path = (Split-Path -Path $PSScriptRoot -Parent),
    [Parameter(Mandatory, ParameterSetName = 'Sign')][string]$Thumbprint,
    [Parameter(ParameterSetName = 'Sign')][string]$TimestampServer = 'http://timestamp.digicert.com',
    [Parameter(Mandatory, ParameterSetName = 'Verify')][switch]$Verify,
    [Parameter(ParameterSetName = 'Sign')][switch]$Force
)

$ErrorActionPreference = 'Stop'
if (-not ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows)) { throw 'Authenticode signing is Windows only.' }
if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Folder not found: $Path" }

$files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Include *.ps1, *.psm1 |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|output)[\\/]' })
if (-not $files.Count) { throw "No .ps1 or .psm1 files under $Path." }

if ($Verify) {
    $rows = foreach ($f in $files) {
        $s = Get-AuthenticodeSignature -FilePath $f.FullName
        [pscustomobject]@{
            File      = $f.FullName.Substring($Path.TrimEnd('\', '/').Length + 1)
            Status    = "$($s.Status)"
            Signer    = $s.SignerCertificate.Subject
            Timestamp = [bool]$s.TimeStamperCertificate
        }
    }
    $bad = @($rows | Where-Object Status -NE 'Valid')
    Write-Output "Signatures under ${Path}: $($rows.Count - $bad.Count) valid, $($bad.Count) not valid."
    if ($bad.Count) { $bad } else { $rows }
    return
}

if ((Test-Path -LiteralPath (Join-Path -Path $Path -ChildPath '.git')) -and -not $Force) {
    throw "$Path is a git working copy. Signing adds a signature block to every file, which git sees as a change. Sign a deployed copy (for example a release extracted to C:\Tools), or use -Force."
}
$cert = @(foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        Get-ChildItem -Path $store -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object Thumbprint -EQ $Thumbprint
    }) | Select-Object -First 1
if (-not $cert) { throw "No code-signing certificate with thumbprint $Thumbprint in CurrentUser\My or LocalMachine\My." }
if (-not $cert.HasPrivateKey) { throw "The certificate $($cert.Subject) has no private key on this machine." }
if ($cert.NotAfter -lt (Get-Date)) { throw "The certificate $($cert.Subject) expired on $($cert.NotAfter)." }

$what = "sign $($files.Count) file(s) with '$($cert.Subject)' (expires $($cert.NotAfter.ToString('d MMM yyyy')))"
if (-not $PSCmdlet.ShouldProcess($Path, $what)) { return }

$sign = @{ Certificate = $cert; HashAlgorithm = 'SHA256' }
if ($TimestampServer) { $sign.TimestampServer = $TimestampServer }
$results = foreach ($f in $files) {
    $s = Set-AuthenticodeSignature -FilePath $f.FullName @sign
    [pscustomobject]@{ File = $f.FullName.Substring($Path.TrimEnd('\', '/').Length + 1); Status = "$($s.Status)"; Message = $s.StatusMessage }
}
$bad = @($results | Where-Object Status -NE 'Valid')
Write-Output "Signed under ${Path}: $($results.Count - $bad.Count) valid, $($bad.Count) not valid."
if ($bad.Count) { $bad }
