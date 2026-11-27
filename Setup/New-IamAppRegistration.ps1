<#
.SYNOPSIS
    Creates the app registration the scripts and the IAM console sign in through, instead of
    Microsoft Graph Command Line Tools, and writes GraphClientId to config.local.psd1.

.DESCRIPTION
    Why: through the shared Microsoft Graph Command Line Tools app, each operator consents to
    the scopes for themselves, and a non-admin cannot consent to admin-level scopes ("Need admin
    approval"). Granting tenant-wide consent to that app instead gives those scopes to every user
    who runs Graph PowerShell. Your own app keeps them to this tool:

      - Single tenant, public client: http://localhost and the Windows broker (WAM) redirect URI
      - Delegated Microsoft Graph scopes only (Get-IamGraphAppScope). No application permissions,
        no secret, no certificate
      - Admin consent for those scopes, once, for the organisation
      - Assignment required: only the operators you assign can sign in through it
      - Operators: -OperatorGroup (assigning a group needs Entra ID P1) and/or -OperatorUpn

    A delegated scope never lets an operator do more than their Entra role allows.

    Afterwards, aim a Conditional Access policy at the app (phishing-resistant MFA, compliant or
    admin device). The last log line gives the app ID to target.

    Writes: the app registration, its enterprise app, the consent grant, the operator
    assignments, and GraphClientId in config.local.psd1 (after a backup). Asks once first.
    Undo: Entra admin center > App registrations > the app > Delete, then empty GraphClientId
    in config.local.psd1.

    Graph scopes for this run (delegated, through Microsoft Graph Command Line Tools):
      Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
      DelegatedPermissionGrant.ReadWrite.All, Group.Read.All, User.Read.All
    Role: Global Administrator or Privileged Role Administrator (admin consent for Microsoft Graph).

.PARAMETER DisplayName
    Name of the app registration. Default: IAM Automation.

.PARAMETER OperatorGroup
    Display name of the group whose members may sign in. Needs Entra ID P1.

.PARAMETER OperatorUpn
    Users who may sign in, instead of or as well as a group.

.PARAMETER Path
    Config file to update. Default: config.local.psd1 in the repo root.

.EXAMPLE
    .\Setup\New-IamAppRegistration.ps1 -OperatorGroup 'IAM Operators' -WhatIf
    Signs in, checks everything and shows the plan. Creates nothing.
.EXAMPLE
    .\Setup\New-IamAppRegistration.ps1 -OperatorUpn jdoe@contoso.com, asmith@contoso.com
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()][string]$DisplayName = 'IAM Automation',
    [string]$OperatorGroup,
    [string[]]$OperatorUpn,
    [string]$Path
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\Shared\IamAutomation.Common.psm1') -Force

if (-not $OperatorGroup -and -not $OperatorUpn) {
    throw 'Name who may sign in: -OperatorGroup, -OperatorUpn, or both. With Assignment required, nobody else can.'
}
if (-not $Path) { $Path = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'config.local.psd1' }
$cfg = Import-IamConfig -Path $Path
if ("$($cfg.GraphClientId)".Trim()) {
    throw "GraphClientId is already set ($($cfg.GraphClientId)). Delete that app registration and empty the key first, or keep using it."
}

function Invoke-IamRetry {
    # A new app takes a few seconds to reach every directory replica: retry instead of failing.
    param([Parameter(Mandatory)][scriptblock]$Action, [Parameter(Mandatory)][string]$What)
    for ($i = 1; $i -le 6; $i++) {
        try { return (& $Action) }
        catch {
            if ($i -eq 6) { throw "$What failed: $($_.Exception.Message)" }
            Start-Sleep -Seconds 5
        }
    }
}

function Get-IamFilterUri {
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Value, [string]$Select = 'id,displayName')
    $quoted = $Value.Replace("'", "''")
    "$Base`?`$filter=$([uri]::EscapeDataString("displayName eq '$quoted'"))&`$select=$Select"
}

# Sign in through Microsoft Graph Command Line Tools, whatever the config says: the app does not exist yet.
Connect-IamGraph -TenantId $cfg.TenantId -ClientId '' -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
'DelegatedPermissionGrant.ReadWrite.All', 'Group.Read.All', 'User.Read.All'

# ---- Read and check everything before changing anything ----
$graphAppId = '00000003-0000-0000-c000-000000000000'
$existing = @((Invoke-MgGraphRequest -Method GET -Uri (Get-IamFilterUri -Base 'v1.0/applications' -Value $DisplayName -Select 'id,appId')).value)
if ($existing.Count) { throw "An app registration named '$DisplayName' already exists (app ID $($existing[0].appId)). Use -DisplayName, or delete it first." }

$graphSp = Invoke-MgGraphRequest -Method GET -Uri "v1.0/servicePrincipals(appId='$graphAppId')?`$select=id,oauth2PermissionScopes"
$scopes = @(Get-IamGraphAppScope)
$scopeIds = foreach ($s in $scopes) {
    $hit = @($graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq $s })
    if (-not $hit.Count) { throw "Microsoft Graph has no delegated scope '$s' in this tenant." }
    $hit[0].id
}

$operators = @()
if ($OperatorGroup) {
    $groups = @((Invoke-MgGraphRequest -Method GET -Uri (Get-IamFilterUri -Base 'v1.0/groups' -Value $OperatorGroup)).value)
    if ($groups.Count -ne 1) { throw "Expected one group named '$OperatorGroup', found $($groups.Count)." }
    $operators += [pscustomobject]@{ Id = $groups[0].id; Name = "group $($groups[0].displayName)" }
}
foreach ($upn in $OperatorUpn) {
    $u = Invoke-MgGraphRequest -Method GET -Uri "v1.0/users/$([uri]::EscapeDataString($upn))?`$select=id,userPrincipalName"
    $operators += [pscustomobject]@{ Id = $u.id; Name = $u.userPrincipalName }
}

$plan = "create app registration '$DisplayName' (single tenant, public client, $($scopes.Count) delegated Graph scopes), " +
"grant admin consent, require assignment, assign $(($operators.Name) -join ', '), write GraphClientId to $Path"
Write-IamLog -Message "Plan: $plan"
Write-IamLog -Message "Scopes: $($scopes -join ', ')"
if (-not $PSCmdlet.ShouldProcess($DisplayName, $plan)) { return }

# ---- Create ----
$body = @{
    displayName            = $DisplayName
    signInAudience         = 'AzureADMyOrg'
    publicClient           = @{ redirectUris = @('http://localhost') }
    requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = @($scopeIds | ForEach-Object { @{ id = $_; type = 'Scope' } }) })
}
$app = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/applications' -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json'
Write-IamLog -Message "Created app registration '$DisplayName': app ID $($app.appId)"

try {
    # The Windows broker (WAM) redirect URI includes the app ID, so it can only be added now.
    $uris = @{ publicClient = @{ redirectUris = @('http://localhost', "ms-appx-web://Microsoft.AAD.BrokerPlugin/$($app.appId)") } } | ConvertTo-Json -Depth 4
    Invoke-IamRetry -What 'Adding the broker redirect URI' -Action {
        Invoke-MgGraphRequest -Method PATCH -Uri "v1.0/applications/$($app.id)" -Body $uris -ContentType 'application/json' | Out-Null
    }

    $spBody = @{ appId = $app.appId; appRoleAssignmentRequired = $true; tags = @('WindowsAzureActiveDirectoryIntegratedApp', 'HideApp') } | ConvertTo-Json
    $sp = Invoke-IamRetry -What 'Creating the enterprise app' -Action {
        Invoke-MgGraphRequest -Method POST -Uri 'v1.0/servicePrincipals' -Body $spBody -ContentType 'application/json'
    }
    Write-IamLog -Message "Enterprise app created with Assignment required: $($sp.id)"

    $grant = @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = ($scopes -join ' ') } | ConvertTo-Json
    Invoke-IamRetry -What 'Granting admin consent' -Action {
        Invoke-MgGraphRequest -Method POST -Uri 'v1.0/oauth2PermissionGrants' -Body $grant -ContentType 'application/json' | Out-Null
    }
    Write-IamLog -Message "Admin consent granted for the organisation: $($scopes.Count) delegated scopes"

    foreach ($o in $operators) {
        $assign = @{ principalId = $o.Id; resourceId = $sp.id; appRoleId = [guid]::Empty.Guid } | ConvertTo-Json
        Invoke-IamRetry -What "Assigning $($o.Name)" -Action {
            Invoke-MgGraphRequest -Method POST -Uri "v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body $assign -ContentType 'application/json' | Out-Null
        }
        Write-IamLog -Message "Assigned $($o.Name) to '$DisplayName'"
    }
}
catch {
    Write-IamLog -Level ERROR -Message "Stopped after creating the app registration (app ID $($app.appId)). Finish it in Entra admin center, or delete it and run again. $($_.Exception.Message)"
    throw
}

# ---- Config ----
$text = Get-Content -LiteralPath $Path -Raw
$line = "    GraphClientId        = '$($app.appId)'"
if ($text -match '(?m)^\s*GraphClientId\s*=.*$') { $text = $text -replace '(?m)^\s*GraphClientId\s*=.*$', $line }
else {
    $end = $text.LastIndexOf('}')
    $text = $text.Substring(0, $end).TrimEnd() + "`r`n`r`n    # Own app registration (Setup\New-IamAppRegistration.ps1). Empty = Microsoft Graph Command Line Tools.`r`n$line`r`n}`r`n"
}
$backup = '{0}.bak-{1:yyyyMMdd-HHmmss}' -f $Path, (Get-Date)
Copy-Item -LiteralPath $Path -Destination $backup
Set-Content -LiteralPath $Path -Value $text -Encoding utf8 -NoNewline -WhatIf:$false
$null = Import-IamConfig -Path $Path
Write-IamLog -Message "GraphClientId written to $Path (backup: $backup)"
Write-IamLog -Message "Next: Conditional Access policy aimed at app ID $($app.appId), then Disconnect-MgGraph and sign in again so the scripts use the new app."

[pscustomobject]@{
    DisplayName        = $DisplayName
    ClientId           = $app.appId
    ServicePrincipalId = $sp.id
    Operators          = ($operators.Name -join ', ')
    Scopes             = $scopes.Count
}
