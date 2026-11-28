#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Unit tests for Shared/IamAutomation.Common.psm1. No tenant needed: Graph and Exchange
# calls are mocked, and anything that writes files is pointed at Pester's TestDrive.

BeforeAll {
    $script:modulePath = Join-Path -Path (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Shared') -ChildPath 'IamAutomation.Common.psm1'
    Import-Module -Name $script:modulePath -Force

    # Stand-ins for the Graph cmdlets the module calls, so Pester can mock them on a runner
    # without the Graph SDK. Each one throws if a test reaches it without a mock.
    New-Module -Name IamGraphStub -ScriptBlock {
        function Get-MgUser {
            [CmdletBinding()]
            param([string]$UserId, [string]$Filter, [string[]]$Property)
            throw "Get-MgUser reached without a mock: $UserId $Filter $Property"
        }
        function Get-MgOrganization {
            [CmdletBinding()]
            param([string[]]$Property)
            throw "Get-MgOrganization reached without a mock: $Property"
        }
        function Invoke-MgGraphRequest {
            [CmdletBinding()]
            param([string]$Method, [string]$Uri, [object]$Body, [string]$ContentType)
            throw "Invoke-MgGraphRequest reached without a mock: $Method $Uri $Body $ContentType"
        }
        function Connect-MgGraph {
            [CmdletBinding()]
            param([string]$TenantId, [string[]]$Scopes, [string]$ClientId, [switch]$NoWelcome)
            throw "Connect-MgGraph reached without a mock: $TenantId $Scopes $ClientId $NoWelcome"
        }
        function Get-MgContext {
            [CmdletBinding()]
            param()
            throw 'Get-MgContext reached without a mock'
        }
    } | Import-Module -Force

    $script:tenantId = '11111111-2222-3333-4444-555555555555'
}

AfterAll {
    Remove-Module -Name IamAutomation.Common, IamGraphStub -Force -ErrorAction SilentlyContinue
}

Describe 'Module' {
    It 'exports every function except the internal UPN helper' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:modulePath, [ref]$null, [ref]$null)
        $defined = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
                ForEach-Object { $_.Name } | Where-Object { $_ -ne 'ConvertTo-IamUpnPart' } | Sort-Object)
        $exported = @((Get-Module -Name IamAutomation.Common).ExportedFunctions.Keys | Sort-Object)
        ($exported -join ',') | Should -Be ($defined -join ',')
    }

    It 'keeps ConvertTo-IamUpnPart private' {
        Get-Command -Module IamAutomation.Common -Name ConvertTo-IamUpnPart -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Describe 'Get-IamUpnPrefix' {
    It 'builds <Expected> from <Format>' -ForEach @(
        @{ Format = '{given}.{surname}'; Expected = 'jane.smith' }
        @{ Format = '{g}{surname}'; Expected = 'jsmith' }
        @{ Format = '{given}{s}'; Expected = 'janes' }
        @{ Format = '{surname}.{given}'; Expected = 'smith.jane' }
    ) {
        Get-IamUpnPrefix -GivenName 'Jane' -Surname 'Smith' -Format $Format | Should -Be $Expected
    }

    It 'uses {given}.{surname} by default' {
        Get-IamUpnPrefix -GivenName 'Jane' -Surname 'Smith' | Should -Be 'jane.smith'
    }

    It 'strips accents: <Given> <Surname> becomes <Expected>' -ForEach @(
        # S with comma below and a with breve (Romanian), e and i with acute (Spanish).
        @{ Given = "$([char]0x0218)tefan"; Surname = "B$([char]0x0103)lan"; Expected = 'stefan.balan' }
        @{ Given = "Jos$([char]0x00E9)"; Surname = "Garc$([char]0x00ED)a"; Expected = 'jose.garcia' }
    ) {
        Get-IamUpnPrefix -GivenName $Given -Surname $Surname | Should -Be $Expected
    }

    It 'drops spaces and apostrophes and keeps hyphens' {
        Get-IamUpnPrefix -GivenName 'Mary Ann' -Surname "O'Brien-Jones" | Should -Be 'maryann.obrien-jones'
    }

    It 'throws on an unknown token' {
        { Get-IamUpnPrefix -GivenName 'Jane' -Surname 'Smith' -Format '{first}.{last}' } | Should -Throw '*unknown token*'
    }

    It 'throws on a result that is not a valid prefix' {
        { Get-IamUpnPrefix -GivenName 'Jane' -Surname 'Smith' -Format '{given}..{surname}' } | Should -Throw '*is not valid*'
    }

    It 'throws when a name has no usable characters' {
        { Get-IamUpnPrefix -GivenName "$([char]0x738B)" -Surname 'Smith' } | Should -Throw '*no characters usable*'
    }
}

Describe 'Get-IamRandomPassword' {
    It 'is 20 characters by default' {
        (Get-IamRandomPassword).Length | Should -Be 20
    }

    It 'honours -Length' {
        (Get-IamRandomPassword -Length 32).Length | Should -Be 32
    }

    It 'always has upper, lower, digit and symbol, and never I, O, l, o, 0 or 1' {
        1..50 | ForEach-Object {
            $pw = Get-IamRandomPassword -Length 14
            $pw | Should -MatchExactly '[A-Z]'
            $pw | Should -MatchExactly '[a-z]'
            $pw | Should -Match '[0-9]'
            $pw | Should -Match '[^A-Za-z0-9]'
            $pw | Should -MatchExactly '^[A-HJ-NP-Za-km-np-z2-9!#%*+=?@-]+$'
        }
    }

    It 'does not repeat itself' {
        Get-IamRandomPassword | Should -Not -Be (Get-IamRandomPassword)
    }

    It 'rejects length <Length>' -ForEach @(@{ Length = 13 }, @{ Length = 129 }) {
        { Get-IamRandomPassword -Length $Length } | Should -Throw
    }
}

Describe 'ConvertTo-IamSecureString' {
    It 'returns a read-only SecureString that holds the text' {
        $secure = ConvertTo-IamSecureString -Text 'Example-Pass-42'
        $secure | Should -BeOfType ([System.Security.SecureString])
        $secure.Length | Should -Be 15
        $secure.IsReadOnly() | Should -BeTrue
        [System.Net.NetworkCredential]::new('', $secure).Password | Should -Be 'Example-Pass-42'
    }
}

Describe 'Import-IamConfig' {
    BeforeAll {
        function Write-TestConfig {
            param([Parameter(Mandatory)][string]$Body)
            $path = Join-Path -Path $TestDrive -ChildPath ('config-{0}.psd1' -f [guid]::NewGuid())
            Set-Content -LiteralPath $path -Value $Body
            $path
        }
    }

    It 'throws when the file is missing' {
        { Import-IamConfig -Path (Join-Path -Path $TestDrive -ChildPath 'missing.psd1') } | Should -Throw '*Config not found*'
    }

    It 'returns the config when every required key is filled in' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; Domain = 'lab.example.org'; Licences = @{ Sales = 'lab:SPE_E3' } }"
        $cfg = Import-IamConfig -Path $path -Require Domain, Licences
        $cfg.Domain | Should -Be 'lab.example.org'
        $cfg.Licences.Sales | Should -Be 'lab:SPE_E3'
    }

    It 'rejects a TenantId of <Value>' -ForEach @(
        @{ Value = '00000000-0000-0000-0000-000000000000' }
        @{ Value = 'contoso.onmicrosoft.com' }
        @{ Value = '' }
    ) {
        $path = Write-TestConfig -Body "@{ TenantId = '$Value' }"
        $err = { Import-IamConfig -Path $path } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'TenantId must be your tenant ID'
    }

    It 'rejects a required key that is missing' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)' }"
        $err = { Import-IamConfig -Path $path -Require UsageLocation } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'UsageLocation is missing or empty'
    }

    It 'rejects a required key that is only whitespace' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; Domain = '   ' }"
        $err = { Import-IamConfig -Path $path -Require Domain } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'Domain is missing or empty'
    }

    It 'rejects a value still copied from config.example.psd1' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; Domain = 'contoso.com' }"
        $err = { Import-IamConfig -Path $path -Require Domain } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'Domain still has the example value'
    }

    It 'checks the values inside a nested table' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; Licences = @{ Sales = 'contoso:ENTERPRISEPACK' } }"
        $err = { Import-IamConfig -Path $path -Require Licences } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'Licences still has the example value'
    }

    It 'lists every problem in one error' {
        $path = Write-TestConfig -Body "@{ TenantId = 'not-a-guid'; Domain = 'contoso.com' }"
        $err = { Import-IamConfig -Path $path -Require Domain, UsageLocation } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'TenantId must be your tenant ID'
        $err.Exception.Message | Should -Match 'Domain still has the example value'
        $err.Exception.Message | Should -Match 'UsageLocation is missing or empty'
    }
}

Describe 'GraphClientId' {
    BeforeAll {
        function Write-TestConfig {
            param([Parameter(Mandatory)][string]$Body)
            $path = Join-Path -Path $TestDrive -ChildPath ('config-{0}.psd1' -f [guid]::NewGuid())
            Set-Content -LiteralPath $path -Value $Body
            $path
        }
        $script:appId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Mock Assert-IamGraphHost -ModuleName IamAutomation.Common
        Mock Write-IamLog -ModuleName IamAutomation.Common
        Mock Connect-MgGraph -ModuleName IamAutomation.Common
        Mock Get-MgContext -ModuleName IamAutomation.Common -MockWith { [pscustomobject]@{ TenantId = 't'; Account = 'jdoe@contoso.com'; Scopes = @('User.Read') } }
    }

    It 'accepts a config without GraphClientId' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)' }"
        { Import-IamConfig -Path $path } | Should -Not -Throw
    }

    It 'rejects a GraphClientId that is not a GUID' {
        $path = Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; GraphClientId = 'my-app' }"
        $err = { Import-IamConfig -Path $path } | Should -Throw -PassThru
        $err.Exception.Message | Should -Match 'GraphClientId must be the Application \(client\) ID'
    }

    It 'signs in through the app in the config' {
        $null = Import-IamConfig -Path (Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; GraphClientId = '$($script:appId)' }")
        Connect-IamGraph -TenantId $script:tenantId -Scopes 'User.Read.All'
        Should -Invoke Connect-MgGraph -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter { $ClientId -eq $script:appId }
    }

    It 'signs in through Microsoft Graph Command Line Tools when GraphClientId is empty' {
        $null = Import-IamConfig -Path (Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; GraphClientId = '' }")
        Connect-IamGraph -TenantId $script:tenantId -Scopes 'User.Read.All'
        Should -Invoke Connect-MgGraph -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter { -not $ClientId }
    }

    It 'lets -ClientId override the config' {
        $null = Import-IamConfig -Path (Write-TestConfig -Body "@{ TenantId = '$($script:tenantId)'; GraphClientId = '$($script:appId)' }")
        Connect-IamGraph -TenantId $script:tenantId -Scopes 'User.Read.All' -ClientId ''
        Should -Invoke Connect-MgGraph -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter { -not $ClientId }
    }
}

Describe 'Get-IamGraphAppScope' {
    It 'covers every scope a script asks Connect-IamGraph for' {
        # Scopes are quoted strings on Connect-IamGraph lines or in $scopes assignments.
        # New-IamAppRegistration.ps1 signs in through Microsoft Graph Command Line Tools, so it is left out.
        $root = Split-Path -Path $PSScriptRoot -Parent
        $files = Get-ChildItem -Path $root -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' -and $_.Name -ne 'New-IamAppRegistration.ps1' }
        $asked = foreach ($f in $files) {
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                if ($line -match 'Connect-IamGraph|\$scopes\s*\+?=') {
                    [regex]::Matches($line, "'([A-Za-z]+(-[A-Za-z]+)?\.[A-Za-z.]+)'") | ForEach-Object { $_.Groups[1].Value }
                }
            }
        }
        $asked = @($asked | Sort-Object -Unique)
        $asked.Count | Should -BeGreaterThan 10
        $missing = @($asked | Where-Object { (Get-IamGraphAppScope) -notcontains $_ })
        $missing | Should -BeNullOrEmpty
    }
}

Describe 'Output files' {
    It 'Get-IamOutputPath returns a timestamped CSV in the output folder and creates it' {
        InModuleScope IamAutomation.Common -Parameters @{ Dir = $TestDrive } {
            $saved = $script:RepoRoot
            try {
                $script:RepoRoot = $Dir
                $path = Get-IamOutputPath -Prefix 'stale-accounts'
                Split-Path -Path $path -Parent | Should -Be (Join-Path -Path $Dir -ChildPath 'output')
                Split-Path -Path $path -Leaf | Should -Match '^stale-accounts-\d{8}-\d{6}\.csv$'
                Test-Path -LiteralPath (Join-Path -Path $Dir -ChildPath 'output') -PathType Container | Should -BeTrue
            }
            finally { $script:RepoRoot = $saved }
        }
    }

    It 'Get-IamOutputFolder creates a named folder under output' {
        InModuleScope IamAutomation.Common -Parameters @{ Dir = $TestDrive } {
            $saved = $script:RepoRoot
            try {
                $script:RepoRoot = $Dir
                $folder = Get-IamOutputFolder -Name 'access-review-2026-11'
                $folder | Should -Be (Join-Path -Path (Join-Path -Path $Dir -ChildPath 'output') -ChildPath 'access-review-2026-11')
                Test-Path -LiteralPath $folder -PathType Container | Should -BeTrue
            }
            finally { $script:RepoRoot = $saved }
        }
    }

    It 'Get-IamOutputFolder rejects <Name>' -ForEach @(
        @{ Name = '..\escape' }
        @{ Name = 'a/b' }
        @{ Name = 'c:d' }
        @{ Name = '.hidden' }
    ) {
        { Get-IamOutputFolder -Name $Name } | Should -Throw '*does not allow*'
    }

    It 'Write-IamLog appends a timestamped line with the level' {
        InModuleScope IamAutomation.Common -Parameters @{ Dir = $TestDrive } {
            $saved = $script:RepoRoot
            try {
                $script:RepoRoot = $Dir
                Write-IamLog -Message 'test line' -Level WARN 6>$null
                $log = Join-Path -Path (Join-Path -Path $Dir -ChildPath 'output') -ChildPath 'iam-automation.log'
                $lines = @(Get-Content -LiteralPath $log)
                $lines[-1] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} \[WARN\] test line$'
            }
            finally { $script:RepoRoot = $saved }
        }
    }

    It 'Write-IamLog copies the line to the event log with the level, ID and Windows account' {
        InModuleScope IamAutomation.Common -Parameters @{ Dir = $TestDrive } {
            $saved = $script:RepoRoot, $script:IamEventLogOn, $script:IamEventWriter
            try {
                $script:RepoRoot = $Dir
                $script:IamEventLogOn = $true
                $script:captured = [System.Collections.Generic.List[object]]::new()
                $script:IamEventWriter = { param($s, $m, $t, $i) $script:captured.Add([pscustomobject]@{ Source = $s; Message = $m; Type = $t; Id = $i }) }
                Write-IamLog -Message 'audit line' -Level WARN 6>$null
                $script:captured.Count | Should -Be 1
                $script:captured[0].Source | Should -Be 'IamAutomation'
                $script:captured[0].Type | Should -Be 'Warning'
                $script:captured[0].Id | Should -Be 2000
                $script:captured[0].Message | Should -Match '^audit line'
                $script:captured[0].Message | Should -Match 'Windows account: '
            }
            finally { $script:RepoRoot, $script:IamEventLogOn, $script:IamEventWriter = $saved }
        }
    }

    It 'Write-IamLog writes the file only when the event source is not registered' {
        InModuleScope IamAutomation.Common -Parameters @{ Dir = $TestDrive } {
            $saved = $script:RepoRoot, $script:IamEventLogOn, $script:IamEventWriter
            try {
                $script:RepoRoot = $Dir
                $script:IamEventLogOn = $false
                $script:IamEventWriter = { throw 'event log reached' }
                { Write-IamLog -Message 'file only' 6>$null } | Should -Not -Throw
                (Get-Content -LiteralPath (Join-Path -Path (Join-Path -Path $Dir -ChildPath 'output') -ChildPath 'iam-automation.log'))[-1] | Should -Match 'file only$'
            }
            finally { $script:RepoRoot, $script:IamEventLogOn, $script:IamEventWriter = $saved }
        }
    }

    It 'Write-IamLog falls back to the file when an event log write fails' {
        InModuleScope IamAutomation.Common -Parameters @{ Dir = $TestDrive } {
            $saved = $script:RepoRoot, $script:IamEventLogOn, $script:IamEventWriter
            try {
                $script:RepoRoot = $Dir
                $script:IamEventLogOn = $true
                $script:IamEventWriter = { throw 'access denied' }
                { Write-IamLog -Message 'still in the file' 6>$null 3>$null } | Should -Not -Throw
                $script:IamEventLogOn | Should -BeFalse
                (Get-Content -LiteralPath (Join-Path -Path (Join-Path -Path $Dir -ChildPath 'output') -ChildPath 'iam-automation.log'))[-1] | Should -Match 'still in the file$'
            }
            finally { $script:RepoRoot, $script:IamEventLogOn, $script:IamEventWriter = $saved }
        }
    }

    It 'Test-IamEventSource is false off Windows and never throws' {
        { Test-IamEventSource -Source "IamTest$([guid]::NewGuid().ToString('N').Substring(0, 8))" } | Should -Not -Throw
        Test-IamEventSource -Source "IamTest$([guid]::NewGuid().ToString('N').Substring(0, 8))" | Should -BeFalse
    }

    It 'Write-IamLog rejects an unknown level' {
        { Write-IamLog -Message 'x' -Level DEBUG } | Should -Throw
    }

    It 'Export-IamCsv writes UTF-8 with a BOM, so Excel keeps accented names' {
        $path = Join-Path -Path $TestDrive -ChildPath 'bom.csv'
        $name = "Ana B$([char]0x0103)lan"
        Export-IamCsv -InputObject @([pscustomobject]@{ Name = $name }) -Path $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        ($bytes[0..2] -join ',') | Should -Be '239,187,191'
        (Import-Csv -LiteralPath $path -Encoding UTF8).Name | Should -Be $name
    }
}

Describe 'Test-IamExchangePlan' {
    It 'is <Expected> for <Case>' -ForEach @(
        @{ Case = 'an enabled Exchange plan'; Service = 'exchange'; Status = 'Enabled'; Expected = $true }
        @{ Case = 'a deleted Exchange plan'; Service = 'exchange'; Status = 'Deleted'; Expected = $false }
        @{ Case = 'another service only'; Service = 'SharePoint'; Status = 'Enabled'; Expected = $false }
    ) {
        $user = [pscustomobject]@{ AssignedPlans = @([pscustomobject]@{ Service = $Service; CapabilityStatus = $Status }) }
        Test-IamExchangePlan -User $user | Should -Be $Expected
    }

    It 'is false with no plans' {
        Test-IamExchangePlan -User ([pscustomobject]@{ AssignedPlans = @() }) | Should -BeFalse
    }
}

Describe 'Test-IamOneDrivePlan' {
    It 'is <Expected> for <Case>' -ForEach @(
        @{ Case = 'an enabled SharePoint plan'; Service = 'SharePoint'; Status = 'Enabled'; Expected = $true }
        @{ Case = 'a suspended SharePoint plan'; Service = 'SharePoint'; Status = 'Suspended'; Expected = $false }
        @{ Case = 'Exchange only'; Service = 'exchange'; Status = 'Enabled'; Expected = $false }
    ) {
        $user = [pscustomobject]@{ AssignedPlans = @([pscustomobject]@{ Service = $Service; CapabilityStatus = $Status }) }
        Test-IamOneDrivePlan -User $user | Should -Be $Expected
    }
}

Describe 'Get-IamLeaverHandover' {
    BeforeAll {
        $script:boss = [pscustomobject]@{ UserPrincipalName = 'boss@lab.example.org'; AccountEnabled = $true }
    }

    BeforeEach {
        Mock Write-IamLog -ModuleName IamAutomation.Common
    }

    It 'lists each device once, company and personal, with the last sign-in' {
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common -ParameterFilter { $Uri -like '*/registeredDevices/*' } -MockWith {
            @{ id = 'd1'; displayName = 'LAPTOP-01'; operatingSystem = 'Windows'; trustType = 'AzureAd'; approximateLastSignInDateTime = '2026-11-20T09:15:00Z' }
            @{ id = 'd2'; displayName = 'iPhone'; operatingSystem = 'iOS'; trustType = 'Workplace'; approximateLastSignInDateTime = $null }
        }
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common -ParameterFilter { $Uri -like '*/ownedDevices/*' } -MockWith { @{ id = 'd1'; displayName = 'LAPTOP-01'; operatingSystem = 'Windows'; trustType = 'AzureAd'; approximateLastSignInDateTime = '2026-11-20T09:15:00Z' } }
        $items = @(Get-IamLeaverHandover -UserId 'u1' -HasOneDrive $false)
        $items.Count | Should -Be 2
        $items[0] | Should -Be 'Device (remove company data, or retire it if company-owned): iPhone - iOS, registered, no sign-in recorded'
        $items[1] | Should -Be 'Device (retire or wipe, collect the hardware): LAPTOP-01 - Windows, Entra joined, last sign-in 20 Nov 2026'
    }

    It 'asks for the OneDrive handover to the manager' {
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common
        $items = @(Get-IamLeaverHandover -UserId 'u1' -Manager $script:boss -HasOneDrive $true)
        $items | Should -Be @('OneDrive (hand over before the account is deleted): give boss@lab.example.org access or copy the files they need')
    }

    It 'says so when there is no manager for the OneDrive' {
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common
        $items = @(Get-IamLeaverHandover -UserId 'u1' -HasOneDrive $true)
        $items[0] | Should -BeLike '*no manager set*'
    }

    It 'returns nothing with no devices and no OneDrive' {
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common
        @(Get-IamLeaverHandover -UserId 'u1' -HasOneDrive $false).Count | Should -Be 0
    }

    It 'turns a failed device lookup into a manual item and still adds the OneDrive item' {
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common -MockWith { throw 'Forbidden' }
        $items = @(Get-IamLeaverHandover -UserId 'u1' -Manager $script:boss -HasOneDrive $true)
        $items.Count | Should -Be 2
        $items[0] | Should -Be "Devices: lookup did not complete, check the user's devices by hand (reason in the log)"
        Should -Invoke Write-IamLog -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter { $Message -like '*Forbidden*' }
        $items[1] | Should -BeLike 'OneDrive*'
    }

    It 'uses no wording the IAM console reads as a failed step' {
        Mock Invoke-IamGraphGetAll -ModuleName IamAutomation.Common -MockWith {
            @{ id = 'd1'; displayName = 'LAPTOP-01'; operatingSystem = 'Windows'; trustType = 'AzureAd'; approximateLastSignInDateTime = '2026-11-20T09:15:00Z' }
            @{ id = 'd2'; displayName = 'iPhone'; operatingSystem = 'iOS'; trustType = 'Workplace'; approximateLastSignInDateTime = $null }
        }
        $items = @(Get-IamLeaverHandover -UserId 'u1' -HasOneDrive $true)
        @($items | Where-Object { $_ -match 'fail|not removed|not cleared|not reset|still enabled' }).Count | Should -Be 0
    }
}

Describe 'Resolve-IamDelegate' {
    It 'reports a missing manager' {
        $d = Resolve-IamDelegate -Manager $null
        $d.Upn | Should -BeNullOrEmpty
        $d.Problem | Should -Be 'No manager set'
    }

    It 'refuses a disabled manager' {
        $d = Resolve-IamDelegate -Manager ([pscustomobject]@{ UserPrincipalName = 'boss@lab.example.org'; AccountEnabled = $false })
        $d.Upn | Should -BeNullOrEmpty
        $d.Problem | Should -Be 'Manager boss@lab.example.org is disabled'
    }

    It 'picks an enabled manager' {
        $d = Resolve-IamDelegate -Manager ([pscustomobject]@{ UserPrincipalName = 'boss@lab.example.org'; AccountEnabled = $true })
        $d.Upn | Should -Be 'boss@lab.example.org'
        $d.Source | Should -Be 'Manager'
    }

    It 'prefers -DelegateTo over the manager' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'd1'; UserPrincipalName = 'cover@lab.example.org'; AccountEnabled = $true }
        }
        $d = Resolve-IamDelegate -DelegateTo 'cover@lab.example.org' -Manager ([pscustomobject]@{ UserPrincipalName = 'boss@lab.example.org'; AccountEnabled = $true })
        $d.Upn | Should -Be 'cover@lab.example.org'
        $d.Source | Should -Be 'DelegateTo'
    }

    It 'throws when -DelegateTo is disabled' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'd1'; UserPrincipalName = 'cover@lab.example.org'; AccountEnabled = $false }
        }
        { Resolve-IamDelegate -DelegateTo 'cover@lab.example.org' } | Should -Throw '*is disabled*'
    }

    It 'throws when -DelegateTo does not exist' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith { throw 'Request_ResourceNotFound' }
        { Resolve-IamDelegate -DelegateTo 'nobody@lab.example.org' } | Should -Throw '*not found in Entra ID*'
    }
}

Describe 'Get-IamLeaverMailboxPlan' {
    BeforeAll {
        $script:boss = [pscustomobject]@{ UserPrincipalName = 'boss@lab.example.org'; AccountEnabled = $true }
        $script:leaver = 'leaver@lab.example.org'
    }

    BeforeEach {
        Mock Connect-IamExchange -ModuleName IamAutomation.Common
    }

    It 'warns that the mailbox will be deleted when the licence goes and nothing converts it' {
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -HasExchangePlan $true -WillRemoveLicence $true
        $plan.Convert | Should -BeFalse
        $plan.Manual[0] | Should -BeLike '*deleted 30 days after the licence goes*'
        Should -Invoke Connect-IamExchange -ModuleName IamAutomation.Common -Times 0 -Exactly
    }

    It 'adds nothing when the licence stays' {
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -HasExchangePlan $true -WillRemoveLicence $false
        $plan.Manual.Count | Should -Be 0
    }

    It 'converts the mailbox and gives the manager Full Access' {
        Mock Get-IamMailboxState -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Exists = $true; Type = 'UserMailbox'; SizeGB = 12.5; NeedsLicence = $false; LicenceReasons = '' }
        }
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -ConvertMailbox -Manager $script:boss -HasExchangePlan $true -WillRemoveLicence $true
        $plan.Convert | Should -BeTrue
        $plan.Delegate | Should -Be 'boss@lab.example.org'
        $plan.Lines | Should -Contain 'convert mailbox to shared (12.5 GB)'
        $plan.Lines | Should -Contain 'Full Access to boss@lab.example.org (manager)'
        $plan.ForceKeepLicence | Should -BeFalse
        $plan.Manual.Count | Should -Be 0
    }

    It 'keeps the licence when the shared mailbox still needs one' {
        Mock Get-IamMailboxState -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Exists = $true; Type = 'UserMailbox'; SizeGB = 3; NeedsLicence = $true; LicenceReasons = 'litigation hold' }
        }
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -ConvertMailbox -Manager $script:boss -HasExchangePlan $true -WillRemoveLicence $true
        $plan.ForceKeepLicence | Should -BeTrue
        $plan.Lines | Should -Contain 'keep licence: the shared mailbox still needs one (litigation hold)'
    }

    It 'leaves access as a manual item when the manager is disabled' {
        Mock Get-IamMailboxState -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Exists = $true; Type = 'UserMailbox'; SizeGB = 1; NeedsLicence = $false; LicenceReasons = '' }
        }
        $disabled = [pscustomobject]@{ UserPrincipalName = 'boss@lab.example.org'; AccountEnabled = $false }
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -ConvertMailbox -Manager $disabled -HasExchangePlan $true -WillRemoveLicence $true
        $plan.Delegate | Should -BeNullOrEmpty
        $plan.Manual | Should -Contain 'Manager boss@lab.example.org is disabled: grant mailbox access by hand, or rerun with -DelegateTo'
    }

    It 'grants no access with -NoDelegate' {
        Mock Get-IamMailboxState -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Exists = $true; Type = 'SharedMailbox'; SizeGB = 1; NeedsLicence = $false; LicenceReasons = '' }
        }
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -ConvertMailbox -NoDelegate -Manager $script:boss -HasExchangePlan $true -WillRemoveLicence $true
        $plan.Delegate | Should -BeNullOrEmpty
        $plan.Lines | Should -Contain 'mailbox already shared'
        $plan.Lines | Should -Contain 'no Full Access (-NoDelegate)'
    }

    It 'converts nothing when there is no mailbox' {
        Mock Get-IamMailboxState -ModuleName IamAutomation.Common -MockWith { [pscustomobject]@{ Exists = $false } }
        $plan = Get-IamLeaverMailboxPlan -UserPrincipalName $script:leaver -ConvertMailbox -Manager $script:boss -HasExchangePlan $true -WillRemoveLicence $true
        $plan.Convert | Should -BeFalse
        $plan.Manual | Should -Contain 'No Exchange Online mailbox found: nothing to convert'
    }
}

Describe 'Write-IamManagerWarning' {
    BeforeEach {
        Mock Write-IamLog -ModuleName IamAutomation.Common
    }

    It 'warns when there is no manager' {
        Write-IamManagerWarning -UserPrincipalName 'mover@lab.example.org' -CurrentManager $null
        Should -Invoke Write-IamLog -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'WARN' -and $Message -like '*has no manager*'
        }
    }

    It 'warns when the manager is disabled' {
        Write-IamManagerWarning -UserPrincipalName 'mover@lab.example.org' -CurrentManager ([pscustomobject]@{ UserPrincipalName = 'old@lab.example.org'; AccountEnabled = $false })
        Should -Invoke Write-IamLog -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'WARN' -and $Message -like '*old@lab.example.org is disabled*'
        }
    }

    It 'warns when the old manager stays' {
        Write-IamManagerWarning -UserPrincipalName 'mover@lab.example.org' -CurrentManager ([pscustomobject]@{ UserPrincipalName = 'old@lab.example.org'; AccountEnabled = $true })
        Should -Invoke Write-IamLog -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'WARN' -and $Message -like '*manager stays old@lab.example.org*'
        }
    }
}

Describe 'Invoke-IamGraphGetAll' {
    It 'follows @odata.nextLink to the last page' {
        Mock Invoke-MgGraphRequest -ModuleName IamAutomation.Common -ParameterFilter { $Uri -eq 'v1.0/groups' } -MockWith {
            @{ value = @(@{ id = '1' }, @{ id = '2' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/groups?$skiptoken=page2' }
        }
        Mock Invoke-MgGraphRequest -ModuleName IamAutomation.Common -ParameterFilter { $Uri -like '*skiptoken=page2' } -MockWith {
            @{ value = @(@{ id = '3' }) }
        }
        $items = @(Invoke-IamGraphGetAll -Uri 'v1.0/groups')
        (($items | ForEach-Object { $_['id'] }) -join ',') | Should -Be '1,2,3'
        Should -Invoke Invoke-MgGraphRequest -ModuleName IamAutomation.Common -Times 2 -Exactly
    }

    It 'returns nothing for an empty collection' {
        Mock Invoke-MgGraphRequest -ModuleName IamAutomation.Common -MockWith { @{ value = @() } }
        @(Invoke-IamGraphGetAll -Uri 'v1.0/groups').Count | Should -Be 0
    }
}

Describe 'Remove-IamUserAuthMethod' {
    BeforeEach {
        Mock Write-IamLog -ModuleName IamAutomation.Common
        Mock Invoke-MgGraphRequest -ModuleName IamAutomation.Common -ParameterFilter { $Method -eq 'GET' } -MockWith {
            @{
                value = @(
                    @{ id = 'pw1'; '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' }
                    @{ id = 'app1'; '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }
                    @{ id = 'ph1'; '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod' }
                    @{ id = 'x1'; '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethod' }
                )
            }
        }
        Mock Invoke-MgGraphRequest -ModuleName IamAutomation.Common -ParameterFilter { $Method -eq 'DELETE' -and $Uri -like '*/microsoftAuthenticatorMethods/app1' }
        # The default method: Graph refuses to delete it.
        Mock Invoke-MgGraphRequest -ModuleName IamAutomation.Common -ParameterFilter { $Method -eq 'DELETE' -and $Uri -like '*/phoneMethods/ph1' } -MockWith {
            throw 'Cannot delete the default method'
        }
    }

    It 'never touches the password, retries a failed delete once, and reports what is left' {
        $r = Remove-IamUserAuthMethod -UserId 'u1' -Confirm:$false
        ($r.Removed -join ',') | Should -Be 'microsoftAuthenticator'
        $r.Failed.Count | Should -Be 2
        ($r.Failed -join '|') | Should -BeLike '*x509Certificate (unsupported type)*'
        ($r.Failed -join '|') | Should -BeLike '*phone (Cannot delete the default method)*'
        Should -Invoke Invoke-MgGraphRequest -ModuleName IamAutomation.Common -Times 2 -Exactly -ParameterFilter {
            $Method -eq 'DELETE' -and $Uri -like '*/phoneMethods/ph1'
        }
        Should -Invoke Invoke-MgGraphRequest -ModuleName IamAutomation.Common -Times 0 -Exactly -ParameterFilter {
            $Uri -like '*passwordMethods*'
        }
    }

    It 'deletes nothing with -WhatIf' {
        Remove-IamUserAuthMethod -UserId 'u1' -WhatIf
        Should -Invoke Invoke-MgGraphRequest -ModuleName IamAutomation.Common -Times 0 -Exactly -ParameterFilter { $Method -eq 'DELETE' }
    }
}

Describe 'Assert-IamSyncState' {
    It 'passes a cloud-only user to a cloud script' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'user@lab.example.org'; OnPremisesSyncEnabled = $null }
        }
        (Assert-IamSyncState -UserPrincipalName 'user@lab.example.org' -Expected Cloud).Id | Should -Be 'u1'
    }

    It 'passes a synced user to a hybrid script' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'user@lab.example.org'; OnPremisesSyncEnabled = $true }
        }
        (Assert-IamSyncState -UserPrincipalName 'user@lab.example.org' -Expected Hybrid).Id | Should -Be 'u1'
    }

    It 'stops a synced user in a cloud script' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'user@lab.example.org'; OnPremisesSyncEnabled = $true }
        }
        { Assert-IamSyncState -UserPrincipalName 'user@lab.example.org' -Expected Cloud } | Should -Throw '*is synced from AD*'
    }

    It 'stops a cloud-only user (sync flag null, not false) in a hybrid script' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'user@lab.example.org'; OnPremisesSyncEnabled = $null }
        }
        { Assert-IamSyncState -UserPrincipalName 'user@lab.example.org' -Expected Hybrid } | Should -Throw '*is cloud-only*'
    }
}

Describe 'Wait-IamCloudUser' {
    BeforeEach {
        Mock Start-Sleep -ModuleName IamAutomation.Common
    }

    It 'returns the user once the condition holds' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith { [pscustomobject]@{ Id = 'u1'; AccountEnabled = $false } }
        $u = Wait-IamCloudUser -UserId 'u1' -Until { param($user) -not $user.AccountEnabled } -TimeoutSeconds 5
        $u.Id | Should -Be 'u1'
    }

    It 'returns Deleted when the object is gone' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith { throw 'Request_ResourceNotFound' }
        Wait-IamCloudUser -UserId 'u1' -TimeoutSeconds 5 | Should -Be 'Deleted'
    }

    It 'returns nothing at timeout' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith { [pscustomobject]@{ Id = 'u1'; AccountEnabled = $true } }
        Wait-IamCloudUser -UserId 'u1' -Until { param($user) -not $user.AccountEnabled } -TimeoutSeconds 0 | Should -BeNullOrEmpty
    }
}

Describe 'Assert-IamGraphHost' {
    It 'stops on Windows PowerShell 5.1' {
        { Assert-IamGraphHost -Edition Desktop } | Should -Throw '*needs PowerShell 7*'
    }

    It 'passes on PowerShell 7' {
        { Assert-IamGraphHost -Edition Core } | Should -Not -Throw
    }
}

Describe 'Assert-IamVerifiedDomain' {
    BeforeEach {
        Mock Get-MgOrganization -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{
                Id              = 'org1'
                VerifiedDomains = @(
                    [pscustomobject]@{ Name = 'lab.example.org' }
                    [pscustomobject]@{ Name = 'labtenant.onmicrosoft.com' }
                )
            }
        }
    }

    It 'passes a verified domain, any case' {
        { Assert-IamVerifiedDomain -Domain 'Lab.Example.ORG' } | Should -Not -Throw
    }

    It 'stops on an AD-only suffix such as the AD DNS root' {
        { Assert-IamVerifiedDomain -Domain 'lab.local' } | Should -Throw "*'lab.local' is not a verified domain*"
    }
}

Describe 'ConvertTo-IamImmutableId' {
    It 'uses objectGUID in AD byte order when mS-DS-ConsistencyGuid is empty' {
        ConvertTo-IamImmutableId -ObjectGuid '00112233-4455-6677-8899-aabbccddeeff' | Should -BeExactly 'MyIRAFVEd2aImaq7zN3u/w=='
    }

    It 'prefers mS-DS-ConsistencyGuid when it is set' {
        $consistency = [byte[]](0..15)
        ConvertTo-IamImmutableId -ObjectGuid '00112233-4455-6677-8899-aabbccddeeff' -ConsistencyGuid $consistency |
            Should -BeExactly 'AAECAwQFBgcICQoLDA0ODw=='
    }
}

Describe 'Get-IamSyncedCloudUser' {
    BeforeEach {
        Mock Write-IamLog -ModuleName IamAutomation.Common
        $script:guid = '00112233-4455-6677-8899-aabbccddeeff'
    }

    It 'finds the account by source anchor, not by UPN' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -ParameterFilter { $Filter -eq "onPremisesImmutableId eq 'MyIRAFVEd2aImaq7zN3u/w=='" } -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'jdoe@lab.example.org'; OnPremisesSyncEnabled = $true }
        }
        (Get-IamSyncedCloudUser -ObjectGuid $script:guid -AdUserPrincipalName 'jdoe@lab.example.org').Id | Should -Be 'u1'
        Should -Invoke Write-IamLog -ModuleName IamAutomation.Common -Times 0 -Exactly
    }

    It 'logs the cloud UPN when it differs from the AD UPN' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'jdoe@labtenant.onmicrosoft.com'; OnPremisesSyncEnabled = $true }
        }
        (Get-IamSyncedCloudUser -ObjectGuid $script:guid -AdUserPrincipalName 'jdoe@lab.local').UserPrincipalName | Should -Be 'jdoe@labtenant.onmicrosoft.com'
        Should -Invoke Write-IamLog -ModuleName IamAutomation.Common -Times 1 -Exactly -ParameterFilter {
            $Message -like '*signs in to Entra ID as jdoe@labtenant.onmicrosoft.com*'
        }
    }

    It 'stops when no account has the source anchor' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith { }
        { Get-IamSyncedCloudUser -ObjectGuid $script:guid -AdUserPrincipalName 'jdoe@lab.example.org' } | Should -Throw '*has no Entra ID account with source anchor*'
    }

    It 'stops when the matched account is no longer synced' {
        Mock Get-MgUser -ModuleName IamAutomation.Common -MockWith {
            [pscustomobject]@{ Id = 'u1'; UserPrincipalName = 'jdoe@lab.example.org'; OnPremisesSyncEnabled = $null }
        }
        { Get-IamSyncedCloudUser -ObjectGuid $script:guid -AdUserPrincipalName 'jdoe@lab.example.org' } | Should -Throw '*sync is off*'
    }
}

Describe 'ConvertTo-IamAdAnchorMap' {
    It 'indexes AD users by the anchor their cloud account holds' {
        $users = @(
            [pscustomobject]@{ ObjectGUID = [guid]'00112233-4455-6677-8899-aabbccddeeff'; 'mS-DS-ConsistencyGuid' = $null; SamAccountName = 'a' }
            [pscustomobject]@{ ObjectGUID = [guid]::NewGuid(); 'mS-DS-ConsistencyGuid' = [byte[]](0..15); SamAccountName = 'b' }
        )
        $map = ConvertTo-IamAdAnchorMap -AdUser $users
        $map.Count | Should -Be 2
        $map['MyIRAFVEd2aImaq7zN3u/w=='].SamAccountName | Should -Be 'a'
        $map['AAECAwQFBgcICQoLDA0ODw=='].SamAccountName | Should -Be 'b'
    }

    It 'compares keys exactly, because Base64 is case-sensitive' {
        $map = ConvertTo-IamAdAnchorMap -AdUser @([pscustomobject]@{ ObjectGUID = [guid]'00112233-4455-6677-8899-aabbccddeeff'; 'mS-DS-ConsistencyGuid' = $null })
        $map.ContainsKey('myiraFVEd2aImaq7zN3u/w==') | Should -BeFalse
    }

    It 'returns an empty map for no users' {
        (ConvertTo-IamAdAnchorMap -AdUser @()).Count | Should -Be 0
    }
}

Describe 'ConvertTo-IamConfigText' {
    It 'writes a file that reads back with the same values' {
        $cfg = [ordered]@{
            TenantId             = $script:tenantId
            StaleDays            = 90
            BreakGlassUpns       = @('bg1@lab.example.org', 'bg2@lab.example.org')
            DepartmentOUs        = [ordered]@{ 'HR' = 'OU=HR,DC=lab,DC=example'; 'Customer Support' = 'OU=CS,DC=lab,DC=example' }
            LeaversOUInSyncScope = $false
            ReviewFallbackUpn    = "o'brien@lab.example.org"
        }
        $path = Join-Path -Path $TestDrive -ChildPath 'roundtrip.psd1'
        Set-Content -LiteralPath $path -Value (ConvertTo-IamConfigText -Config $cfg)
        $back = Import-PowerShellDataFile -Path $path
        $back.TenantId | Should -Be $script:tenantId
        $back.StaleDays | Should -Be 90
        $back.StaleDays | Should -BeOfType [int]
        @($back.BreakGlassUpns).Count | Should -Be 2
        $back.DepartmentOUs['Customer Support'] | Should -Be 'OU=CS,DC=lab,DC=example'
        $back.LeaversOUInSyncScope | Should -BeFalse
        $back.LeaversOUInSyncScope | Should -BeOfType [bool]
        $back.ReviewFallbackUpn | Should -Be "o'brien@lab.example.org"
    }

    It 'keeps the key order and writes comments above a key' {
        $text = ConvertTo-IamConfigText -Config ([ordered]@{ B = 'x'; A = 'y' }) -Comment @{ A = 'Comment for A' }
        $lines = $text -split '\r?\n'
        $lines[1] | Should -Match '^\s+B\s+= ''x''$'
        $lines[2] | Should -Be '    # Comment for A'
        $lines[3] | Should -Match '^\s+A\s+= ''y''$'
    }

    It 'writes empty arrays and tables' {
        $text = ConvertTo-IamConfigText -Config ([ordered]@{ List = @(); Map = @{} })
        $text | Should -Match 'List = @\(\)'
        $text | Should -Match 'Map\s+= @\{\}'
    }

    It 'refuses a value it cannot write' {
        { ConvertTo-IamConfigText -Config @{ Bad = [pscustomobject]@{ a = 1 } } } | Should -Throw '*strings, numbers or booleans*'
    }
}

Describe 'Test-IamOuInSyncScope' {
    BeforeAll {
        $script:inc = @('DC=lab,DC=example')
    }

    It 'is in scope under an included container' {
        Test-IamOuInSyncScope -DistinguishedName 'OU=Leavers,OU=Lab Users,DC=lab,DC=example' -Inclusion $script:inc | Should -BeTrue
    }

    It 'is in scope when it is the included container itself, in any case' {
        Test-IamOuInSyncScope -DistinguishedName 'ou=leavers,dc=lab,dc=example' -Inclusion @('OU=Leavers,DC=lab,DC=example') | Should -BeTrue
    }

    It 'is out of scope under an excluded child of an included container' {
        Test-IamOuInSyncScope -DistinguishedName 'OU=Leavers,OU=Lab Users,DC=lab,DC=example' -Inclusion $script:inc -Exclusion @('OU=Leavers,OU=Lab Users,DC=lab,DC=example') |
            Should -BeFalse
    }

    It 'is in scope again under an included OU inside an excluded one' {
        Test-IamOuInSyncScope -DistinguishedName 'OU=Keep,OU=Old,DC=lab,DC=example' -Inclusion @('DC=lab,DC=example', 'OU=Keep,OU=Old,DC=lab,DC=example') -Exclusion @('OU=Old,DC=lab,DC=example') |
            Should -BeTrue
    }

    It 'does not match on a partial OU name' {
        Test-IamOuInSyncScope -DistinguishedName 'OU=Leavers,DC=lab,DC=example' -Inclusion @('ers,DC=lab,DC=example') | Should -BeFalse
    }

    It 'is out of scope with no inclusion list' {
        Test-IamOuInSyncScope -DistinguishedName 'OU=Leavers,DC=lab,DC=example' | Should -BeFalse
    }
}

Describe 'ConvertFrom-IamMsolDescription' {
    It 'reads the server name' {
        $d = 'Account created by Microsoft Azure Active Directory Connect with installation identifier 0a1b2c3d running on computer SYNC01 configured to synchronize to tenant lab.example.org.'
        ConvertFrom-IamMsolDescription -Description $d | Should -Be 'SYNC01'
    }

    It 'returns nothing for ''<Value>''' -ForEach @(
        @{ Value = 'Service account' }
        @{ Value = '' }
    ) {
        ConvertFrom-IamMsolDescription -Description $Value | Should -BeNullOrEmpty
    }
}

Describe 'Get-IamUpnFormatGuess' {
    It 'finds the format most users follow, counting numbered duplicates' {
        $users = @(
            @{ givenName = 'Jane'; surname = 'Doe'; userPrincipalName = 'jane.doe@lab.example.org' }
            @{ givenName = 'John'; surname = 'Doe'; userPrincipalName = 'john.doe2@lab.example.org' }
            @{ givenName = 'Ana'; surname = 'Silva'; userPrincipalName = 'asilva@lab.example.org' }
        )
        $g = Get-IamUpnFormatGuess -User $users
        $g.Format | Should -Be '{given}.{surname}'
        $g.Hits | Should -Be 2
        $g.Total | Should -Be 3
    }

    It 'ignores guests and users without a name' {
        $users = @(
            @{ givenName = 'Jane'; surname = 'Doe'; userPrincipalName = 'jdoe@lab.example.org' }
            @{ givenName = 'Ext'; surname = 'User'; userPrincipalName = 'ext.user_partner.example#EXT#@lab.example.org' }
            @{ givenName = $null; surname = 'Admin'; userPrincipalName = 'admin@lab.example.org' }
        )
        $g = Get-IamUpnFormatGuess -User $users
        $g.Format | Should -Be '{g}{surname}'
        $g.Total | Should -Be 1
    }

    It 'returns nothing when no format matches' {
        Get-IamUpnFormatGuess -User @(@{ givenName = 'Jane'; surname = 'Doe'; userPrincipalName = 'user42@lab.example.org' }) |
            Should -BeNullOrEmpty
    }

    It 'returns nothing for no users' {
        Get-IamUpnFormatGuess -User @() | Should -BeNullOrEmpty
    }
}

Describe 'Get-IamBreakGlassCandidate' {
    BeforeAll {
        $script:admins = @(
            @{ id = 'u-bg'; userPrincipalName = 'bg@lab.example.org' }
            @{ id = 'u-admin'; userPrincipalName = 'admin@lab.example.org' }
        )
        function Get-TestPolicy {
            param([string]$State = 'enabled', [string[]]$IncludeUsers = @('All'), [string[]]$ExcludeUsers = @(), [string[]]$ExcludeGroups = @())
            @{ state = $State; conditions = @{ users = @{ includeUsers = $IncludeUsers; excludeUsers = $ExcludeUsers; excludeGroups = $ExcludeGroups } } }
        }
    }

    It 'suggests an admin excluded by user from every policy that covers everyone' {
        $policies = @((Get-TestPolicy -ExcludeUsers 'u-bg'), (Get-TestPolicy -ExcludeUsers 'u-bg'))
        Get-IamBreakGlassCandidate -Admin $script:admins -Policy $policies | Should -Be 'bg@lab.example.org'
    }

    It 'suggests an admin excluded through a group' {
        $policies = @(Get-TestPolicy -ExcludeGroups 'g-bg')
        Get-IamBreakGlassCandidate -Admin $script:admins -Policy $policies -GroupIdsByUserId @{ 'u-bg' = @('g-bg') } |
            Should -Be 'bg@lab.example.org'
    }

    It 'skips an admin still covered by one enabled policy' {
        $policies = @((Get-TestPolicy -ExcludeUsers 'u-bg'), (Get-TestPolicy))
        Get-IamBreakGlassCandidate -Admin $script:admins -Policy $policies | Should -BeNullOrEmpty
    }

    It 'ignores report-only and disabled policies' {
        $policies = @((Get-TestPolicy -ExcludeUsers 'u-bg'), (Get-TestPolicy -State 'disabled'), (Get-TestPolicy -State 'enabledForReportingButNotEnforced'))
        Get-IamBreakGlassCandidate -Admin $script:admins -Policy $policies | Should -Be 'bg@lab.example.org'
    }

    It 'suggests nobody when no policy excludes anyone' {
        Get-IamBreakGlassCandidate -Admin $script:admins -Policy @(Get-TestPolicy -IncludeUsers 'u-other') | Should -BeNullOrEmpty
    }

    It 'suggests nobody without enabled policies' {
        Get-IamBreakGlassCandidate -Admin $script:admins -Policy @() | Should -BeNullOrEmpty
    }
}

Describe 'Get-IamLicenceFinding' {
    BeforeAll {
        $script:now = [datetime]'2026-11-27T12:00:00Z'
        $script:cutoff = $script:now.AddDays(-90)
        $script:skuNames = @{ 'sku-e3' = 'SPE_E3'; 'sku-p2' = 'AAD_PREMIUM_P2' }
        function Get-TestUser {
            param([bool]$Enabled = $true, [string[]]$Sku = @('sku-e3'), [bool[]]$ByGroup = @($false), $LastSignIn, $Created = '2025-01-01T00:00:00Z', [string]$Upn = 'jdoe@contoso.com')
            $i = 0
            [pscustomobject]@{
                DisplayName             = 'J Doe'
                UserPrincipalName       = $Upn
                AccountEnabled          = $Enabled
                CreatedDateTime         = $Created
                OnPremisesSyncEnabled   = $null
                AssignedLicenses        = @($Sku | ForEach-Object { [pscustomobject]@{ SkuId = $_ } })
                LicenseAssignmentStates = @($Sku | ForEach-Object { [pscustomobject]@{ SkuId = $_; AssignedByGroup = $(if ($ByGroup[$i++]) { 'group-1' } else { $null }) } })
                SignInActivity          = [pscustomobject]@{ LastSignInDateTime = $LastSignIn; LastNonInteractiveSignInDateTime = $null; LastSuccessfulSignInDateTime = $null }
            }
        }
    }

    It 'flags a disabled account with a direct licence' {
        $r = Get-IamLicenceFinding -User (Get-TestUser -Enabled $false -LastSignIn '2026-11-20T00:00:00Z') -SkuName $script:skuNames -Cutoff $script:cutoff -Now $script:now
        $r.Finding | Should -Be 'Disabled'
        $r.AssignedBy | Should -Be 'Direct'
        $r.Licences | Should -Be 'SPE_E3'
        $r.Action | Should -BeLike 'Remove the licence, unless a shared mailbox*'
    }

    It 'points a disabled account with a group licence at the group' {
        $r = Get-IamLicenceFinding -User (Get-TestUser -Enabled $false -ByGroup $true) -SkuName $script:skuNames -Cutoff $script:cutoff -Now $script:now
        $r.AssignedBy | Should -Be 'Group'
        $r.Action | Should -Be 'Remove from the licensing group'
    }

    It 'reports mixed assignment and sorts the licence names' {
        $u = Get-TestUser -Sku 'sku-p2', 'sku-e3' -ByGroup $true, $false -LastSignIn '2026-11-26T00:00:00Z'
        $r = Get-IamLicenceFinding -User $u -SkuName $script:skuNames -Cutoff $script:cutoff -Now $script:now
        $r.AssignedBy | Should -Be 'Direct and group'
        $r.Licences | Should -Be 'AAD_PREMIUM_P2; SPE_E3'
        $r.Finding | Should -Be ''
    }

    It 'flags an enabled account with no sign-in since the threshold' {
        $r = Get-IamLicenceFinding -User (Get-TestUser -LastSignIn '2026-07-01T00:00:00Z') -SkuName $script:skuNames -Cutoff $script:cutoff -Now $script:now
        $r.Finding | Should -Be 'Inactive'
        $r.DaysInactive | Should -Be 149
    }

    It 'flags an old account that never signed in, but not a new one' {
        (Get-IamLicenceFinding -User (Get-TestUser) -Cutoff $script:cutoff -Now $script:now).Finding | Should -Be 'Never signed in'
        (Get-IamLicenceFinding -User (Get-TestUser -Created '2026-11-20T00:00:00Z') -Cutoff $script:cutoff -Now $script:now).Finding | Should -Be ''
    }

    It 'flags only disabled accounts without sign-in data' {
        (Get-IamLicenceFinding -User (Get-TestUser) -Cutoff $script:cutoff -Now $script:now -NoSignInData).Finding | Should -Be ''
        (Get-IamLicenceFinding -User (Get-TestUser -Enabled $false) -Cutoff $script:cutoff -Now $script:now -NoSignInData).Finding | Should -Be 'Disabled'
    }

    It 'marks break-glass accounts as expected' {
        $r = Get-IamLicenceFinding -User (Get-TestUser -Upn 'bg@contoso.com' -Enabled $false) -Cutoff $script:cutoff -Now $script:now -BreakGlass 'bg@contoso.com'
        $r.Finding | Should -Be 'Expected (break-glass)'
    }

    It 'shows the SKU ID when the name is unknown' {
        $r = Get-IamLicenceFinding -User (Get-TestUser -Sku 'sku-unknown' -LastSignIn '2026-11-26T00:00:00Z') -SkuName $script:skuNames -Cutoff $script:cutoff -Now $script:now
        $r.Licences | Should -Be 'sku-unknown'
    }
}

Describe 'Get-IamCredentialFinding' {
    BeforeAll {
        $script:now = [datetime]'2026-11-28T12:00:00Z'
        function Get-TestCredential {
            param([string]$KeyId, [string]$End, [string]$Usage, $Thumb, [string]$Name = 'cred')
            [pscustomobject]@{ KeyId = $KeyId; DisplayName = $Name; EndDateTime = $End; Usage = $Usage; CustomKeyIdentifier = $Thumb }
        }
    }

    It 'flags an expired secret with nothing to replace it' {
        $app = [pscustomobject]@{ Id = 'o1'; AppId = 'a1'; DisplayName = 'Payroll sync'; KeyCredentials = @(); PasswordCredentials = @(Get-TestCredential -KeyId 'k1' -End '2026-11-10T00:00:00Z') }
        $r = @(Get-IamCredentialFinding -Object $app -Kind 'App registration' -Now $script:now)
        $r.Count | Should -Be 1
        $r[0].Type | Should -Be 'Secret'
        $r[0].Status | Should -Be 'Expired'
        $r[0].DaysLeft | Should -Be -19
        $r[0].Action | Should -BeLike 'Renew now*'
    }

    It 'marks an expiring certificate as replaced when a newer one is valid beyond the window' {
        $app = [pscustomobject]@{ Id = 'o1'; AppId = 'a1'; DisplayName = 'HR feed'; PasswordCredentials = @(); KeyCredentials = @(
                (Get-TestCredential -KeyId 'old' -End '2026-12-20T00:00:00Z' -Usage 'Verify' -Thumb 'T1')
                (Get-TestCredential -KeyId 'new' -End '2027-12-20T00:00:00Z' -Usage 'Verify' -Thumb 'T2')
            ) }
        $r = @(Get-IamCredentialFinding -Object $app -Kind 'App registration' -Now $script:now -Days 60)
        ($r | Where-Object KeyId -EQ 'old').Status | Should -Be 'Expiring, replaced'
        ($r | Where-Object KeyId -EQ 'old').Action | Should -BeLike 'Delete the old credential*'
        ($r | Where-Object KeyId -EQ 'new').Status | Should -Be 'OK'
        ($r | Where-Object KeyId -EQ 'new').Action | Should -Be ''
    }

    It 'gives the renew-by date for an expiring secret' {
        $app = [pscustomobject]@{ Id = 'o1'; AppId = 'a1'; DisplayName = 'Backup'; KeyCredentials = @(); PasswordCredentials = @(Get-TestCredential -KeyId 'k1' -End '2027-01-15T12:00:00Z') }
        $r = Get-IamCredentialFinding -Object $app -Kind 'App registration' -Now $script:now -Days 60
        $r.Status | Should -Be 'Expiring'
        $r.Action | Should -BeLike 'Renew before 15 Jan 2027*'
    }

    It 'counts a SAML signing certificate (Sign, Verify and its password) as one certificate' {
        $thumb = [byte[]](1, 2, 3, 4)
        $sp = [pscustomobject]@{ Id = 'o2'; AppId = 'a2'; DisplayName = 'SAML Toolkit'
            KeyCredentials      = @(
                (Get-TestCredential -KeyId 'ks' -End '2029-11-14T00:00:00Z' -Usage 'Sign' -Thumb $thumb)
                (Get-TestCredential -KeyId 'kv' -End '2029-11-14T00:00:00Z' -Usage 'Verify' -Thumb $thumb)
            )
            PasswordCredentials = @(Get-TestCredential -KeyId 'kp' -End '2029-11-14T00:00:00Z' -Thumb $thumb)
        }
        $r = @(Get-IamCredentialFinding -Object $sp -Kind 'Enterprise app' -Now $script:now)
        $r.Count | Should -Be 1
        $r[0].Type | Should -Be 'Certificate'
        $r[0].Usage | Should -Be 'Sign, Verify'
        $r[0].Status | Should -Be 'OK'
    }

    It 'returns nothing for an object without credentials' {
        $app = [pscustomobject]@{ Id = 'o3'; AppId = 'a3'; DisplayName = 'Empty'; KeyCredentials = $null; PasswordCredentials = $null }
        @(Get-IamCredentialFinding -Object $app -Kind 'App registration' -Now $script:now).Count | Should -Be 0
    }
}
