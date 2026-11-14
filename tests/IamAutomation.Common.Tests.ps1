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
        function Invoke-MgGraphRequest {
            [CmdletBinding()]
            param([string]$Method, [string]$Uri, [object]$Body, [string]$ContentType)
            throw "Invoke-MgGraphRequest reached without a mock: $Method $Uri $Body $ContentType"
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
