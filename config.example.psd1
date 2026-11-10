@{
    # Copy this file to config.local.psd1 (gitignored) and replace every example value.
    # Scripts refuse to run while a value they need is empty or still contains "contoso".

    # Your tenant: Entra admin center > Overview > Tenant ID.
    TenantId             = '00000000-0000-0000-0000-000000000000'

    # Domain new users are created in (joiner). Any verified domain in the tenant.
    DefaultDomain        = 'contoso.onmicrosoft.com'

    # UPN prefix pattern for new users. Tokens: {given}, {surname}, {g} (first initial), {s}.
    # Examples: '{given}.{surname}' -> jane.doe   '{g}{surname}' -> jdoe
    UpnFormat            = '{given}.{surname}'

    # Two-letter country code. Required before a licence can be assigned.
    UsageLocation        = 'GB'

    # Licence the joiner assigns. List yours with: Get-MgSubscribedSku | Select-Object SkuPartNumber
    # Using group-based licensing instead? Run the joiner with -SkipLicense.
    LicenseSkuPartNumber = 'ENTERPRISEPACK'

    # Days without sign-in before Get-StaleAccounts flags an account.
    StaleDays            = 90

    # Emergency access accounts. The leaver refuses to touch them. Get-MfaRegistration flags them
    # without phishing-resistant MFA, the other reports mark them as expected.
    BreakGlassUpns       = @('breakglass@contoso.onmicrosoft.com')

    # Access reviews: who reviews a group with no enabled owner, and rows where the owner
    # would be reviewing their own access. Usually the IAM or IT security lead.
    ReviewFallbackUpn    = 'iam.lead@contoso.onmicrosoft.com'

    # Exact department names your dynamic groups key on. Joiner and mover reject anything else.
    AllowedDepartments   = @('HR', 'IT', 'Engineering', 'Customer Support', 'Warehouse', 'Finance')

    # ---- Hybrid scripts only ----

    # Department name -> OU where its users live. The keys are the allowed departments
    # for the hybrid joiner and mover, so match them to your dynamic group rules.
    DepartmentOUs        = @{
        'HR'      = 'OU=HR,OU=Users,DC=contoso,DC=local'
        'Finance' = 'OU=Finance,OU=Users,DC=contoso,DC=local'
    }

    # Where the hybrid leaver moves disabled accounts. Check whether this OU is inside the
    # Entra Connect sync scope: if it is not, the sync deletes the cloud account and
    # soft-deletes its mailbox.
    LeaversOU            = 'OU=Leavers,DC=contoso,DC=local'

    # Active Entra Connect server (not a staging server). Needs WinRM and ADSyncOperators.
    EntraConnectServer   = 'SYNC01.contoso.local'

    # AD groups the hybrid leaver never removes, and the hybrid mover does not list.
    ProtectedAdGroups    = @('Domain Users')

    # Set to $true only after checking Entra Connect > Domain and OU filtering shows LeaversOU
    # as synced. The hybrid leaver's -ConvertMailbox refuses to run unless this is $true.
    LeaversOUInSyncScope = $false
}
