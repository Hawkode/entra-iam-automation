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

    # Emergency access accounts. Reports mark them as expected, the leaver refuses to touch them.
    BreakGlassUpns       = @('breakglass@contoso.onmicrosoft.com')

    # Exact department names your dynamic groups key on. Joiner and mover reject anything else.
    AllowedDepartments   = @('HR', 'IT', 'Engineering', 'Customer Support', 'Warehouse', 'Finance')

    # Hybrid scripts only.
    LeaversOU            = 'OU=Leavers,DC=lab,DC=local'
    EntraConnectServer   = 'SYNC01'
}
