@{
    # Copy to config.local.psd1 (gitignored) and fill in real values.
    TenantId             = '00000000-0000-0000-0000-000000000000'
    DefaultDomain        = 'contoso.onmicrosoft.com'
    UsageLocation        = 'GB'
    LicenseSkuPartNumber = 'ENTERPRISEPACK'   # find yours with: Get-MgSubscribedSku | Select SkuPartNumber
    StaleDays            = 90

    # Hybrid scripts only
    LeaversOU            = 'OU=Leavers,DC=lab,DC=local'
    EntraConnectServer   = 'SYNC01'
}