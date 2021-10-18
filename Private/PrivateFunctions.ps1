. $PSScriptRoot\SetupTypes.ps1

function Test-SM365ConnectionStatus
{
    [CmdLetBinding()]
    Param
    (

    )

    [bool] $isConnected = $false

    if(!(Get-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue))
    {
        Write-Warning "ExchangeOnlineManagement module not yet imported"
        Write-Warning "Importing ExchangeOnlineManagement module"
        $m = Import-Module ExchangeOnlineManagement -PassThru -ErrorAction SilentlyContinue

        if(!$m)
        {throw [System.Exception] "ExchangeOnlineManagement module does not seem to be installed"}
    }
    else
    {
        $isConnected = (Get-PSSession | ? { $_.Name -like "ExchangeOnlineInternalSession*" -and $_.State -eq "Opened" }).Count -gt 0
    }

    if(!$isConnected)
    {
        Write-Warning "You're not connected to your Exchange Online organization"

        if($InteractiveSession) # defined in public/Functions.ps1
        {
            try
            {
                # throws an exception if authentication fails
                Connect-ExchangeOnline
                $isConnected = $true
            }
            catch
            {}
        }
    }

    # Record the default domain, of the Exchange Online organization we're connected to
    if($isConnected -and !$Script:ExODefaultDomain)
    {
        [string] $Script:ExODefaultDomain = Get-AcceptedDomain | ?{$_.Default} | select -ExpandProperty DomainName -First 1
    }

    return $isConnected
}

# Generic function to avoid code duplication
function Set-SM365PropertiesFromConfigJson
{
    [CmdLetBinding()]
    Param
    (
        [psobject] $InputObject,
        [psobject] $Json,
        [SM365.ConfigVersion] $Version
    )

    # use the defaults if the requested version is not supplied (for overriding specific aspects only)
    if(!$json.Version.$Version)
    {
        $Version = [SM365.ConfigVersion]::Latest
    }

    # skip if skipping requested or the default version isn't available either
    if($json.Version.$Version.Skip -or !$json.Version.$version)
    {
        $InputObject.Skip = $true;
        return
    }

    # Set all properties that aren't version specific
    $json.psobject.properties | % {
        if ($_.Name -notin @("Version", "Name"))
        { $InputObject.$($_.Name) = $_.Value }
    }

    # Set the version specific properties, except if none has been requested
    if ($Version -ne [SM365.ConfigVersion]::None)
    {
        $json.Version.$Version.psobject.properties | % {
            $InputObject.$($_.Name) = $_.Value
        }
    }
}

# Essentially a factory function for either an empty
# settings object, filled with necessary attributes to identify
# the O365 object (i.e. the Name), or version specific settings.
function Get-SM365InboundConnectorSettings
{
    [CmdletBinding()]
    Param
    (
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Latest
    )

    if($Version -ne "None")
    {Write-Verbose "Loading inbound connector settings for version $Version"}
    else
    {Write-Verbose "Loading mandatory inbound connector settings"}

    $json = ConvertFrom-Json (Get-Content -Path "$PSScriptRoot\..\ExOConfig\Connectors\Inbound.json" -Raw)

    $ret = [SM365.InboundConnectorSettings]::new($json.Name, $Version)

    Set-SM365PropertiesFromConfigJson $ret -Json $json -Version $Version

    return $ret
}

function Get-SM365OutboundConnectorSettings
{
    [CmdletBinding()]
    Param
    (
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Latest
    )

    if($Version -ne "None")
    {Write-Verbose "Loading outbound connector settings for version $Version"}
    else
    {Write-Verbose "Loading mandatory outbound connector settings"}

    $json = ConvertFrom-Json (Get-Content -Path "$PSScriptRoot\..\ExOConfig\Connectors\Outbound.json" -Raw)

    $ret = [SM365.OutboundConnectorSettings]::new($json.Name, $Version)

    Set-SM365PropertiesFromConfigJson $ret -Json $json -Version $Version

    return $ret
}

function Get-SM365TransportRuleSettings
{
    [CmdLetBinding()]
    Param
    (
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Latest,
        [SM365.AvailableTransportRuleSettings[]] $Settings =[SM365.AvailableTransportRuleSettings]::All
    )

    if($Version -ne "None")
    {Write-Verbose "Loading transport rule settings for version $Version"}
    else
    {Write-Verbose "Loading mandatory transport rule settings"}

    $settingsToFetch = 0
    foreach($set in $Settings)
    {$settingsToFetch = $settingsToFetch -bor $set}


    $configs = array string
    $ret = array SM365.TransportRuleSettings -Capacity $configs.Count
    $addSetting = {
        Param
        (
            [string] $FileName,
            [SM365.AvailableTransportRuleSettings] $Type
        )
        $json = ConvertFrom-Json (Get-Content "$PSScriptRoot\..\ExOConfig\Rules\$FileName" -Raw)

        $settings = [SM365.TransportRuleSettings]::new($json.Name, $Version, $Type)

        Set-SM365PropertiesFromConfigJson $settings -Json $json -Version $Version

        if(!$settings.skip)
        {$ret.Add($settings)}
    }

    if([SM365.AvailableTransportRuleSettings]::OutgoingHeaderCleaning -band $settingsToFetch)
    {& $addSetting "X-SM-outgoing-header-cleaning.json" "OutgoingHeaderCleaning"}

    if([SM365.AvailableTransportRuleSettings]::DecryptedHeaderCleaning -band $settingsToFetch)
    {& $addSetting "X-SM-decrypted-header-cleaning.json" "DecryptedHeaderCleaning"}

    if([SM365.AvailableTransportRuleSettings]::EncryptedHeaderCleaning -band $settingsToFetch)
    {& $addSetting "X-SM-encrypted-header-cleaning.json" "EncryptedHeaderCleaning"}

    if([SM365.AvailableTransportRuleSettings]::SkipSpfIncoming -band $settingsToFetch)
    {& $addSetting "Skip-SPF-incoming.json" "SkipSpfIncoming"}

    if([SM365.AvailableTransportRuleSettings]::SkipSpfInternal -band $settingsToFetch)
    {& $addSetting "Skip-SPF-internal.json" "SkipSpfInternal"}

    if([SM365.AvailableTransportRuleSettings]::Inbound -band $settingsToFetch)
    {& $addSetting "Inbound.json" "Inbound"}

    if([SM365.AvailableTransportRuleSettings]::Outbound -band $settingsToFetch)
    {& $addSetting "Outbound.json" "Outbound"}

    # Deactivated, because it seems unnecessary
    # if([SM365.AvailableTransportRuleSettings]::Internal -band $settingsToFetch)
    # {& $addSetting "Internal.json" "Internal"}

    # Return the array in reverse SMPriority order, so that they can be created with the
    # same priority, i.e.:
    # New-TransportRule @param -Priority 3
    # But via this sorting, an SMPriority 0 rule will actually be at the top (but at priority 3).
    $ret | Sort-Object -Property SMPriority -Descending
}
# SIG # Begin signature block
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUx0bjykmO9WE5AFuSAgGKjg88
# PSiggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
# AQsFADCBqTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEoMCYG
# A1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjE4MDYGA1UECxMv
# KGMpIDIwMDYgdGhhd3RlLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkx
# HzAdBgNVBAMTFnRoYXd0ZSBQcmltYXJ5IFJvb3QgQ0EwHhcNMTMxMjEwMDAwMDAw
# WhcNMjMxMjA5MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3Rl
# LCBJbmMuMSYwJAYDVQQDEx10aGF3dGUgU0hBMjU2IENvZGUgU2lnbmluZyBDQTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJtVAkwXBenQZsP8KK3TwP7v
# 4Ol+1B72qhuRRv31Fu2YB1P6uocbfZ4fASerudJnyrcQJVP0476bkLjtI1xC72Ql
# WOWIIhq+9ceu9b6KsRERkxoiqXRpwXS2aIengzD5ZPGx4zg+9NbB/BL+c1cXNVeK
# 3VCNA/hmzcp2gxPI1w5xHeRjyboX+NG55IjSLCjIISANQbcL4i/CgOaIe1Nsw0Rj
# gX9oR4wrKs9b9IxJYbpphf1rAHgFJmkTMIA4TvFaVcnFUNaqOIlHQ1z+TXOlScWT
# af53lpqv84wOV7oz2Q7GQtMDd8S7Oa2R+fP3llw6ZKbtJ1fB6EDzU/K+KTT+X/kC
# AwEAAaOCARcwggETMC8GCCsGAQUFBwEBBCMwITAfBggrBgEFBQcwAYYTaHR0cDov
# L3QyLnN5bWNiLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6Al
# oCOGIWh0dHA6Ly90MS5zeW1jYi5jb20vVGhhd3RlUENBLmNybDAdBgNVHSUEFjAU
# BggrBgEFBQcDAgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgEGMCkGA1UdEQQiMCCk
# HjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTU2ODAdBgNVHQ4EFgQUV4abVLi+
# pimK5PbC4hMYiYXN3LcwHwYDVR0jBBgwFoAUe1tFz6/Oy3r9MZIaarbzRutXSFAw
# DQYJKoZIhvcNAQELBQADggEBACQ79degNhPHQ/7wCYdo0ZgxbhLkPx4flntrTB6H
# novFbKOxDHtQktWBnLGPLCm37vmRBbmOQfEs9tBZLZjgueqAAUdAlbg9nQO9ebs1
# tq2cTCf2Z0UQycW8h05Ve9KHu93cMO/G1GzMmTVtHOBg081ojylZS4mWCEbJjvx1
# T8XcCcxOJ4tEzQe8rATgtTOlh5/03XMMkeoSgW/jdfAetZNsRBfVPpfJvQcsVncf
# hd1G6L/eLIGUo/flt6fBN591ylV3TV42KcqF2EVBcld1wHlb+jQQBm1kIEK3Osgf
# HUZkAl/GR77wxDooVNr2Hk+aohlDpG9J+PxeQiAohItHIG4wggSfMIIDh6ADAgEC
# AhBdMTrn+ZR0fTH9F/xerQI2MA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAkBgNVBAMTHXRoYXd0ZSBTSEEyNTYg
# Q29kZSBTaWduaW5nIENBMB4XDTIwMDMxNjAwMDAwMFoXDTIzMDMxNjIzNTk1OVow
# XTELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBkFhcmdhdTERMA8GA1UEBwwITmV1ZW5o
# b2YxFDASBgNVBAoMC1NFUFBtYWlsIEFHMRQwEgYDVQQDDAtTRVBQbWFpbCBBRzCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKE54Nn5Vr8YcEcTv5k0vFyW
# 26kzBt9Pe2UcawfjnyqvYpWeCuOXxy9XXif24RNuBROEc3eqV4EHbA9v+cOrE1me
# 4HTct7byRM0AQCzobeFAyei3eyeDbvb963pUD+XrluCQS+L80n8yCmcOwB+weX+Y
# j2CY7s3HZfbArzTxBHo5AKEDp9XxyoCc/tUQOq6vy+wdbOOfLhrNMkDDCsBWSLqi
# jx3t1E+frAYF7tXaO5/FEGTeb/OjXqOpoooNL38FmCJh0CKby090sBJP5wSienn1
# NdhmBOKRL+0K3bomozoYmQscpT5AfWo4pFQm+8bG4QdNaT8AV4AHPb4zf23bxWUC
# AwEAAaOCAWowggFmMAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUV4abVLi+pimK5PbC
# 4hMYiYXN3LcwHQYDVR0OBBYEFPKf1Ta/8vAMTng2ZeBzXX5uhp8jMCsGA1UdHwQk
# MCIwIKAeoByGGmh0dHA6Ly90bC5zeW1jYi5jb20vdGwuY3JsMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzBuBgNVHSAEZzBlMGMGBmeBDAEEATBZ
# MCYGCCsGAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEF
# BQcCAjAjDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwVwYIKwYB
# BQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vdGwuc3ltY2QuY29tMCYGCCsG
# AQUFBzAChhpodHRwOi8vdGwuc3ltY2IuY29tL3RsLmNydDANBgkqhkiG9w0BAQsF
# AAOCAQEAdszNU8RMB6w9ylqyXG3EjWnvii7aigN0/8BNwZIeqLP9aVrHhDEIqz0R
# u+KJG729SgrtLgc7OenqubaDLiLp7YICAsZBUae3a+MS7ifgVLuDKBSdsMEH+oRu
# N1iGMfnAhykg0P5ltdRlNfDvQlIFiqGCcRaaGVC3fqo/pbPttbW37osyIxTgmB4h
# EWs1jo8uDEHxw5qyBw/3CGkBhf5GNc9mUOHeEBMnzOesmlq7h9R2Q5FaPH74G9FX
# xAG2z/rCA7Cwcww1Qgb1k+3d+FGvUmVGxJE45d2rVj1+alNc+ZcB9Ya9+8jhMssM
# LjhJ1BfzUWeWdZqRGNsfFj+aZskwxjGCAgEwggH9AgEBMGAwTDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEmMCQGA1UEAxMddGhhd3RlIFNIQTI1
# NiBDb2RlIFNpZ25pbmcgQ0ECEF0xOuf5lHR9Mf0X/F6tAjYwCQYFKw4DAhoFAKB4
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkE
# MRYEFC/hNRvlVNztJ0hsfLMBFTCzfRcvMA0GCSqGSIb3DQEBAQUABIIBAGx5TD+1
# h/goM0a1KdpGEAiIoUHqkdF+EpfWvcv+1kSRYvCVIvotohOrT/ssQWswS88ramVQ
# S2AnECRf7xNLSzs0Z4YTrTVXUdaJtyHKp1VbJhve1ktuCcQQkZ/5qJjCdVyORPgF
# 3U3mbcO+satURCNyrxnsHFcBIEyhTnw2UzrWI3S8tMscXG5IY48HyjE0Po34wf6a
# byLwXOt6e8lo9l3bmNaz+tsTx3NBUf7ZgxduOaPsmbd0+QmjLaftjAdndCYDqZjP
# ZTN5ZZBv2fsyme2XDqFwUW1vqQ0sTav+EmTPssoO14QCi2ydTaN1U9OerxQCLkfC
# zw+5hjTcYFwhUEM=
# SIG # End signature block
