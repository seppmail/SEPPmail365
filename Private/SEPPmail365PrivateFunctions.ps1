function Get-SM365TransportRuleDefaults {
    #[CmdLetBinding(SupportsShouldProcess)]
    Write-Verbose "Load default transport rules from module folder and transform into hashtables"
    $script:outgoingHeaderCleaningParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-outgoing-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$outgoingHeaderCleaningParam[$_.Name] = $_.Value}
    $script:decryptedHeaderCleaningParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-decrypted-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$decryptedHeaderCleaningParam[$_.Name] = $_.Value}
    $script:encryptedHeaderCleaningParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-encrypted-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$encryptedHeaderCleaningParam[$_.Name] = $_.Value}
    $script:InternalParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\internal.json -Raw)).psobject.properties | ForEach-Object {$InternalParam[$_.Name] = $_.Value}
    $script:OutboundParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\outbound.json -Raw)).psobject.properties | ForEach-Object {$OutboundParam[$_.Name] = $_.Value}
    $script:InboundParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\inbound.json -Raw)).psobject.properties | ForEach-Object {$InboundParam[$_.Name] = $_.Value}
}
function Remove-SM365TransportRules {

    [CmdletBinding(SupportsShouldProcess = $true,
                           ConfirmImpact = 'Medium'
                    )]
    param()
    Get-SM365TransportRuleDefaults
    if ($PSCmdlet.ShouldProcess($($outgoingHeaderCleaningParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($outgoingHeaderCleaningParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($decryptedHeaderCleaningParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($decryptedHeaderCleaningParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($encryptedHeaderCleaningParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($encryptedHeaderCleaningParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($InternalParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($InternalParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($OutboundParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($OutboundParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($InboundParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($InboundParam.Name)
    }

}
function New-SM365TransportRules {
    [CmdletBinding(SupportsShouldProcess = $true,
                           ConfirmImpact = 'Medium'
                )]
    param()

    Write-Verbose "Read Outbound Connector Information"
    $outboundConn = Get-OutboundConnector |Where-Object Name -match '^\[SEPPmail\].*$'
    if (!($outboundconn)) {
        Write-Error "No SEPPmail outbound connector found. Run `"New-SM365Connectors`" to add the proper SEPPmail connectors"
    } 
    else 
        {
        Get-SM365TransportRuleDefaults
        Write-Verbose "Adapt Transport rules with outbound connector information"
        $InternalParam.RouteMessageOutboundConnector = $OutboundConn.Name
        $OutboundParam.RouteMessageOutboundConnector = $OutboundConn.Name
        $InboundParam.RouteMessageOutboundConnector = $OutboundConn.Name

        Write-Verbose "Set rules priority"
        $outgoingHeaderCleaningParam.Priority = $placementPrio
        $decryptedHeaderCleaningParam.Priority = $placementPrio
        $encryptedHeaderCleaningParam.Priority = $placementPrio
        $InternalParam.Priority = $placementPrio
        $OutboundParam.Priority = $placementPrio
        $InboundParam.Priority = $placementPrio

        Write-Verbose "Create Transport Rules"
        if ($PSCmdlet.ShouldProcess($($outgoingHeaderCleaningParam.Name),'Create transportrule')) {
            New-TransportRule @outgoingHeaderCleaningParam
        }
        if ($PSCmdlet.ShouldProcess($($decryptedHeaderCleaningParam.Name),'Create transportrule')) {
            New-TransportRule @decryptedHeaderCleaningParam
        }
        if ($PSCmdlet.ShouldProcess($($encryptedHeaderCleaningParam.Name),'Create transportrule')) {
            New-TransportRule @encryptedHeaderCleaningParam
        }
        if ($PSCmdlet.ShouldProcess($($InternalParam.Name),'Create transportrule')) {
            New-TransportRule @InternalParam
        }
        if ($PSCmdlet.ShouldProcess($($OutboundParam.Name),'Create transportrule')) {
            New-TransportRule @OutboundParam
        }
        if ($PSCmdlet.ShouldProcess($($InboundParam.Name),'Create transportrule')) {
            New-TransportRule @InboundParam
        }
    }
}

# SIG # Begin signature block
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbFezsNtbRuJorX9rB8zeOJ4d
# hR6ggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
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
# MRYEFAEx8LK0sNuOES5tD2bTz1ORi5rMMA0GCSqGSIb3DQEBAQUABIIBAJZsFJDD
# wbSfU/9Ufdsa28g5QOt24/9qjWt62pb5DFYQA1qAdGnYxKjlJCpioCvytSpd9ID6
# dybcQ6h/+iHjxnB/wdWa6D9LpOdTViykmoKQ42O/UyoXQf7FiTBEbLGhaK99GZZ4
# FtsGdsK5VJMmnhe1ktOfRrRmeyAtr1Yua2Ul58gncSa7Do1HnTvBdEhOstYZ9iEN
# 90pSW1jYJ2jZBJCBO483XL0wqx9HpSsoNqSTXRBDsMAkEhf6ZhhD7vfo/+U5fWky
# WOpE1nuOuwMEVmtngG16bvgyBNN3YIxRt+jskfQxtp6f29aCvb6hugdUiVW2S4+j
# 6riNbWs5j/jUsRM=
# SIG # End signature block
