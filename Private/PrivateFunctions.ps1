# Generic function to avoid code duplication
function Set-SM365PropertiesFromConfigJson
{
    [CmdLetBinding()]
    Param
    (
        [psobject] $InputObject,
        [psobject] $Json,
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::None,
        [SM365.ConfigOption[]] $Option
    )

    # use the latest if the requested version is not supplied (for overriding specific aspects only)
    #if(!$json.Version.$Version)
    #{
    #    $Version = [SM365.ConfigVersion]::Latest
    #}

    # skip if the requested version isn't available
    if(!$json.Version.$version) {
        $InputObject.Skip = $true;
    }

    # Set all properties that aren't version specific
    $json.psobject.properties | Foreach-Object {
        if ($_.Name -notin @("Version", "Name", "Option"))
        { $InputObject.$($_.Name) = $_.Value }
    }

    # Default version actually acts as default properties now
    if($json.Version["Default"]){
        $json.Version["Default"].psobject.properties | Foreach-Object 
            $InputObject.$($_.Name) = $_.Value
    }

    # Set the version specific properties, except if none has been requested
    if ($Version -ne [SM365.ConfigVersion]::None) {
        $json.Version.$Version.psobject.properties | Foreach-Object {
            $InputObject.$($_.Name) = $_.Value
        }
    }

    if($Option -and $json.Option)
    {
        $Option | Where-Object {$json.Option.$_} | ForEach-Object{
            $Json.Option.$_.psobject.properties | ForEach-Object{
                $InputObject.$($_.Name) = $_.Value
            }
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
        [ValidateSet('Default','Partner')]
        [String]$Type = 'Default'
    )
    begin {
        $ret = $null
        $raw = $null
    }
    process {
        Write-Verbose "Loading inbound connector settings for routingtype $Routing"
        $raw = (Get-Content "$PSScriptRoot\..\ExOConfig\Connectors\Inbound.json" -Raw|Convertfrom-Json -AsHashtable)
        $ret = $raw.$Type    
    }
    end {
        return $ret
    }
}

function Get-SM365OutboundConnectorSettings
{
    [CmdletBinding()]
    Param
    (
        [ValidateSet('Default','Partner')]
        [String]$Type = 'Default'
    )

    begin {
        $ret = $null
        $raw = $null
    }
    process {
        Write-Verbose "Loading outbound connector settings"
        $raw = (Get-Content "$PSScriptRoot\..\ExOConfig\Connectors\Outbound.json" -Raw|Convertfrom-Json -AsHashtable)
        $ret= $Raw.$Type
    }
    end
    {
        return $ret
    }
}

function Get-SM365TransportRuleSettings
{
    [CmdLetBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        $File
    )
    begin {
        $ret = $null
        $raw = $null
    }
    process {
            $raw = (Get-Content $file -Raw|Convertfrom-Json -AsHashtable)
            $ret = $raw.default
            return $ret    
    }
    end {
    }
}
# SIG # Begin signature block
# MIIL/AYJKoZIhvcNAQcCoIIL7TCCC+kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBU9BDQLF/VvtgP
# pOxqHhyxFo5xGn4TymsnN8e0QTVoz6CCCUAwggSZMIIDgaADAgECAhBxoLc2ld2x
# r8I7K5oY7lTLMA0GCSqGSIb3DQEBCwUAMIGpMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMdGhhd3RlLCBJbmMuMSgwJgYDVQQLEx9DZXJ0aWZpY2F0aW9uIFNlcnZpY2Vz
# IERpdmlzaW9uMTgwNgYDVQQLEy8oYykgMjAwNiB0aGF3dGUsIEluYy4gLSBGb3Ig
# YXV0aG9yaXplZCB1c2Ugb25seTEfMB0GA1UEAxMWdGhhd3RlIFByaW1hcnkgUm9v
# dCBDQTAeFw0xMzEyMTAwMDAwMDBaFw0yMzEyMDkyMzU5NTlaMEwxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAkBgNVBAMTHXRoYXd0ZSBTSEEy
# NTYgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAm1UCTBcF6dBmw/wordPA/u/g6X7UHvaqG5FG/fUW7ZgHU/q6hxt9nh8BJ6u5
# 0mfKtxAlU/TjvpuQuO0jXELvZCVY5YgiGr71x671voqxERGTGiKpdGnBdLZoh6eD
# MPlk8bHjOD701sH8Ev5zVxc1V4rdUI0D+GbNynaDE8jXDnEd5GPJuhf40bnkiNIs
# KMghIA1BtwviL8KA5oh7U2zDRGOBf2hHjCsqz1v0jElhummF/WsAeAUmaRMwgDhO
# 8VpVycVQ1qo4iUdDXP5Nc6VJxZNp/neWmq/zjA5XujPZDsZC0wN3xLs5rZH58/eW
# XDpkpu0nV8HoQPNT8r4pNP5f+QIDAQABo4IBFzCCARMwLwYIKwYBBQUHAQEEIzAh
# MB8GCCsGAQUFBzABhhNodHRwOi8vdDIuc3ltY2IuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwMgYDVR0fBCswKTAnoCWgI4YhaHR0cDovL3QxLnN5bWNiLmNvbS9UaGF3
# dGVQQ0EuY3JsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCAQYwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJLTEt
# NTY4MB0GA1UdDgQWBBRXhptUuL6mKYrk9sLiExiJhc3ctzAfBgNVHSMEGDAWgBR7
# W0XPr87Lev0xkhpqtvNG61dIUDANBgkqhkiG9w0BAQsFAAOCAQEAJDv116A2E8dD
# /vAJh2jRmDFuEuQ/Hh+We2tMHoeei8Vso7EMe1CS1YGcsY8sKbfu+ZEFuY5B8Sz2
# 0FktmOC56oABR0CVuD2dA715uzW2rZxMJ/ZnRRDJxbyHTlV70oe73dww78bUbMyZ
# NW0c4GDTzWiPKVlLiZYIRsmO/HVPxdwJzE4ni0TNB7ysBOC1M6WHn/TdcwyR6hKB
# b+N18B61k2xEF9U+l8m9ByxWdx+F3Ubov94sgZSj9+W3p8E3n3XKVXdNXjYpyoXY
# RUFyV3XAeVv6NBAGbWQgQrc6yB8dRmQCX8ZHvvDEOihU2vYeT5qiGUOkb0n4/F5C
# ICiEi0cgbjCCBJ8wggOHoAMCAQICEF0xOuf5lHR9Mf0X/F6tAjYwDQYJKoZIhvcN
# AQELBQAwTDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEmMCQG
# A1UEAxMddGhhd3RlIFNIQTI1NiBDb2RlIFNpZ25pbmcgQ0EwHhcNMjAwMzE2MDAw
# MDAwWhcNMjMwMzE2MjM1OTU5WjBdMQswCQYDVQQGEwJDSDEPMA0GA1UECAwGQWFy
# Z2F1MREwDwYDVQQHDAhOZXVlbmhvZjEUMBIGA1UECgwLU0VQUG1haWwgQUcxFDAS
# BgNVBAMMC1NFUFBtYWlsIEFHMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAoTng2flWvxhwRxO/mTS8XJbbqTMG3097ZRxrB+OfKq9ilZ4K45fHL1deJ/bh
# E24FE4Rzd6pXgQdsD2/5w6sTWZ7gdNy3tvJEzQBALOht4UDJ6Ld7J4Nu9v3relQP
# 5euW4JBL4vzSfzIKZw7AH7B5f5iPYJjuzcdl9sCvNPEEejkAoQOn1fHKgJz+1RA6
# rq/L7B1s458uGs0yQMMKwFZIuqKPHe3UT5+sBgXu1do7n8UQZN5v86Neo6miig0v
# fwWYImHQIpvLT3SwEk/nBKJ6efU12GYE4pEv7QrduiajOhiZCxylPkB9ajikVCb7
# xsbhB01pPwBXgAc9vjN/bdvFZQIDAQABo4IBajCCAWYwCQYDVR0TBAIwADAfBgNV
# HSMEGDAWgBRXhptUuL6mKYrk9sLiExiJhc3ctzAdBgNVHQ4EFgQU8p/VNr/y8AxO
# eDZl4HNdfm6GnyMwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3RsLnN5bWNiLmNv
# bS90bC5jcmwwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMG4G
# A1UdIARnMGUwYwYGZ4EMAQQBMFkwJgYIKwYBBQUHAgEWGmh0dHBzOi8vd3d3LnRo
# YXd0ZS5jb20vY3BzMC8GCCsGAQUFBwICMCMMIWh0dHBzOi8vd3d3LnRoYXd0ZS5j
# b20vcmVwb3NpdG9yeTBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0dHA6
# Ly90bC5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly90bC5zeW1jYi5jb20v
# dGwuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQB2zM1TxEwHrD3KWrJcbcSNae+KLtqK
# A3T/wE3Bkh6os/1pWseEMQirPRG74okbvb1KCu0uBzs56eq5toMuIuntggICxkFR
# p7dr4xLuJ+BUu4MoFJ2wwQf6hG43WIYx+cCHKSDQ/mW11GU18O9CUgWKoYJxFpoZ
# ULd+qj+ls+21tbfuizIjFOCYHiERazWOjy4MQfHDmrIHD/cIaQGF/kY1z2ZQ4d4Q
# EyfM56yaWruH1HZDkVo8fvgb0VfEAbbP+sIDsLBzDDVCBvWT7d34Ua9SZUbEkTjl
# 3atWPX5qU1z5lwH1hr37yOEyywwuOEnUF/NRZ5Z1mpEY2x8WP5pmyTDGMYICEjCC
# Ag4CAQEwYDBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3RlLCBJbmMuMSYw
# JAYDVQQDEx10aGF3dGUgU0hBMjU2IENvZGUgU2lnbmluZyBDQQIQXTE65/mUdH0x
# /Rf8Xq0CNjANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgACh
# AoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAM
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA8KBINdQ8/bJC/kMKDF2MSxktl
# nnknVPi1pmgh+CPyQTANBgkqhkiG9w0BAQEFAASCAQAbYlEOTYCu6GHDxEApsk1s
# 4IDuu1rYS2C76Z4m+AYgistCUvZ2r6VL5Qu7JnmINS6ujai+YREbXvSZcMH7UldY
# 8wL23vMib/CxcmS/S3D1teshceHe3GEoAZVaAzLzR5uFpt+bNUkdibkv62wkshos
# 1UG48eVYK/Rtk7f0UHcnCrLQ6yk68c57C9Jlr6YjSqRS7QVTa7cTQy5MDXufcy1T
# kTAEwfpHWMUPgw+cMBe3Ru3G7fne+Mh+FpylVgQmeXexzY5OBdfLCO3oveMGOSZf
# 9ddp7WDkyhNvDbfSNwPmqvTqvYcDBf5+zAoe1Wn5ZtHxwN1UCeG0KT7O+5ZRvVMx
# SIG # End signature block
