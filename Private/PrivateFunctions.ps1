# Generic function to avoid code duplication
<#
.SYNOPSIS
Sets properties on an input object from a configuration stored in a JSON object.

.DESCRIPTION
The Set-SM365PropertiesFromConfigJson function takes an input object and a JSON configuration object 
and sets properties on the input object based on the JSON data. It can also set version-specific 
and option-specific properties as required.

.PARAMETER InputObject
The object on which the properties will be set. This object will be modified based on the properties 
found in the provided JSON configuration.

.PARAMETER Json
The JSON object containing configuration data. This should include both general properties and 
version-specific or option-specific properties if applicable.

.PARAMETER Version
Specifies the configuration version to use when setting properties. If no version is specified, 
the default behavior will be applied. The parameter defaults to `[SM365.ConfigVersion]::None`.

.PARAMETER Option
An array of configuration options that can be used to set option-specific properties from the JSON 
configuration.

.EXAMPLE
$inputObject = New-Object PSObject -Property @{ Name = "Sample" }
$jsonConfig = Get-Content -Path "C:\config.json" -Raw | ConvertFrom-Json
Set-SM365PropertiesFromConfigJson -InputObject $inputObject -Json $jsonConfig -Version "V1" -Option @("Option1", "Option2")

This example reads a JSON configuration file, parses it, and sets the properties on an input object 
based on the configuration data for version "V1" and the specified options.

.NOTES
The function assumes that the JSON structure includes a "Version" section for version-specific properties 
and an "Option" section for option-specific settings. It skips setting properties if the specified version 
does not exist in the JSON structure.
#>
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

<#
.SYNOPSIS
Retrieves inbound connector settings from a JSON configuration file.

.DESCRIPTION
The Get-SM365InboundConnectorSettings function reads inbound connector settings from a JSON file located 
in the specified path and returns the settings based on the specified connector type (e.g., Default or Partner).

.PARAMETER Type
Specifies the type of connector settings to retrieve. The valid values are 'Default' and 'Partner'. 
The parameter defaults to 'Default' if not specified.

.EXAMPLE
Get-SM365InboundConnectorSettings -Type 'Partner'

This example retrieves the inbound connector settings for the 'Partner' type from the JSON configuration file.

.EXAMPLE
Get-SM365InboundConnectorSettings

This example retrieves the default inbound connector settings, as the Type parameter defaults to 'Default'.

.NOTES
The function assumes that the JSON configuration file `Inbound.json` is located in the `..\ExOConfig\Connectors` 
directory relative to the script's location. The JSON structure should have keys corresponding to the 
valid types ('Default', 'Partner') for correct data retrieval.
#>
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

<#
.SYNOPSIS
Retrieves outbound connector settings from a JSON configuration file.

.DESCRIPTION
The Get-SM365OutboundConnectorSettings function reads outbound connector settings from a JSON file 
located in the specified path and returns the settings based on the specified connector type 
(e.g., Default or Partner).

.PARAMETER Type
Specifies the type of connector settings to retrieve. The valid values are 'Default' and 'Partner'. 
The parameter defaults to 'Default' if not specified.

.EXAMPLE
Get-SM365OutboundConnectorSettings -Type 'Partner'

This example retrieves the outbound connector settings for the 'Partner' type from the JSON configuration file.

.EXAMPLE
Get-SM365OutboundConnectorSettings

This example retrieves the default outbound connector settings, as the Type parameter defaults to 'Default'.

.NOTES
The function assumes that the JSON configuration file `Outbound.json` is located in the `..\ExOConfig\Connectors` 
directory relative to the script's location. The JSON structure should have keys corresponding to the 
valid types ('Default', 'Partner') for correct data retrieval.
#>
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


<#
.SYNOPSIS
Retrieves transport rule settings from a JSON file and returns them as a hashtable.

.DESCRIPTION
The Get-SM365TransportRuleSettings function reads a JSON file specified by the user, 
parses its contents, and returns the transport rule settings found within the `default` 
section of the JSON as a hashtable.

.PARAMETER File
Specifies the path to the JSON file that contains the transport rule settings. This parameter 
is mandatory.

.EXAMPLE
Get-SM365TransportRuleSettings -File "C:\path\to\settings.json"

This example reads the specified JSON file, extracts the `default` section, and returns it as 
a hashtable.

.NOTES
The function assumes that the JSON file is properly formatted and that it includes a `default` 
key at the top level. The function reads the entire file as a raw string and converts it into 
a hashtable for easy access and processing.
#>
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

<#
.SYNOPSIS
Prompts the user to input a specified number of IP addresses and returns them as an array.

.DESCRIPTION
The Get-IPAddressArray function allows the user to enter a specified number of IP addresses.
Each input is validated to ensure it matches the basic format of an IPv4 address. If an invalid 
IP address is entered, the function prompts the user to re-enter a valid IP address for that 
iteration. The function returns an array containing all the valid IP addresses provided.

.PARAMETER Count
The number of IP addresses the user wishes to input. This parameter is mandatory.

.EXAMPLE
Get-IPAddressArray -Count 3

This example prompts the user to enter three IP addresses. If the user enters any invalid 
IP address, they are prompted to enter it again until a valid address is provided. The 
function returns an array of the entered IP addresses.

.NOTES
This function performs a basic validation for IPv4 addresses using a regular expression. 
For more complex or accurate validation, consider using built-in .NET methods or modules 
for IP address parsing.
#>
function Get-IPAddressArray {
    [CmdLetBinding()]
    param (
        [Parameter(
            Mandatory=$true,
            HelpMessage="Geben Sie die Anzahl der Adressen ein, die sie eingeben wollen."
        )]
        [int]$Count
    )
    $ipArray = @()

    for ($i = 1; $i -le $Count; $i++) {
        $ip = Read-Host -Prompt "Geben Sie IP-Adresse Nr. $i ein"
        
        # Validierung der IP-Adresse (optionale einfache Validierung)
        if ($ip -match '^([0-9]{1,3}\.){3}[0-9]{1,3}$') {
            $ipArray += $ip
        } else {
            Write-Host "Ungültige IP-Adresse: $ip. Bitte geben Sie eine gültige IP-Adresse ein."
            $i-- # Wiederhole diese Schleifenrunde für eine erneute Eingabe
        }
    }
    return $ipArray
}

<#
.SYNOPSIS
Adds unique strings to an existing string array only if they do not already exist in the array.

.DESCRIPTION
The Add-UniqueStringsToArray function takes an existing string array and an array of new strings.
It checks each new string to see if it already exists in the existing array. If a string is not 
already present, it adds the string to the array. The function returns the updated array.

.PARAMETER ExistingArray
The existing string array to which new unique strings will be added. If null or empty, the array 
is initialized as an empty array.

.PARAMETER NewStrings
The array of new strings to be added to the existing array if they do not already exist in it.

.EXAMPLE
$existingArray = @('example.com', 'test.com')
$newStrings = @('test.com', 'newdomain.com', 'sample.org')
$updatedArray = Add-UniqueStringsToArray -ExistingArray $existingArray -NewStrings $newStrings
Write-Host "Updated Array: $updatedArray"

This example takes an array containing 'example.com' and 'test.com', and adds 'newdomain.com' 
and 'sample.org' while skipping 'test.com' since it already exists in the existing array. 
The output will be:
Updated Array: example.com test.com newdomain.com sample.org
#>
function Add-UniqueStringsToArray {
    param (
        [string[]]$ExistingArray,
        [string[]]$NewStrings
    )

    # Wenn das vorhandene Array null oder leer ist, initialisieren wir es
    if (-not $ExistingArray) {
        $ExistingArray = @()
    }

    # Durchlaufen der neuen Strings und Hinzufügen, wenn sie nicht bereits existieren
    foreach ($string in $NewStrings) {
        if ($ExistingArray -notcontains $string) {
            $ExistingArray += $string
        }
    }

    # Rückgabe des aktualisierten Arrays
    return $ExistingArray
}

# SIG # Begin signature block
# MIIVzAYJKoZIhvcNAQcCoIIVvTCCFbkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC7YRY71Ew5pqbT
# fis2qW8wLYZFv/4D/H/DEDK0kYNBgKCCEggwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggZzMIIE26ADAgECAhAMcJlHeeRMvJV4PjhvyrrbMA0GCSqG
# SIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYw
# HhcNMjMwMzIwMDAwMDAwWhcNMjYwMzE5MjM1OTU5WjBqMQswCQYDVQQGEwJERTEP
# MA0GA1UECAwGQmF5ZXJuMSQwIgYDVQQKDBtTRVBQbWFpbCAtIERldXRzY2hsYW5k
# IEdtYkgxJDAiBgNVBAMMG1NFUFBtYWlsIC0gRGV1dHNjaGxhbmQgR21iSDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOapobQkNYCMP+Y33JcGo90Soe9Y
# /WWojr4bKHbLNBzKqZ6cku2uCxhMF1Ln6xuI4ATdZvm4O7GqvplG9nF1ad5t2Lus
# 5SLs45AYnODP4aqPbPU/2NGDRpfnceF+XhKeiYBwoIwrPZ04b8bfTpckj/tvenB9
# P8/9hAjWK97xv7+qsIz4lMMaCuWZgi8RlP6XVxsb+jYrHGA1UdHZEpunEFLaO9Ss
# OPqatPAL2LNGs/JVuGdq9p47GKzn+vl+ANd5zZ/TIP1ifX76vorqZ9l9a5mzi/HG
# vq43v2Cj3jrzIQ7uTbxtiLlPQUqkRzPRtiwTV80JdtRE+M+gTf7bT1CTvG2L3scf
# YKFk7S80M7NydxV/qL+l8blGGageCzJ8svju2Mo4BB+ALWr+gBmCGqrM8YKy/wXR
# tbvdEvBOLsATcHX0maw9xRCDRle2jO+ndYkTKZ92AMH6a/WdDfL0HrAWloWWSg62
# TxmJ/QiX54ILQv2Tlh1Al+pjGHN2evxS8i+XoWcUdHPIOoQd37yjnMjCN593wDzj
# XCEuDABYw9BbvfSp29G/uiDGtjttDXzeMRdVCJFgULV9suBVP7yFh9pK/mVpz+aC
# L2PvqiGYR41xRBKqwrfJEdoluRsqDy6KD985EdXkTvdIFKv0B7MfbcBCiGUBcm1r
# fLAbs8Q2lqvqM4bxAgMBAAGjggGpMIIBpTAfBgNVHSMEGDAWgBQPKssghyi47G9I
# ritUpimqF6TNDDAdBgNVHQ4EFgQUL96+KAGrvUgJnXwdVnA/uy+RlEcwDgYDVR0P
# AQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSgYD
# VR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9z
# ZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAwPqA8oDqGOGh0dHA6
# Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYu
# Y3JsMHkGCCsGAQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0cDovL2NydC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcnQwIwYIKwYB
# BQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMB4GA1UdEQQXMBWBE3N1cHBv
# cnRAc2VwcG1haWwuY2gwDQYJKoZIhvcNAQEMBQADggGBAHnWpS4Jw/QiiLQi2EYv
# THCtwKsj7O3G7wAN7wijSJcWF7iCx6AoCuCIgGdWiQuEZcv9pIUrXQ6jOSRHsDNX
# SvIhCK9JakZJSseW/SCb1rvxZ4d0n2jm2SdkWf5j7+W+X4JHeCF9ZOw0ULpe5pFs
# IGTh8bmTtUr3yA11yw4vHfXFwin7WbEoTLVKiL0ZUN0Qk+yBniPPSRRlUZIX8P4e
# iXuw7lh9CMaS3HWRKkK89w//18PjUMxhTZJ6dszN2TAfwu1zxdG/RQqvxXUTTAxU
# JrrCuvowtnDQ55yXMxkkSxWUwLxk76WvXwmohRdsavsGJJ9+yxj5JKOd+HIZ1fZ7
# oi0VhyOqFQAnjNbwR/TqPjRxZKjCNLXSM5YSMZKAhqrJssGLINZ2qDK/CEcVDkBS
# 6Hke4jWMczny8nB8+ATJ84MB7tfSoXE7R0FMs1dinuvjVWIyg6klHigpeEiAaSaG
# 5KF7vk+OlquA+x4ohPuWdtFxobOT2OgHQnK4bJitb9aDazGCAxowggMWAgEBMGgw
# VDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UE
# AxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNgIQDHCZR3nkTLyV
# eD44b8q62zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgACh
# AoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAM
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBdiclaYpDLzlUgXlJFKDTK3BS+
# W3C5N9XKTaIg8X9ghTANBgkqhkiG9w0BAQEFAASCAgChJ0gi+CSrqeHyC7MPJFM4
# lkxaY5gsr+E2LR8bOSMMqQIEtk6V1IzZriGDNFY7KZ1t+R+FB0XCNOnctawo9BfR
# Q/SSTqTc4A/Q8V9ZxEMaXy5xsdDjJaJfJQPVsoEIeVA6E91LBw/RIA+NMgleoa/H
# cMaQGS7GaPJYYVvygZdjITSIE2joyudOcon5CJ8fqtiHgwoAclXBPvWlqKH7IhRK
# r/PDcdoHYedE51h3wVXE2nyaY29XUl1cAOqztl3qzP4mFZk6ChdQUEWPa9Tw/NkY
# f8PO0qO/g4FuapqD2VwUGkMFwFxlNAqaXzBTkWdQh4WhlxMiMZ65q9I+g6mZF4/W
# 7IZqQgO1R0POYuFPpenRn3aDWbCk1RLt2I9QQLWvRC7jTEsS6V9yTFvJonHidJqI
# c7DVEwQuyAi/gpO9kymPLYupHthu+ULXSKQXGV3OB0IrucssS4mJjkg5rFH0h2s0
# 7P51kBPJ5rL9p2RJbvfSSBAuJ+wK7GPz8erGjB3V2OaaAHCoM2aIYqYfQ1E+G5cG
# WO4zl5/v9wYya3xNovX9Mw/46+BLPsJT1TbdJZmxkdGXjItowsBP1aRCLtx7VF/e
# Hugbf5fqyq9RAfW5htiN29uAB/UvArXezJAZfSJD2SuzfjJm3LTGITojIPhxhdXI
# ynKN5Ofb2ADvFb0jqjy09w==
# SIG # End signature block
