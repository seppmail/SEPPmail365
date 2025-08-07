<#
.SYNOPSIS
    Reads existing SEPPmail transport rules from Exchange Online
.DESCRIPTION
    Get-SM365Rules
    Reads TransportRules from Exchange Online which are similar to the ones we deploy.
.LINK
    https://github.com/seppmail/SEPPmail365/blob/master/Readme.md
#>
function Get-SM365Rules {
    [CmdletBinding()]
    param
    ()

    if (!(Test-SM365ConnectionStatus))
    { 
        throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" 
    }
    else 
    {
        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        $TransPortRuleFiles = Get-Childitem -Path "$PSScriptroot\..\ExoConfig\Rules\*.json"
        Foreach ($File in $TransPortRuleFiles) {
            $setting = Get-SM365TransportRuleSettings -File $File
            #{
                $rule = Get-TransportRule $setting.Name -ErrorAction SilentlyContinue
            
                if($rule)
                {

					if ($rule.Identity -like '*100*') {
						$rule|Select-Object Identity,Priority,State,@{Name = 'ExcludedDomains'; Expression={$_.ExceptIfRecipientDomainIs}}
					}
					elseif ($rule.Identity -like '*200*') {
						$rule|Select-Object Identity,Priority,State,@{Name = 'ExcludedDomains'; Expression={$_.ExceptIfSenderDomainIs}}
					}
					else {
						$rule|Select-Object Identity,Priority,State,ExcludedDomains
					}

                }
                else
                {
                    Write-Warning "Rule $($setting.Name) does not exist"
                }
            #}
        }
    }
}

<#
.SYNOPSIS
    Creates necessary rules for SEPPmail Appliance integration
.DESCRIPTION
    SEPPmail Appiance integration needs a couple of transport rules to route the e-mails for encryption/decryption.
.LINK
    https://github.com/seppmail/SEPPmail365/blob/master/Readme.md
.EXAMPLE
    New-SM365Rules -SEPPmailDomain 'contoso.eu' -disabled:$false
    Creates mailflow rules to direct all mails for the contoso.eu domain in and out via SEPPmail for cryptographic processing and ENABLES them.
.EXAMPLE
    New-SM365Rules -SEPPmailDomain 'contoso.eu'
    Creates mailflow rules to direct all mails for the contoso.eu domain in and out via SEPPmail for cryptographic processing DISABLED.
.EXAMPLE
    New-SM365Rules -SEPPmailDomain 'contoso.eu' -Placementpriority Bottom
    Creates mailflow rules to direct all mails for the contoso.eu domain in and out via SEPPmail for cryptographic processing and places the rules at the very last place of the existing non-SEPPmail rules.
.EXAMPLE
    New-SM365Rules -SEPPmailDomain 'contoso.eu','contoso.ch'
    Creates mailflow rules to direct all mails for both the contoso.eu and the contoso.ch domain in and out via SEPPmail for cryptographic processing.
.EXAMPLE
    New-SM365Rules -SEPPmailDomain 'contoso.eu' -SCLInboundvalue 0
    Creates mailflow rules to direct all mails for both the contoso.eu domain in and out via SEPPmail for cryptographic processing and takes all e-Mails (SCL 0), independent of their SPAM level.
#>
function New-SM365Rules
{
    [CmdletBinding(SupportsShouldProcess = $true,
                   ConfirmImpact = 'Medium'
                  )]
    param
    (
        [Parameter(Mandatory=$false,
                   HelpMessage='Should the new rules be placed before or after existing ones (if any)')]
        [ValidateSet('Top','Bottom')]
                   [String]$PlacementPriority = 'Top',

        [Parameter(Mandatory=$false,
                   HelpMessage='E-Mail domains you want to INCLUDE into cryptographic processing through the SEPPmail Appliance')]
        [ValidateScript(
            {   if (Get-AcceptedDomain -Identity $_ -Erroraction silentlycontinue) {
                    $true
                } else {
                    Write-Error "Domain $_ could not get validated, please check accepted domains with 'Get-AcceptedDomains'"
                }
            }
            )]
        [Alias('ManagedDomain')]           
        [String[]]$SEPPmailDomain,

        [Parameter(
		Mandatory = $false,
			HelpMessage = 'Rule 100/110 will only send e-mails to SEPPmail Appliance which requires cryptographic processing'
		)]
		[bool]$CryptoContentOnly = $true,

        [Parameter(Mandatory=$false,
        HelpMessage='SCL Value for inbound Mails which should NOT be processed by SEPPmail.Cloud. Default is 5')]
        [ValidateSet('-1','0','5','6','8','9')]
        [int]$SCLInboundValue=5,        

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Should the rules be created active or inactive'
        )]
        [bool]$Disabled = $true
    )

    begin
    {
        if (!(Test-SM365ConnectionStatus))
        { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        $ExistingTransportrules = Get-TransportRule

        $outboundConnectors = Get-OutboundConnector | Where-Object { $_.Name -match "^\[SEPPmail\]" }
        if(!($outboundConnectors))
        {
            throw [System.Exception] "No SEPPmail outbound connector found. Run `"New-SM365Connectors`" to add the proper SEPPmail connectors"
        }
        if ($($outboundConnectors.Enabled) -ne $true) {
            throw [System.Exception] "SEPPmail outbound-connector is disabled, cannot create rules. Create connectors without -Disable switch, or enable them in the admin portal."
        }
    }

    process
    {
        try
        {
            Write-Verbose "Read existing custom transport rules"
            $existingNonSMTransportRules = $ExistingTransportrules | Where-Object Name -NotMatch '^\[SEPPmail\].*$'
            [int] $placementPrio = @(0, $existingNonSMTransportRules.Count)[!($PlacementPriority -eq "Top")] <# Poor man's ternary operator #>
            if ($existingNonSMTransportRules)
            {
                if($InteractiveSession -and !$PSBoundParameters.ContainsKey("PlacementPriority") <# Prio already set, so no need to ask #>)
                {
                    Write-Warning 'Found existing custom transport rules.'
                    Write-Warning '--------------------------------------------'
                    foreach ($etpr in $existingTransportRules) {
                        Write-Warning "Rule name `"$($etpr.Name)`" with state `"$($etpr.State)`" has priority `"$($etpr.Priority)`""
                    }
                    Write-Warning '--------------------------------------------'
                    Do {
                        try {
                            [ValidateSet('Top', 'Bottom', 'Cancel', 't', 'T', 'b', 'B', 'c', 'C', $null)]$existingRulesAction = Read-Host -Prompt "Where shall we place the SEPPmail rules ? (Top(Default)/Bottom/Cancel)"
                        }
                        catch {}
                    }
                    until ($?)

                    switch ($existingRulesAction) {
                        'Top' { $placementPrio = '0' }
                        't' { $placementPrio = '0' }
                        'Bottom' { $placementPrio = ($existingTransportRules).count }
                        'b' { $placementPrio = ($existingTransportRules).count }
                        'Cancel' { return }
                        'c' { return }
                        default { $placementPrio = '0' }
                    }
                }
            }
            else
            {
                Write-Verbose 'No existing custom rules found'
            }
            Write-Verbose "Placement priority is $placementPrio"

            Write-Verbose "Read existing SEPPmail transport rules"
            $existingSMTransportRules = $ExistingTransportrules | Where-Object Name -Match '^\[SEPPmail\].*$'
            [bool] $createRules = $true
            if ($existingSMTransportRules)
            {
                if($InteractiveSession)
                {
                    Write-Warning 'Found existing [SEPPmail] Rules.'
                    Write-Warning '--------------------------------------------'
                    foreach ($eSMtpr in $existingSMTransportRules) {
                        Write-Warning "Rule name `"$($eSMtpr.Name)`" with state `"$($eSMtpr.State)`" has priority `"$($eSMtpr.Priority)`""
                    }
                    Write-Warning '--------------------------------------------'
                    Do {
                        try {
                            [ValidateSet('y', 'Y', 'n', 'N')]$recreateSMRules = Read-Host -Prompt "Shall we delete and recreate them ? (Y/N)"
                        }
                        catch {}
                    }
                    until ($?)
                    if ($recreateSMRules -like 'y') {
                        Remove-SM365Rules
                    }
                    else {
                        $createRules = $false
                    }
                }
                else
                {
                    throw [System.Exception] "SEPPmail Transport rules already exist"
                }
            }

            if($createRules)
            {
                $TransPortRuleFiles = Get-Childitem -Path "$PSScriptroot\..\ExoConfig\Rules\*.json"
                
                Write-Verbose "Building List of excluded Domains for outbound rule"
                [System.Collections.ArrayList]$ExcludeEmailDomain = (Get-AcceptedDomain).DomainName
                $SEPPmailDomain|Foreach-Object {$ExcludeEmailDomain.Remove($_)}

                Foreach ($File in $TransPortRuleFiles) {

                    $setting = Get-SM365TransportRuleSettings -File $File
					$setting.Priority = $placementPrio + $setting.SMPriority
					$setting.Remove('SMPriority')
                    if ($Disabled -eq $true) {
                        $setting.Enabled = $false
                    } else {
                        $setting.Enabled = $true
                    }
                    if (($ExcludeEmailDomain.count -ne 0) -and ($Setting.Name -eq '[SEPPmail] - 100 Route incoming e-mails to SEPPmail')) {
                        Write-Verbose "Excluding Inbound E-Mails domains $ExcludeEmailDomain"
                        $Setting.ExceptIfRecipientDomainIs = $ExcludeEmailDomain
						if ($SCLInboundValue -ne 5) {
							Write-Verbose "Setting Value $SCLInboundValue to Inbound flowing to SEPPmail.cloud"
						$Setting.ExceptIfSCLOver = $SCLInboundValue
						}
                    }

                    #1978 LimitInbound traffic to cryptographic e-mails.
                    if (($cryptoContentOnly) -and ($Setting.Name -eq '[SEPPmail] - 100 Route incoming e-mails to SEPPmail')) {
                        Write-Verbose "Setting HeaderContains* for crypto content only"
                        $Setting.HeaderContainsMessageHeader = 'content-type'
						$Setting.HeaderContainsWords = "application/x-pkcs7-mime","application/pkcs7-mime","application/x-pkcs7-signature","application/pkcs7-signature","multipart/signed","application/pgp-signature","multipart/encrypted","application/pgp-encrypted","application/octet-stream"			
                    }

                    if (($cryptoContentOnly) -and ($Setting.Name -eq '[SEPPmail] - 110 Route incoming tagged e-mails to SEPPmail')) {
                        Write-Verbose "Setting HeaderContains* for crypto content only"
						$setting.SubjectOrBodyContainsWords += '-----BEGIN PGP'
                    }

                    if (($ExcludeEmailDomain.count -ne 0) -and ($Setting.Name -eq '[SEPPmail] - 200 Route outgoing e-mails to SEPPmail')) {
                        Write-Verbose "Excluding Outbound E-Mail domains $ExcludeEmailDomain"
                        $Setting.ExceptIfSenderDomainIs = $ExcludeEmailDomain
                    }
                    if ($PSCmdlet.ShouldProcess($setting.Name, "Create transport rule"))
                    {
                        $Now = Get-Date
                        Write-Verbose "Adding Timestamp $now to Comment"
                        $ModuleVersion = $myInvocation.MyCommand.Version
                        Write-Verbose "Adding ModuleVersion $ModuleVersion to Comment"
                        $setting.Comments += "`n#Created with SEPPmail365 PowerShell Module version $ModuleVersion on $Now"
                        Write-Verbose "Creating rule with name $($Setting.Name)"
                        New-TransportRule @setting
                    }
                }                            
            }
        }
        catch {
            throw [System.Exception] "Error: $($_.Exception.Message)"
        }
    }

    end
    {

    }
}

<#
.SYNOPSIS
    Removes the SEPPmail inbound and outbound rules
.DESCRIPTION
    Convenience function to remove the SEPPmail rules with one command
.LINK
    https://github.com/seppmail/SEPPmail365/blob/master/Readme.md
.EXAMPLE
    Remove-SM365Rules -whatif
    Simulates the removal
.EXAMPLE
    Remove-SM365Rules -verbose
    Adds extra output
.EXAMPLE
    Remove-SM365Rules
    Removes all [SEPPmail] rules
#>
function Remove-SM365Rules {
    [CmdletBinding(SupportsShouldProcess = $true,
                   ConfirmImpact = 'Medium'
                  )]
    param
    (
    )

    if (!(Test-SM365ConnectionStatus))
    { 
        throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" 
    }

    Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

    Write-Verbose "Removing current version module rules"
    $TransPortRuleFiles = Get-Childitem -Path "$PSScriptroot\..\ExoConfig\Rules\*.json"
    Foreach ($File in $TransPortRuleFiles) {
        $setting = Get-SM365TransportRuleSettings -File $File
            if($PSCmdlet.ShouldProcess($setting.Name, "Remove transport rule"))
            {
                $rule = Get-TransportRule $setting.Name -ErrorAction SilentlyContinue
                if($rule)
                    {$rule | Remove-TransportRule -Confirm:$false}
                else
                    {Write-Verbose "Rule $($setting.Name) does not exist"}
            }   
    }

    Write-Verbose "Removing module 1.1.x version rules"
    [string[]]$11rules = '[SEPPmail] - Route incoming/internal Mails to SEPPmail',`
                         '[SEPPmail] - Route ExO organiz./internal Mails to SEPPmail',`
                         '[SEPPmail] - Route outgoing/internal Mails to SEPPmail',`
                         '[SEPPmail] - Skip SPF check after incoming appliance routing',`
                         '[SEPPmail] - Skip SPF check after internal appliance routing'
    try 
    {
        foreach ($rule in $11rules) 
        {
            If($PSCmdLet.ShouldProcess($rule, "Remove module 1.1 transport rule")) 
            {
                If (Get-TransportRule -id $rule -ErrorAction SilentlyContinue) 
                {
                    {
                        Remove-TransportRule -id $rule -Confirm:$false
                    }
                }
            }
        }
    }
    catch 
    {
        throw [System.Exception] "Error: $($_.Exception.Message)"
    }        
}

if (!(Get-Alias 'Set-SM365rules' -ErrorAction SilentlyContinue)) {
    New-Alias -Name Set-SM365Rules -Value New-SM365Rules
}

Register-ArgumentCompleter -CommandName New-SM365Rules -ParameterName SEPPmailDomains -ScriptBlock $paramDomSB


# SIG # Begin signature block
# MIIVzAYJKoZIhvcNAQcCoIIVvTCCFbkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCv9YaImiW0Qb4q
# ADhZZ+vdAFtliZHDzC0Z2CgtHQcYCqCCEggwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDw0KgCahmxNqrx+93FcN3Z850V
# /sTEcZYkelofOwQNVTANBgkqhkiG9w0BAQEFAASCAgARpnicYosO6sNpJYTkpTF9
# LTMgJgHxf06bU8J3L1AR/SoyzMtxOIlVUdftpChHg5njy3aX8GDYBOkR02Fb7e4i
# nOY8pDPtbdb4oZiN7Yh94ZZ3bI5c41jLGJOKmCsXQPyuJGSALUntAIKk1+KSsa0W
# a+yJL6DbzMnTtvgjtJXBQWUHgBzFp6P4DMH7qS92Amraj9A6FIH5+C+wck3ppK+3
# 3243GfTpAc3y2dIF8cH61K7LQo9mm7OkXpLh4knQVx6Qvcz+KFrRAYOUmIWLGoBh
# AqVyxRyBe/kn0bJncyn6Ur6Iys/qQMRle3+L9tHvsky49MmdU+N9hpbjIUTNRyN5
# UlGm0vQxz6alamKRBx/TC3Y/2VJ+wEuvmA2H4lD7QIA2gTumkfkQwu9HSFrSTSmw
# J6PlvPV+RpY4EGrVe/QfJ/fttNm7hCqOFPPFINP0WQUQn8t4pxUx28kPv45cFnCS
# m0mpvb37yivkNot4B+kmzMhDQ+N519jzyH5wsj6ls9v+AuGvDBfrGXUh3jhrSyzD
# EmWrBPvUdYMqPHpPMFiPR2++ixmWJktxeIrQPZSa6ud/MsOArRumif7LR3hzo6Tz
# ibWF1Px0JbtUi340Aaov8EV2q+/VjOYoa4VQBN5dc+GV4aYPJ/NRTlV/AbRLrqBU
# ycqyzAMjECseYHzeD489RA==
# SIG # End signature block
