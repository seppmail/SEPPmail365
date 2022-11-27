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
                    <#$outputHt = [ordered]@{
                        Name = $rule.Name
                        State = $rule.State
                        Priority = $rule.Priority
                        ExceptIfSenderDomainIs = $rule.ExceptIfSenderDomainIs
                        ExceptIfRecipientDomainIs = $rule.ExceptIfRecipientDomainIs
                        RouteMessageOutboundConnector = $rule.RouteMessageOutboundConnector
                        Comments = $rule.Comments    
                    }
                    $outputRule = New-Object -TypeName PSObject -Property $outputHt
                    Write-Output $outputRule
                    #return $rule
                    #>
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
        [Alias('Managedomains')]           
        [String[]]$SEPPmailDomain,

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
                    }
                    if (($ExcludeEmailDomain.count -ne 0) -and ($Setting.Name -eq '[SEPPmail] - 100 Route incoming e-mails to SEPPmail')) {
                        Write-Verbose "Excluding Inbound E-Mails domains $ExcludeEmailDomain"
                        $Setting.ExceptIfRecipientDomainIs = $ExcludeEmailDomain
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
    Updates existing SEPPmail transport rules to default values
.DESCRIPTION
    The -Version parameter can be used to update to a specific ruleset version
    matching your SEPPmail appliance.
.EXAMPLE
    Set-SM365Rules -Version Default
#>

<#
.SYNOPSIS
    Removes the SEPPmail inbound and outbound connectors
.DESCRIPTION
    Convenience function to remove the SEPPmail connectors
.EXAMPLE
    Remove-SM365Connectors
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
# MIIL/AYJKoZIhvcNAQcCoIIL7TCCC+kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB0X648yxE4Dxk+
# ztiQOQX7VobwYyx9QlQfjH+1pqZQt6CCCUAwggSZMIIDgaADAgECAhBxoLc2ld2x
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCUJrXCQP2x12GDagk1ON1ETquO
# q2URsvMZV8We8B42pjANBgkqhkiG9w0BAQEFAASCAQBLExO2l4EilyGSQNx8Ku3/
# 0hJhg8Ec4lI2Y2gHkU+Ju0Tbn6UirotQxGkNif72Qpkyb19pgrR+WBJCZzuhXBIo
# qMtHKPoSvPGiuoOG3kHM8Bp3kWsCanmve2RdHPQ5uF8k7Kdf4faYo6SBNaORs9S+
# MgvAd1qsrGG1YqyUuIgenxxvWkefSBHXXEcV7ja7daiVwnJkE6JCU6n7+Sv6Za08
# E1hHAad40JHeoW6pbO4iYwgFS3hN5lQ9EJjeHaEvutKbscDN1vBY5+ESUpP0SBHu
# JgIIgWVeyVqzH6dTlKcm97YfZUXzOwRshn0QA3Uq/gEqvzYxp3jHZycPPTa3xtDt
# SIG # End signature block
