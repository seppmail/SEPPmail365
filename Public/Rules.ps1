﻿function Get-SM365Rules {
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
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJS8Ggj0ssB+l514TxDWq8RGr
# LRKggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
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
# MRYEFJ4q1Q/kVWDpRsw15SJ6t2MQN71AMA0GCSqGSIb3DQEBAQUABIIBAGFzqXk2
# oAaF7vD/x3bRWItVvdngBuXPdVJ446g5badWZ6b7nWwMl7m+zZYPS8Cp1rbak6IZ
# vKWzLmhXu6uANmRzRPbcZOeVP0yYUrAKDXSlIqwyxzsBf185LaZRODKq3FOxL7pf
# vOWsnDm4J6nHfKWsG7NW8Pj3pSnvSilRvHbOjg5/sod4hKILDZnrChFfCnvlqSQL
# DzC+Ooa15pv/BqV/p8SWQV6ERnUGXpOj/8YdIDeuwLJzlwiwzy60IFH2LhWPEqbG
# ZhpvPLzS1bp8qVaOSSlSGAMVur6whPUopIr/SRNkmJLzd1GDLSTYwnEAXg7rWUVm
# BvcgkXUFBdI8bJs=
# SIG # End signature block
