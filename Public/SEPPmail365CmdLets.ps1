﻿<#
.SYNOPSIS
    Adds SEPPmail Exchange Online connectors
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online
    This commandlet will create the connectors for you.

    The -SEPPmailFQDN must point to a SEPPmail Appliance with a valid certificat to establish the TLS conenction.

.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.consoso.com'
#>
function New-SM365Connectors
{
    [CmdletBinding(SupportsShouldProcess = $true,
                           ConfirmImpact = 'Medium'
                    )]
    param(
            [Parameter(
                Mandatory = $true,
                HelpMessage = 'FQDN of the SEPPmail Appliance'
            )]
            [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
            [Alias("FQDN")]
            [String]$SEPPmailFQDN,

            [Parameter(
                Mandatory = $true,
                HelpMessage = 'Associated Accepted Domains, the connector will take e-Mails from'
            )]
            [Alias("ibad")]
            [String[]]$InboundAcceptedDomains
        )

    begin
    {
        if (!(Get-AcceptedDomain))
        {
            Write-Error "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"
            break
        }
        else
        {
            $defdomain = (Get-AcceptedDomain | Where-Object Default -Like 'True').DomainName
            Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue

            Write-Verbose "Testing for hybrid Setup"
            $HybridInboundConn = Get-InboundConnector |Where-Object {(($_.Name -clike 'Inbound from *') -or ($_.ConnectorSource -clike 'HybridWizard'))} 
            $HybridOutBoundConn = Get-OutBoundConnector |Where-Object {(($_.Name -clike 'Outbound to *') -or ($_.ConnectorSource -clike 'HybridWizard'))} 

            if ($HybridInboundConn -or $HybridOutBoundConn) {
                Write-Warning "!!! - Hybrid Configuration detected - we assume you know what you are doing. Be sure to backup your connector settings before making any change."
                Write-Verbose "Ask user to continue if Hybrid is found."
                Do
                {
                    try
                    {
                        [ValidateSet('y', 'Y', 'n', 'N')]$hybridContinue = Read-Host -Prompt "Create SEPPmail connectors in hybrid environment ? (Y/N)"
                    }
                    catch {}
                }
                until ($?)
                if (($hybridContinue -eq 'n') -or ($hybridContinue -eq 'N')) {
                    Write-Verbose "Exiting due to user decision."
                    break
                }
    
            } else {
                Write-Information "No Hybrid Connectors detected, seems to be a clean cloud-only environment" -InformationAction Continue
            }

            function New-SM365InboundConnector {
                Write-Verbose "Creating SEPPmail Inbound Connector !"
                if ($PSCmdLet.ShouldProcess($($InboundConnParam.Name),'Creating Inbound Connector')) {
                    $InboundConn = New-InboundConnector @InboundConnParam 
                }
            }
            function New-SM365OutboundConnector {
                Write-Verbose "Creating SEPPmail Outbound Connector $($outboundConnParam.Name)!"
                if ($PSCmdLet.ShouldProcess($($outboundConnParam.Name),'Creating Outbound Connector')) {
                    $OutboundConn = New-OutboundConnector @OutboundConnParam
                }
            }
        }
    }

    process
    {
        #region
        Write-Verbose "Load default connector settings from PSModule folder and transform into hashtables"
        $InboundConnParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Connectors\Inbound.json -Raw)).psobject.properties | ForEach-Object { $InboundConnParam[$_.Name] = $_.Value }
        $OutboundConnParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Connectors\Outbound.json -Raw)).psobject.properties | ForEach-Object { $OutboundConnParam[$_.Name] = $_.Value }

        Write-Verbose "Fill in values from Parameters"
        $OutboundConnParam.SmartHosts = $SEPPmailFQDN
        $OutboundConnParam.TlsDomain = $SEPPmailFQDN
        $InboundConnParam.TlsSenderCertificateName = $SEPPmailFQDN
        Write-Verbose "Set AssociatedAcceptedDomains to $null for all or specific domains"
        if ($InboundAcceptedDomains -eq '*') {
            Write-Verbose "Removing Key AssociatedAcceptedDomains from parameter-hashtable"
            $InboundConnParam.Remove('AssociatedAcceptedDomains')
        }
        else {
            $InboundConnParam.AssociatedAcceptedDomains = $InboundAcceptedDomains
        }
        #endregion

        Write-Verbose "Read existing SEPPmail Inbound Connector"
        $existingSMInboundConn = Get-InboundConnector | Where-Object Name -Match '^\[SEPPmail\].*$'
        if ($existingSMInboundConn)
        {
            Write-Warning "Found existing SEPPmail inbound Connector with name: `"$($existingSMInboundConn.Name)`", created `"$($existingSMInboundConn.WhenCreated)`" incoming SEPPmail is `"$($existingSMInboundConn.TlsSenderCertificateName)`""
            Do
            {
                try
                {
                    [ValidateSet('y', 'Y', 'n', 'N')]$recreateSMInboundConn = Read-Host -Prompt "Shall we delete and recreate the inbound connector ? (Y/N)"
                }
                catch {}
            }
            until ($?)

            if ($recreateSMInboundConn -like 'y')
            {
                Write-Verbose "Removing existing SEPPmail Inbound Connector !"
                $existingSMInboundConn | Remove-InboundConnector 
                
                New-SM365InboundConnector
            }
            
            else
            {
                Write-Warning "Leaving existing SEPPmail Inbound Connector `"$($existingSMInboundConn.Name)`" untouched."
            }
        }
        else
        {
            New-SM365InboundConnector
        }

        Write-Verbose "Read existing SEPPmail outbound connector"
        $existingSMOutboundConn = Get-OutboundConnector | Where-Object Name -Match '^\[SEPPmail\].*$'
        if ($existingSMOutboundConn)
        {
            Write-Warning "Found existing SEPPmail outbound connector with name: `"$($existingSMOutboundConn.Name)`" created on `"$($existingSMOutboundConn.WhenCreated)`" pointing to SEPPmail `"$($existingSMOutboundConn.TlsDomain)`" "
            Do
            {
                try
                {
                    [ValidateSet('y', 'Y', 'n', 'N')]$recreateSMOutboundConn = Read-Host -Prompt "Shall we delete and recreate the outbound connector ? (Y/N)"
                }
                catch {}
            }
            until ($?)

            if ($recreateSMOutboundConn -like 'y')
            {
                Write-Verbose "Removing existing Outbound Connector $($existingSMOutboundConn.Name) !"
                $existingSMOutboundConn | Remove-OutboundConnector

                New-SM365OutboundConnector
            }
            else
            {
                Write-Warning "Leaving existing SEPPmail outbound connector `"$($existingSMOutboundConn.Name)`" untouched."
            }
        }
        else
        {
            New-SM365OutboundConnector
        }
    }

    end
    {
        if ($outboundConn) { return $OutboundConn }
        if ($inboundConn) { return $InboundConn }
    }
}

<#
.SYNOPSIS
    Create SEPPmailruleset
.DESCRIPTION
    Creates rules to direct the mailflow between Exchange Online and SEPPmail
.EXAMPLE
    PS C:\> New-SM365Rules
    Creates the needed ruleset to integrate SEPPmail with Exchange online
#>
function New-SM365Rules
{
    [CmdletBinding(SupportsShouldProcess = $true,
                           ConfirmImpact = 'Medium'
                    )]
    param(

    )

    begin
    {
        try {
            if (!(Get-AcceptedDomain))
            {
                Write-Error "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"
                break
            }
            else
            {
                $defdomain = (Get-AcceptedDomain | Where-Object Default -Like 'True').DomainName
                Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue
            }
        } catch {
            Write-Error "Could not retrieve Exchange Online information - are you connected to your subscription as admin ?"
            Write-Error "Category Info: $Error[0].CategoryInfo"
        }
    }

    process
    {
        try {
            Write-Verbose "Read existing custom transport rules"
            $existingTransportRules = Get-TransportRule | Where-Object Name -NotMatch '^\[SEPPmail\].*$'
            if ($existingTransportRules)
            {
                Write-Warning 'Found existing custom transport rules.'
                Write-Warning '--------------------------------------------'
                foreach ($etpr in $existingTransportRules)
                {
                    Write-Warning "Rule name `"$($etpr.Name)`" with state `"$($etpr.State)`" has priority `"$($etpr.Priority)`""
                }
                Write-Warning '--------------------------------------------'
                Do
                {
                    try
                    {
                        [ValidateSet('Top', 'Bottom', 'Cancel','t','T','b','B','c','C',$null)]$existingRulesAction = Read-Host -Prompt "Where shall we place the SEPPmail rules ? (Top(Default)/Bottom/Cancel)"
                    }
                    catch {}
                }
                until ($?)

                switch ($existingRulesAction)
                {
                    'Top' { $placementPrio = '0' }
                    't' { $placementPrio = '0' }
                    'Bottom' { $placementPrio = ($existingTransportRules).count }
                    'b' { $placementPrio = ($existingTransportRules).count }
                    'Cancel' { exit }
                    'c' { exit }
                    default { $placementPrio = '0' }
                }
            }
            else
            {
                Write-Verbose 'No existing custom rules found'
            }
            Write-Verbose "Placement priority is $placementPrio"

            Write-Verbose "Read existing SEPPmail transport rules"
            $existingSMTransportRules = Get-TransportRule | Where-Object Name -Match '^\[SEPPmail\].*$'
            if ($existingSMTransportRules)
            {
                Write-Warning 'Found existing [SEPPmail] Rules.'
                Write-Warning '--------------------------------------------'
                foreach ($eSMtpr in $existingSMTransportRules)
                {
                    Write-Warning "Rule name `"$($eSMtpr.Name)`" with state `"$($eSMtpr.State)`" has priority `"$($eSMtpr.Priority)`""
                }
                Write-Warning '--------------------------------------------'
                Do
                {
                    try
                    {
                        [ValidateSet('y', 'Y', 'n', 'N')]$recreateSMRules = Read-Host -Prompt "Shall we delete and recreate them ? (Y/N)"
                    }
                    catch {}
                }
                until ($?)
                if ($recreateSMRules -like 'y')
                {
                    Remove-SM365TransportRules
                    New-SM365TransportRules
                }
            }
            else
            {
                New-SM365TransportRules
            }
        }
        catch {
            Write-Error "Error $_.CategoryInfo occured"
        }
    }

    end
    {

    }
}

<#
.SYNOPSIS
    Removes the SEPPmail inbound and outbound connectors
.DESCRIPTION
    Convenience function to remove the SEPPmail connectors
.EXAMPLE
    Remove-SM365Connector
#>
function Remove-SM365Connector 
{
    [CmdletBinding(SupportsShouldProcess=$true,
                   ConfirmImpact='Medium')]
    Param 
    (
           
    )

    if($PSCmdlet.ShouldProcess("Outbound connector", "Remove SEPPmail connector"))
    {Get-OutboundConnector | Where-Object Name -Match '^\[SEPPmail\].*$' | Remove-OutboundConnector}

    if($PSCmdlet.ShouldProcess("Inbound connector", "Remove SEPPmail connector"))
    {Get-InboundConnector | Where-Object Name -Match '^\[SEPPmail\].*$' | Remove-InboundConnector}
}

<#
.SYNOPSIS
    Produce a status Report for M365 Exchange Online
.DESCRIPTION
    Before any change to the message flow is done, this report retreives the most needed information to decide how to integrate SEPPmail into Exchange Online
.EXAMPLE
    New-SM365ExOReport
#>
function New-SM365ExOReport {
    [CmdletBinding(SupportsShouldProcess=$true,
                   ConfirmImpact='Medium')]
    Param (
        # Define output Format
        [Parameter(Mandatory=$false)]
        [ValidateSet("Console", "HTML")]
        $Output = 'Console'
    )

    begin {
    }

    process {
        try {
            if ($pscmdlet.ShouldProcess("Target", "Operation")) {
                #"Whatis is $Whatif and `$pscmdlet.ShouldProcess is $($pscmdlet.ShouldProcess) "
                #For later Use
            }
            #$HA = "Accepted Domains"|Convertto-HTML -Property @{l='Report section'; e={ $_}} -Fragment
            $A = Get-AcceptedDomain |select-object Domainname,DomainType,Default,EmailOnly,ExternallyManaged,OutboundOnly|Convertto-HTML -Fragment
            
            Write-Verbose "Audit Log and Dkim Settings"
            $B = Get-AdminAuditLogConfig |Select-Object Name,AdminAuditLogEnabled,LogLevel,AdminAuditLogAgeLimit |Convertto-HTML -Fragment
            $C = Get-DkimSigningConfig|Select-Object Domain,Status|Convertto-HTML -Fragment

            Write-Verbose "Phishing and Malware Policies"
            $D = Get-AntiPhishPolicy|Select-Object Identity,isDefault,IsValid|Convertto-HTML -Fragment
            $E = Get-MalwareFilterPolicy|Select-Object Identity,Action,IsDefault|Convertto-HTML -Fragment

            Write-Verbose "ATP Information"
            $F = Get-ATPTotalTrafficReport|Select-Object Organization,Eventtype,Messagecount|Convertto-HTML -Fragment

            Write-Verbose " Get-HybridMailflow"
            $G = Get-HybridMailflow|Convertto-HTML -Fragment
            
            #Write-Verbose " Get-HybridMailflowDatacenterIPs"
            #Get-HybridMailflowDatacenterIPs|Select-Object -ExpandProperty DatacenterIPs|Format-Table
            #$H = Get-IntraOrganizationConfiguration|Select-Object OnlineTargetAddress,OnPremiseTargetAddresses,IsValid|Convertto-HTML -Fragment
            
            Write-Verbose "Get-IntraorgConnector"
            $I = Get-IntraOrganizationConnector|Select-Object Identity,TargetAddressDomains,DiscoveryEndpoint,IsValid|Convertto-HTML -Fragment
            
            Write-Verbose "Get-MigrationConfig"
            $J = Get-MigrationConfig|Select-Object Identity,Features,IsValid|Convertto-HTML -Fragment
            
            Write-Verbose "Get-MigrationStatistics"
            $K = Get-MigrationStatistics|Select-Object Identity,Totalcount,FinalizedCount,MigrationType,IsValid|Convertto-HTML -Fragment

            Write-Verbose "InboundConnectors"
            $L = Get-InboundConnector |Select-Object Identity,ConnectorType,ConnectorSource,EFSkipLastIP,EFUsers,IsValid|Convertto-HTML -Fragment
            
            Write-Verbose "OutboundConnectors"
            $M = Get-OutboundConnector|Select-Object Identity,ConnectorType,ConnectorSource,EFSkipLastIP,EFUsers,IsValid|Convertto-HTML -Fragment
            
            Write-Verbose "TransportRules"
            $N = Get-TransportRule | select-object Name,IsValid |Convertto-HTML -Fragment

            $style = "<style>BODY{font-family: Arial; font-size: 10pt;}"
            $style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
            $style = $style + "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
            $style = $style + "TD{border: 1px solid black; padding: 5px; }"
            $style = $style + "</style>"
            Convertto-HTML -Body "$HA $a $b $c $d $e $f $g $i $j $k $l $m $n" -Title "SEPPmail365 Exo Report" -Head $style

        }
        catch {
            Write-Error "Error $_.CategoryInfo occured"
        }
    }   
    end {
    }
}
# SIG # Begin signature block
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUris45MMqj1M3SxP5MfYaKgeK
# b4uggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
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
# MRYEFNDDze6h8zApcPAFOO7S1KPA13cgMA0GCSqGSIb3DQEBAQUABIIBAB3eBbX/
# 3MXL6PnU558vhOXL4eAyksiSyOm0GuA6QdL7RP7o3ElWlxYN/YUOyOaxgNdvb87e
# +s9nr1l2ckDSZ/aytFTjeJkYcRKd03CTnfIbn/GHsNp88WsRD3kQhei0OngB2vjz
# soweFE+stwAqN1yB4L1SobZDCGOzzuOXePqg5EBDIucu7WeaBxFVAooshfaHhCvB
# qfGVEBhaLu66nHrQmHV7l968GCgcSbOZTFDau/wNx92yQS0/yT0dAaJN50kgZWwO
# 70zSVY4KzUgfs8wsNsqW7age53RsapjSJwxnu//uDQ1YyzNvlokPp6pDG9yQ0Hm5
# QejYRgR8Uvdh3Hc=
# SIG # End signature block
