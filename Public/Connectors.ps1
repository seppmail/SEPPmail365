<#
.SYNOPSIS
    Read existing SEPPmail Exchange Online connectors
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online
    This commandlet will show existing connectors.

.EXAMPLE
    Get-SM365Connectors
#>
function Get-SM365Connectors
{
    [CmdletBinding()]
    Param
    ()

    if (!(Test-SM365ConnectionStatus))
    { 
        throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet"
    }
    else {
        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        $inbound = Get-SM365InboundConnectorSettings -Version "None"
        $outbound = Get-SM365OutboundConnectorSettings -Version "None"
    
        if (Get-OutboundConnector | Where-Object Identity -eq $($outbound.Name))
        {
            $obc = Get-OutboundConnector $outbound.Name
            $obOutputHT = [ordered]@{
                   OutBoundConnectorName = $obc.Name
             OutBoundConnectorSmartHosts = $obc.SmartHosts
              OutBoundConnectorTlsDomain = $obc.TlsDomain
            OutBoundConnectorTlsSettings = $obc.TlsSettings
                OutBoundConnectorEnabled = $obc.Enabled
            }
            $obOutputConnector = New-Object -TypeName PSObject -Property $obOutputHt
            Write-Output $obOutputConnector

        }
        else {
            Write-Warning "No SEPPmail Outbound Connector with name `"$($outbound.Name)`" found"
        }
    
    
        if (Get-InboundConnector | Where-Object Identity -eq $($inbound.Name))
        {
            $ibc = Get-InboundConnector $inbound.Name

            $ibOutputHT = [ordered]@{
                                InboundConnectorName = $ibc.Name
                   InboundConnectorSenderIPAddresses = $ibc.SenderIPAddresses
            InboundConnectorTlsSenderCertificateName = $ibc.TlsSenderCertificateName
                          InboundConnectorRequireTLS = $ibc.RequireTLS
                             InboundConnectorEnabled = $ibc.Enabled
            }
            $ibOutputConnector = New-Object -TypeName PSObject -Property $ibOutputHt
            Write-Output $ibOutputConnector

        }
        else 
        {
            Write-Warning "No SEPPmail Inbound Connector with Name `"$($inbound.Name)`" found"
        }
    
    
    }
}

<#
.SYNOPSIS
    Adds SEPPmail Exchange Online connectors
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online
    This commandlet will create the connectors for you.

    The -SEPPmailFQDN must point to a SEPPmail Appliance with a valid certificate to establish the TLS connection.
    To use a wildcard certifiacate, use the -TLSCertName parameter.

.EXAMPLE
    Takes the Exchange Online environment settings and creates Inbound and Outbound connectors to a SEPPmail Appliance with a wildcard TLS certificate

    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com' -TLSCertName '*.contoso.com'
.EXAMPLE
    Takes the Exchange Online environment settings and creates Inbound and Outbound connectors to a SEPPmail Appliance.
    Assumes that the TLS certificate is identical with the SEPPmail FQDN

    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com'
.EXAMPLE
    Same as above, just no officially trusted certificate needed
    
    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com' -AllowSelfSignedCertificates
.EXAMPLE
    Same as the default config, just with no TLS encryption at all.

    New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -NoOutBoundTlsCheck
.EXAMPLE
    If you want to create the connectors, but just disable them on creation, use the -Disabled switch.

    New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -Disabled

.EXAMPLE
    If your SEPPmail is just accessible via an IP Address, use the -SEPPmailIP parameter.

    New-SM365Connectors -SEPPmailIp '51.144.46.62'

.EXAMPLE 
    To avoid, adding the SEPPmail to the ANTI-SPAM WHiteList of Microsoft Defender use the example below
     
    New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -Option NoAntiSpamWhiteListing
#>
function New-SM365Connectors
{
    [CmdletBinding(
         SupportsShouldProcess = $true,
         ConfirmImpact = 'Medium',
         DefaultParameterSetName = 'FqdnTls'
     )]

    param
    (
        #region FqdnTls
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'FQDN of the SEPPmail Appliance, i.e. securemail.contoso.com',
            ParameterSetName = 'FqdnTls',
            Position = 0
        )]
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'FQDN of the SEPPmail Appliance, i.e. securemail.contoso.com',
            ParameterSetName = 'FqdnNoTls',
            Position = 0
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias('FQDN','SMFQDN')]
        [String] $SEPPmailFQDN,
        #endregion fqdntls

        #region TLSSenderCertificateName
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Name of the certificate if different from the SEPPmail-FQDN. Read the cetificate name in your SEPPmail under SSL==>Issued to==>Name (CN)',
            ParameterSetname = 'FqdnTls',
            Position = 1
        )]
        [Alias('TLSCertName','CertName')]
        [String] $TLSCertificateName,
        #endregion

        #region selfsigned
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'OutBound Connector trusts also self signed certificates',
            ParameterSetName = 'FqdnTls'
        )]
        [Alias('AllowSelfSigned','SelfSigned')]
        [Switch] $AllowSelfSignedCertificates,
        #endregion SelfSigned

        #region NoOutboundTls
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'OutBound Connector allows also non-TLS conenctions',
            ParameterSetName = 'FqdnNoTls'
        )]
        [Alias('NoTls')]
        [Switch] $NoOutBoundTlsCheck,
        #endregion NoTls

        #region IP
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'If SEPPmail has no FQDN and is represented as an IP Address',
            ParameterSetName = 'Ip',
            Position = 0
        )]
        [ValidatePattern("(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")]
        [Alias('SMIP','SMIPAddress')]
        [string] $SEPPmailIP,
        #endregion IP

        #region Option
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Which configuration version to use',
            ParameterSetName = 'FqdnTls'
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Which configuration version to use',
            ParameterSetName = 'FqdnNoTls'
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Which configuration version to use',
            ParameterSetName = 'Ip'
        )]
        [SM365.ConfigOption[]]$Option = 'Default',
        #endregion Option

        #region disabled
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Disable the connectors on creation',
            ParameterSetName = 'FqdnTls'
         )]
        [Parameter(
           Mandatory = $false,
           HelpMessage = 'Disable the connectors on creation',
           ParameterSetName = 'FqdnNoTls'
        )]
        [Parameter(
           Mandatory = $false,
           HelpMessage = 'Disable the connectors on creation',
           ParameterSetName = 'Ip'
        )]
        [switch]$Disabled
        #endregion disabled

    )

    begin
    {
        if(!(Test-SM365ConnectionStatus))
        {throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet"}
        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        #resolve IP
        if ($PSCmdLet.ParameterSetName -like 'Fqdn*') {
            try {
                Write-Verbose "Transform $SEPPmailFQDN to IP Adress for IP based options"
                $SEPPmailIP = ([System.Net.Dns]::GetHostAddresses($SEPPmailFQDN).IPAddressToString)
                Write-Verbose "$SEPPmailFQDN equals the IP(s): $SEPPmailIP"
            }
            catch {
                Write-Error "Could not resolve IP Address of $SEPPmailFQDN. Please check SEPPmailFQDN hostname and try again."
                break
            }
        }

        Write-Verbose "Prepare Values out of Parametersets"
        If (($PsCmdLet.ParameterSetName -like 'FqdnTls') -or ($PsCmdLet.ParameterSetName -eq 'FqdnTls')) {
                $InboundTlsDomain = $SEPPmailFQDN
                $OutboundTlsDomain = $SEPPmailFQDN
            }
        else {
            [string[]]$SenderIPAddresses = $SEPPmailIP
        }

        #region collecting existing connectors
        Write-Verbose "Collecting existing connectors"
        $allInboundConnectors = Get-InboundConnector
        $allOutboundConnectors = Get-OutboundConnector

        Write-Verbose "Testing for hybrid Setup"
        $HybridInboundConn = $allInboundConnectors |Where-Object {(($_.Name -clike 'Inbound from *') -or ($_.ConnectorSource -clike 'HybridWizard'))}
        $HybridOutBoundConn = $allOutboundConnectors |Where-Object {(($_.Name -clike 'Outbound to *') -or ($_.ConnectorSource -clike 'HybridWizard'))}

        if ($HybridInboundConn -or $HybridOutBoundConn)
        {
            Write-Warning "!!! - Hybrid Configuration detected - we assume you know what you are doing. Be sure to backup your connector settings before making any change."

            if($InteractiveSession)
            {
                Write-Verbose "Ask user to continue if Hybrid is found."
                Do {
                    try {
                        [ValidateSet('y', 'Y', 'n', 'N')]$hybridContinue = Read-Host -Prompt "Create SEPPmail connectors in hybrid environment ? (Y/N)"
                    }
                    catch {}
                }
                until ($?)
                if ($hybridContinue -eq 'n') {
                    Write-Verbose "Exiting due to user decision."
                    break
                }
            }
            else
            {
                # should we error out here, since connector creation might be dangerous?
            }
        } else {
            Write-Information "No Hybrid Connectors detected, seems to be a clean cloud-only environment" -InformationAction Continue
        }
        #endregion

    }

    process
    {
        #region - Inbound Connector
        Write-Verbose "Read Inbound Connector Settings"
        $inbound = Get-SM365InboundConnectorSettings -Version 'Default' -Option $Option
        
        if ($PSCmdLet.ParametersetName -eq 'FqdnTls') {
            $inbound.TlsSenderCertificateName = $InboundTlsDomain
        }
        
        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($disabled) {
            $inbound.Enabled = $false
        }

        Write-Verbose "Setting SEPPmail IP Address(es) $SEPPmailIP for EFSkipIP´s and Anti-SPAM Whitelist"
        [string[]]$SEPPmailIprange = $SEPPmailIP
        $inbound.EFSkipIPs.AddRange($SEPPmailIPRange)

        Write-Verbose "Read existing SEPPmail Inbound Connector from Exchange Online"
        $existingSMInboundConn = $allInboundConnectors | Where-Object Name -EQ $inbound.Name

        # only $false if the user says so interactively
        [bool]$createInbound = $true
        if ($existingSMInboundConn)
        {
            Write-Warning "Found existing SEPPmail inbound Connector with name: `"$($existingSMInboundConn.Name)`", created `"$($existingSMInboundConn.WhenCreated)`" incoming SEPPmail is `"$($existingSMInboundConn.TlsSenderCertificateName)`""

            if($InteractiveSession)
            {
                [string] $tmp = $null
                Do {
                    try {
                        [ValidateSet('y', 'Y', 'n', 'N')]$tmp = Read-Host -Prompt "Shall we delete and recreate the inbound connector (will only work if no rules use it)? (Y/N)"
                        break
                    }
                    catch {}
                }
                until ($?)

                if ($tmp -eq 'y') {
                    $createInbound = $true

                    Write-Verbose "Removing existing SEPPmail Inbound Connector $($existingSMInboundConn.Name) !"
                    if ($PSCmdLet.ShouldProcess($($existingSMInboundConn.Name), 'Removing existing SEPPmail inbound Connector')) {
                        $existingSMInboundConn | Remove-InboundConnector -Confirm:$false # user already confirmed action

                        if (!$?)
                        { throw $error[0] }
                    }
                }
                else {
                    Write-Warning "Leaving existing SEPPmail Inbound Connector `"$($existingSMInboundConn.Name)`" untouched."
                    $createInbound = $false
                }
            }
            else
            {
                throw [System.Exception] "Inbound connector $($inbound.Name) already exists"
            }
        }
        else
        {Write-Verbose "No existing Inbound Connector found"}

        if($createInbound)
        {
            # necessary assignment for splatting
            $param = $inbound.ToHashtable()

            Write-Verbose "Modify params based on ParameterSet"
            Write-verbose "IP based Config, using $SenderIPAdresses"
            if ($PSCmdLet.ParameterSetName -eq 'Ip') {
                $param.SenderIPAddresses = $SenderIPAddresses
                $param.RequireTls = $false
            } 
            Write-Verbose "FQDN and Self Signed certificates, TLSCertificatename = $SEPPmailFQDN"
            if (($PSCmdLet.ParameterSetName -eq 'FQDNTls') -and ($AllowSelfSignedCertificates)) {
                $param.RestrictDomainsToCertificate = $false
                $param.TlsSenderCertificateName = $SEPPmailFQDN
            }
            Write-Verbose "FQDN and certificatename equals FQDN, using $SEPpmailFQDN as TLSCertificateName"
            if (($PSCmdLet.ParameterSetName -eq 'FQDNTls') -and ($TLSCertificateName.Length -eq 0)) {
                $param.TlsSenderCertificateName = $SEPPmailFQDN
            }
            Write-Verbose "FQDN and certificatename specified, using $TlscertificateName as TLSCertificateName"
            if (($PSCmdLet.ParameterSetName -eq 'FQDNTls') -and ($TLSCertificateName.Length -gt 0)) {
                $param.TlsSenderCertificateName = $TLSCertificateName
            }
            Write-Verbose "NoTls, using $SEPPmailFQDN as TLSCertificateName"
            if ($PSCmdLet.ParameterSetName -eq 'FqdnNoTls') {
                $param.TlsSenderCertificateName = $SEPPmailFQDN
            }

            Write-Verbose "Creating SEPPmail Inbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($($param.Name), 'Creating Inbound Connector'))
            {
                Write-Debug "Inbound Connector settings:"
                $param.GetEnumerator() | Foreach-Object {
                    Write-Debug "$($_.Key) = $($_.Value)"
                }
                $Now = Get-Date
                $param.Comment += "`n#Created with SEPPmail365 PowerShell Module on $now"
                [void](New-InboundConnector @param)

                if(!$?) {
                    throw $error[0]
                } else {
                    #region - Add SMFQDN to hosted Connection Filter Policy Whitelist
                    if ($option[0] -ne 'NoAntiSpamWhiteListing')
                    {
                        Write-Verbose "Adding SEPPmail Appliance to wWhitelist in 'Hosted Connection Filter Policy'"
                        Write-Verbose "Collecting existing WhiteList"
                        $hcfp = Get-HostedConnectionFilterPolicy
                        [string[]]$existingAllowList = $hcfp.IPAllowList
                        Write-verbose "Adding SEPPmail Appliance to Policy $($hcfp.Id)"
                        if ($existingAllowList) {
                            $FinalIPList = ($existingAllowList + $SEPPmailIP)|sort-object -Unique
                        }
                        else {
                            $FinalIPList = $SEPPmailIP
                        }
                        Write-verbose "Adding IPaddress list with content $finalIPList to Policy $($hcfp.Id)"
                        if ($FinalIPList) {
                            Set-HostedConnectionFilterPolicy -Identity $hcfp.Id -IPAllowList $finalIPList
                        }
                    }
                    #endRegion - Hosted Connection Filter Policy WhiteList
                }
            }
        }
        #endRegion InboundConnector

        #region OutboundConnector
        $outbound = Get-SM365OutboundConnectorSettings -Version 'Default' -Option $Option
        $param = $outbound.ToHashtable()
        if ($PsCmdLet.ParameterSetname -like 'fqdn*') {
            $param.SmartHosts = $SEPPmailFQDN            
        } else {
            $param.SmartHosts = $SenderIPAddresses                  
        }
        Write-Verbose "Set Tls outbound domain depending in ParameterSetName $PsCmdLet.ParameterSetName"
        if ($PsCmdLet.ParameterSetName -eq 'FqdnTls') {
            $param.TlsDomain = $OutboundTlsDomain
            if ($AllowSelfSignedCertificates) {
                $param.TlsSettings = 'EncryptionOnly'
                $param.Remove('TlsDomain')
            }
        }

        if ($PsCmdLet.ParameterSetName -ne 'FqdnTls') {
            $param.TlsSettings = $null
        }

        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($Disabled) {
            $param.Enabled = $false
        }

        Write-Verbose "Read existing SEPPmail outbound connector"
        $existingSMOutboundConn = $allOutboundConnectors | Where-Object Name -EQ $outbound.Name
        # only $false if the user says so interactively
        
        [bool]$createOutBound = $true #Set Default Value
        if ($existingSMOutboundConn)
        {
            Write-Warning "Found existing SEPPmail outbound connector with name: `"$($existingSMOutboundConn.Name)`" created on `"$($existingSMOutboundConn.WhenCreated)`" pointing to SEPPmail `"$($existingSMOutboundConn.TlsDomain)`" "

            if($InteractiveSession)
            {
                [string] $tmp = $null

                Do {
                    try {
                        [ValidateSet('y', 'Y', 'n', 'N')]$tmp = Read-Host -Prompt "Shall we delete and recreate the outbound connector (will only work if no rules use it)? (Y/N)"
                        break
                    }
                    catch {}
                }
                until ($?)

                if ($tmp -eq 'y') {
                    $createOutbound = $true

                    Write-Verbose "Removing existing Outbound Connector $($existingSMOutboundConn.Name) !"
                    if ($PSCmdLet.ShouldProcess($($existingSMOutboundConn.Name), 'Removing existing SEPPmail Outbound Connector')) {
                        $existingSMOutboundConn | Remove-OutboundConnector -Confirm:$false # user already confirmed action

                        if (!$?)
                        { throw $error[0] }
                    }
                }
                else {
                    Write-Warning "Leaving existing SEPPmail outbound connector `"$($existingSMOutboundConn.Name)`" untouched."
                    $createOutbound = $false
                }
            }
            else
            {
                throw [System.Exception] "Outbound connector $($outbound.Name) already exists"
            }
        }
        else
        {Write-Verbose "No existing Outbound Connector found"}

        if($createOutbound)
        {
            Write-Verbose "Creating SEPPmail Outbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($($param.Name), 'Creating Outbound Connector'))
            {
                Write-Debug "Outbound Connector settings:"
                $param.GetEnumerator() | ForEach-Object{
                    Write-Debug "$($_.Key) = $($_.Value)"
                }

                $Now = Get-Date
                $param.Comment += "`n#Created with SEPPmail365 PowerShell Module on $now"

                if ($TLSCertificateName.Length -gt 0) {
                    $param.TlsDomain = $TLSCertificateName
                }

                [void](New-OutboundConnector @param)

                if(!$?)
                {throw $error[0]}
            }
        }
        #endregion OutboundConnector
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
    Remove-SM365Connectors
#>
function Remove-SM365Connectors
{
    [CmdletBinding(SupportsShouldProcess=$true,
                   ConfirmImpact='Medium')]
    Param
    (
    [Switch]$leaveAntiSpamWhiteList
    )

    if (!(Test-SM365ConnectionStatus))
    { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

    Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

    $inbound = Get-SM365InboundConnectorSettings -Version "None"
    $outbound = Get-SM365OutboundConnectorSettings -Version "None"
    $hcfp = Get-HostedConnectionFilterPolicy

    if($PSCmdlet.ShouldProcess($outbound.Name, "Remove SEPPmail outbound connector $($Outbound.Name)"))
    {
        if (Get-OutboundConnector | Where-Object Identity -eq $($outbound.Name))
        {
            Remove-OutboundConnector $outbound.Name
        }
        else {
            Write-Warning 'No SEPPmail Outbound Connector found'
        }
    }

    if($PSCmdlet.ShouldProcess($inbound.Name, "Remove SEPPmail inbound connector $($inbound.Name)"))
    {
        $InboundConnector = Get-InboundConnector | Where-Object Identity -eq $($inbound.Name)
        if ($inboundConnector)
            {
            Write-Verbose 'Collect Inbound Connector IP for later Whitelistremoval'
            
            [string]$InboundSEPPmailIP = $null
            if ($inboundConnector.SenderIPAddresses.count -le 1) {
                $InboundSEPPmailIP = $InboundConnector.SenderIPAddresses[0]
            } 
            if ($inboundConnector.TlsSenderCertificateName) {
                $InboundSEPPmailIP = ([System.Net.Dns]::GetHostAddresses($($inboundConnector.TlsSenderCertificateName)).IPAddressToString)
            }
            Remove-InboundConnector $inbound.Name

            Write-Verbose "If Inbound Connector has been removed, remove also Whitelisted IPs"
            if ((!($leaveAntiSpamWhiteList)) -and (!(Get-InboundConnector | Where-Object Identity -eq $($inbound.Name))))
            {
                    Write-Verbose "Remove SEPPmail Appliance IP from Whitelist in 'Hosted Connection Filter Policy'"
                    
                    Write-Verbose "Collecting existing WhiteList"
                    [System.Collections.ArrayList]$existingAllowList = $hcfp.IPAllowList
                    Write-verbose "Removing SEPPmail Appliance IP $InboundSEPPmailIP from Policy $($hcfp.Id)"
                    if ($existingAllowList) {
                        $existingAllowList.Remove($InboundSEPPmailIP)
                        Set-HostedConnectionFilterPolicy -Identity $hcfp.Id -IPAllowList $existingAllowList
                        Write-Information "IP: $InboundSEPPmailIP removed from Hosted Connection Filter Policy $hcfp.Id"
                }
            }
        }
        else 
        {
            Write-Warning 'No SEPPmail Inbound Connector found'
        }
    }
}

<#
.SYNOPSIS
    Backs up all existing connectors to individual json files
.DESCRIPTION
    Convenience function to perform a backup of all existing connectors
.EXAMPLE
    Backup-SM365Connectors -OutFolder "C:\temp"
#>
function Backup-SM365Connectors
{
    [CmdletBinding()]
    param
    (
        [Parameter(
             Mandatory = $true,
             HelpMessage = 'Folder in which the backed up configuration will be stored'
         )]
        [Alias('Folder','Path')]
        [String] $OutFolder
    )

    begin
    {
        if (!(Test-SM365ConnectionStatus))
        { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue
    }

    process
    {
        if(!(Test-Path $OutFolder))
        {New-Item $OutFolder -ItemType Directory}

        Get-InboundConnector | foreach-object{
            $n = $_.Name
            $n = $n -replace "[\[\]*\\/?:><`"]"

            $p = "$OutFolder\inbound_connector_$n.json"

            Write-Verbose "Backing up $($_.Name) to $p"
            ConvertTo-Json -InputObject $_ | Out-File $p
        }

        Get-OutboundConnector | foreach-object {
            $n = $_.Name
            $n = $n -replace "[\[\]*\\/?:><`"]"

            $p = "$OutFolder\outbound_connector_$n.json"
            Write-Verbose "Backing up $($_.Name) to $p"
            ConvertTo-Json -InputObject $_ | Out-File $p
        }
    }
}

if (!(Get-Alias 'Set-SM365Connectors' -ErrorAction SilentlyContinue)) {
    New-Alias -Name Set-SM365Connectors -Value New-SM365Connectors
}

# SIG # Begin signature block
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUej60TaHRJTBbH5TtYGgqnzXw
# HdaggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
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
# MRYEFDkDtJ9vng7jXYeXKbHVwiJQKzkpMA0GCSqGSIb3DQEBAQUABIIBAAekxgCc
# hb8oNQlFbGUTbwRFGIlnMyg2RZIvp4t/ai+fPW0qAIDgXWUr/1RM+zkdc3RZHDMP
# ZcOPOAuY05fmg+v4EZVtNklnWxBRVJ4VoXMK9t4qufiJu0E/2bmNZcE2yfI9OFva
# lXTBxdpu/P7XrB7N2Y9YiwGcySHCEk9Ch+4VDvKWfdBIYS5fEoTRzITFS9Bb7bpZ
# k9sGVGE7BRKG7PLmkpd9nbHiFKJlLpBhVdddULKzrGYDrXB0b4RWr5eBFR+jOTSv
# DIwQ5ftM9xBkshPsawdgC+CUDui8tF5Hr+TAs3slEQzISipRV1zlBED605EcK6L+
# X8RZKChiOXz4ZdQ=
# SIG # End signature block
