$ModuleVersion = $myInvocation.MyCommand.Version

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

        $inbound = Get-SM365InboundConnectorSettings
        $outbound = Get-SM365OutboundConnectorSettings
    
        if (Get-OutboundConnector -outvariable obc | Where-Object Identity -eq $($outbound.Name))
        {
            $obc|select-object Name,Enabled,WhenCreated,SmartHosts
        }
        else {
            Write-Warning "No SEPPmail Outbound Connector with name `"$($outbound.Name)`" found"
        }
        if (Get-InboundConnector -outvariable ibc | Where-Object Identity -eq $($inbound.Name))
        {
            $ibc|select-object Name,Enabled,WhenCreated,TlsSenderCertificateName
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
    This cmdlet will create the two connectors for you.

    The -SEPPmailFQDN must point to a SEPPmail Appliance with a valid certificate to establish the TLS connection.
    To use a wildcard certificate, use the -TLSCertName parameter.

.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com' -TLSCertName '*.contoso.com'
    Takes the Exchange Online environment settings and creates Inbound and Outbound connectors to a SEPPmail Appliance with a wildcard TLS certificate
.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com'
    Takes the Exchange Online environment settings and creates Inbound and Outbound connectors to a SEPPmail Appliance.
    Assumes that the TLS certificate is identical with the SEPPmail FQDN
.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com' -CBCCertName 'inbound.contoso.com'
    For MSP Setups with Certificate Based Connectors (CBC) we need different certificates for inbound and outbound connectors.
    Takes the Exchange Online environment settings and creates Inbound and Outbound connectors to a SEPPmail Appliance.
    Uses the FQDN as certificate name for the outbound connector and takes the -CBCCertName as the certificate name for the inbound connector
    See the SEPPmail online manual for details on how to setup ARC/CBC here https://docs.seppmail.com/de/09_ht_mso365_ssl_certificate.html?q=CBC
.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com' -AllowSelfSignedCertificates
    Same as above, just no officially trusted certificate needed.
.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -NoOutBoundTlsCheck
    Same as the default config, just with no TLS encryption at all.
.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -Disabled
    Use this option if you want to create the connectors, but just disable them on creation, use the -Disabled switch.
.EXAMPLE
    New-SM365Connectors -SEPPmailIp '51.144.46.62'
    Use this if your SEPPmail is just accessible via an IP Address, use the -SEPPmailIP parameter.
.EXAMPLE 
    New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -NoAntiSpamWhiteListing
    To avoid adding the SEPPmail appliance to the ANTI-SPAM WhiteList of Microsoft Defender, use the -NoAntiSpamWhiteListing switch.
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
        #endregion FqdnTls

        #region TLSSenderCertificateName
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Name of the certificate if different from the SEPPmail-FQDN. Read the cetificate name in your SEPPmail under SSL==>Issued to==>Name (CN)',
            ParameterSetname = 'FqdnTls',
            Position = 1
        )]
        [Alias('TLSCertName','CertName')]
        [String] $TLSCertificateName,
        #endregion TLSSenderCertificateName

        #region SelfSigned
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

        #region NoAntiSpamWhiteListing
        [Parameter(
            HelpMessage = 'Do not Add SEPPmailIP to the HostedConnectionFilterPolicy',
            ParameterSetName = 'FqdnTls'
        )]
        [Parameter(
            HelpMessage = 'Do not Add SEPPmailIP to the HostedConnectionFilterPolicy',
            ParameterSetName = 'FqdnNoTls'
        )]
        [Parameter(
            HelpMessage = 'Do not Add SEPPmailIP to the HostedConnectionFilterPolicy',
            ParameterSetName = 'Ip'
        )]
        [switch]$NoAntiSpamWhiteListing,
        #endRegion

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
        [switch]$Disabled,
        #endregion disabled

        #region MSP-CBC
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'MSP setup requires a second certificate',
            ParameterSetName = 'FqdnTls',
            Position = 2
        )]
        [string]$CBCcertName
        #endregion
    )

    begin
    {
        if(!(Test-SM365ConnectionStatus))
        {throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet"}
        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        #Resolve IP
        if ($PSCmdLet.ParameterSetName -like 'Fqdn*') {
            try {
                Write-Verbose "Transform $SEPPmailFQDN to IP Address for IP based options"
                $SEPPmailIP = ([System.Net.Dns]::GetHostAddresses($SEPPmailFQDN).IPAddressToString)
                Write-Verbose "$SEPPmailFQDN equals the IP(s): $SEPPmailIP"
            }
            catch {
                Write-Error "Could not resolve IP Address of $SEPPmailFQDN. Please check SEPPmailFQDN hostname and try again."
                break
            }
        }

        #region collecting existing connectors
        Write-Verbose "Collecting existing connectors"
        $allInboundConnectors = Get-InboundConnector
        $allOutboundConnectors = Get-OutboundConnector

        Write-Verbose "Testing for hybrid Setup"
        $HybridInboundConn = $allInboundConnectors |Where-Object {(($_.Name -clike 'Inbound from *') -or ($_.ConnectorSource -clike 'HybridWizard'))}
        $HybridOutBoundConn = $allOutboundConnectors |Where-Object {(($_.Name -clike 'Outbound to *') -or ($_.ConnectorSource -clike 'HybridWizard'))}
        #endregion collecting existing connectors

        #region warn on hybrid
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
        #endregion warn on hybrid
    }

    process
    {
        #region - Check existing Outbound Connector
        Write-Verbose "Read existing SEPPmail outbound connector"
        $existingSMOutboundConn = $allOutboundConnectors | Where-Object Name -like '`[SEPPmail`]*'
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
        #endregion - Check existing Outbound Connector

        #region - Create Outbound Connector
        $outboundParam = Get-SM365OutboundConnectorSettings
        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($Disabled) {
            $outboundParam.Enabled = $false
        }

        switch ($PSCmdLet.ParameterSetName) {
            'Ip' {
                Write-Verbose "IP based Config, using $SenderIPAddresses"
                [string[]]$SenderIPAddresses = $SEPPmailIP
                $outboundParam.SenderIPAddresses = $SenderIPAddresses
                $outboundParam.TlsSettings = $null
            }
            'FqdnNoTls' {
                Write-Verbose "NoTls, using $SEPPmailFQDN as SmartHost"
                $outboundParam.TlsSettings = $null
                $outboundParam.SmartHosts = $SEPPmailFQDN
                if ($TLSCertificateName.Length -gt 0) {
                    $outboundParam.TlsDomain = $TLSCertificateName
                }

            }
            'FqdnTls' {
                Write-Verbose "FQDN and TLS, using $SEPPmailFQDN as SmartHost"
                $outboundParam.TlsDomain = $SEPPmailFQDN
                if ($TLSCertificateName.Length -gt 0) {
                    $outboundParam.TlsDomain = $TLSCertificateName
                } elseif ($NoOutBoundTlsCheck) {
                    Write-Verbose "No TLS required for outbound connector"
                    $outboundParam.TlsSettings = $null
                } elseif ($AllowSelfSignedCertificates) {
                    $outboundParam.TlsSettings = 'EncryptionOnly'
                    $outboundParam.Remove('TlsDomain')
                } else {
                    $outboundParam.TlsSettings = 'DomainValidation'
                }
            }
        }

        if($createOutbound)
        {
            Write-Verbose "Creating SEPPmail Outbound Connector $($outboundParam.Name)!"
            if ($PSCmdLet.ShouldProcess($($outboundParam.Name), 'Creating Outbound Connector'))
            {
                Write-Verbose "Adding creation comment to outbound connector"
                $Now = Get-Date
                $outboundParam.Comment += "`n#Created with SEPPmail365 PowerShell Module version $ModuleVersion on $now"

                Write-Debug "Outbound Connector settings:"
                $outboundParam.GetEnumerator() | ForEach-Object{
                    Write-Debug "$($_.Key) = $($_.Value)"
                }

                #[void](New-OutboundConnector $outboundParam)

                if(!$?)
                {throw $error[0]}
            }
        }
        #endregion - Create Outbound Connector

        #region - Check existing inbound connector
        Write-Verbose "Read existing SEPPmail Inbound Connector from Exchange Online"
        $existingSMInboundConn = $allInboundConnectors | Where-Object Name -like '`[SEPPmail`]*'

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
                throw [System.Exception] "Inbound connector $($inboundParam.Name) already exists"
            }
        }
        else
        {Write-Verbose "No existing Inbound Connector found"}
        #endregion - Check existing inbound connector

        #region - Create Inbound Connector
        Write-Verbose "Read Inbound Connector Settings"
        $inboundParam = Get-SM365InboundConnectorSettings
        
        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($disabled) {
            $inboundParam.Enabled = $false
        }

        # Due to ARC Setup of Exo tenants and EFSkipLastIP is $true by default, EFSKipIP´s must be empty in certain setups.
        #TODO: Check mit Sebastian wann der leer sein muss
        if ($PsCmdLet.ParameterSetName -ne 'FqdnTls') {
            Write-Verbose "Setting SEPPmail IP Address(es) $SEPPmailIP for EFSkipIP´s and Anti-SPAM Whitelist"
            
            # Remove all IPv6 addresses
            [string[]]$SEPPmailIpRange = Remove-IPv6Address -IPArray $SEPPmailIP
            $inboundParam.EFSkipIPs = $SEPPmailIpRange
        } else {
            $inboundParam.Remove('EFSkipIPs')
        }

        if($createInbound)
        {
            Write-Verbose "Modify params based on ParameterSet"

            # Configure inbound connector parameters based on parameter set
            switch ($PSCmdLet.ParameterSetName) {
                'Ip' {
                    Write-Verbose "IP based Config, using $SenderIPAddresses"
                    [string[]]$SenderIPAddresses = $SEPPmailIP
                    $inboundParam.SenderIPAddresses = $SenderIPAddresses
                    $inboundParam.RequireTls = $false
                    $inboundParam.EFSkipLastIP = $false
                }
                'FqdnTls' {
                    # Handle self-signed certificates
                    if ($AllowSelfSignedCertificates) {
                        Write-Verbose "FQDN and Self Signed certificates, TLSCertificateName = $SEPPmailFQDN"
                        $inboundParam.RestrictDomainsToCertificate = $false
                        $inboundParam.TlsSenderCertificateName = $SEPPmailFQDN
                    }
                    # Handle CBC certificate name (MSP setup)
                    elseif ($CBCcertName) {
                        Write-Verbose "FQDN and CBC CertificateName, using $CBCcertName as TLSCertificateName"
                        $inboundParam.TlsSenderCertificateName = $CBCcertName
                    }
                    # Handle custom TLS certificate name
                    elseif ($TLSCertificateName.Length -gt 0) {
                        Write-Verbose "FQDN and CertificateName specified, using $TLSCertificateName as TLSCertificateName"
                        $inboundParam.TlsSenderCertificateName = $TLSCertificateName
                    }
                    # Default case: use FQDN as certificate name
                    else {
                        Write-Verbose "FQDN and CertificateName equals FQDN, using $SEPPmailFQDN as TLSCertificateName"
                        $inboundParam.TlsSenderCertificateName = $SEPPmailFQDN
                    }
                }
                'FqdnNoTls' {
                    Write-Verbose "NoTls, using $SEPPmailFQDN as TLSCertificateName"
                    $inboundParam.TlsSenderCertificateName = $SEPPmailFQDN
                }
            }

            Write-Verbose "Creating SEPPmail Inbound Connector $($inboundParam.Name)!"
            if ($PSCmdLet.ShouldProcess($($inboundParam.Name), 'Creating Inbound Connector'))
            {
                Write-Verbose "Adding creation comment to inbound connector"
                $Now = Get-Date
                $ModuleVersion = $myInvocation.MyCommand.Version
                $inboundParam.Comment += "`n#Created with SEPPmail365 PowerShell Module version $ModuleVersion on $now"

                Write-Debug "Inbound Connector settings:"
                $inboundParam.GetEnumerator() | Foreach-Object {
                    Write-Debug "$($_.Key) = $($_.Value)"
                }
                #[void](New-InboundConnector @inboundParam)

                if(!$?) {
                    throw $error[0]
                } else {
                    #region - Add SMFQDN to hosted Connection Filter Policy Whitelist
                    if ($NoAntiSpamWhiteListing -eq $true)
                    {
                        Write-Verbose "Adding SEPPmail Appliance to allowlist in 'Hosted Connection Filter Policy'"
                        Write-Verbose "Collecting existing WhiteList"
                        $hcfp = Get-HostedConnectionFilterPolicy
                        [string[]]$existingAllowList = $hcfp.IPAllowList
                        Write-verbose "Adding SEPPmail Appliance to Policy $($hcfp.Id)"
                        if ($existingAllowList) {
                            $FinalIPList = ($existingAllowList + $SEPPmailIP)|sort-object -Unique
                        }
                        else {
                            $FinalIPList = Remove-IPv6Address -IPArray $SEPPmailIP
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
        #endRegion - Create InboundConnector
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
.EXAMPLE
    Remove-SM365Connectors -leaveAntiSpamWhiteList
    Removes the connectors but leaves the IP Adress of the SEPPmail appliance in the ansiSpam Allowlist.
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

    $inbound = Get-SM365InboundConnectorSettings
    $outbound = Get-SM365OutboundConnectorSettings
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
                try {
                    $InboundSEPPmailIP = ([System.Net.Dns]::GetHostAddresses($($inboundConnector.TlsSenderCertificateName)).IPAddressToString)
                }
                catch {
                    $InboundSEPPmailIP = $null
                }
            }
            Remove-InboundConnector $inbound.Name

            Write-Verbose "If Inbound Connector has been removed, remove also Whitelisted IPs"
            if ((!($leaveAntiSpamWhiteList)) -and (!(Get-InboundConnector | Where-Object Identity -eq $($inbound.Name))) -and ($InboundSEPPmailIP))
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


if (!(Get-Alias 'Set-SM365Connectors' -ErrorAction SilentlyContinue)) {
    New-Alias -Name Set-SM365Connectors -Value New-SM365Connectors
}

# SIG # Begin signature block
# MIIVzAYJKoZIhvcNAQcCoIIVvTCCFbkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDmuRyqEzE7D6Ku
# FthtnQzQ9ZXB5sJU1PQJJkhVzWO07KCCEggwggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCB/FAr3ZViOr74a8jAWaPuI+gn
# dt/mFZ3Viaqka8kiMzANBgkqhkiG9w0BAQEFAASCAgB0NMhqB4Wh87Woal8bpJy/
# 6XHS4siHyT6JzWmDqtg1wilTTPGhasWCcJhUz8LFZIJKEW3VCiTKK4VpEgqQDMsx
# PJKvcWvF7M0+g8LDAzo/5/PTljoUz8vGpSs8jRdrYB6CfmUZdybCCDi1Yim3Mfyl
# xSnoxuH0S5CpHcT8I7PHAPtPyIfIFMLlTTNzQq1TbIOHOtPqjV+vGbFtvcdZRdY9
# Be4Rly9YnKPuOt5Zd3qcE9VOjdmQ9cXsTNWzE5rawPyHjbszlvXlx9nD6XBFcglk
# fujHAHPr3AUaIWIIBa1Fq42qVuFIBXzH5ELuTuy/18w3i+Q8RoAeL0g7evpYJNVO
# /RG9RbfL9jQYuTFu/Fe2Yj9Ydri4oAi3e7Gs+kdxW6e6O6kk9MVB/o1i1dck5m6D
# cNSA2MSlZigLRxYJgazijkcFlNuAmf1DbB0M9Gd84ktSK+o0vksCo4wWVW7FJmo9
# hMboEAHdo5lWGpQ/XQKnUf+/aLG/OL+JdbMjLHjt05tHShAL6TvlsQHQwd0W3bjO
# wE0N5nTxIWr8e6Slcsg2hctls6buYOZKei7CqJ3j1uXM31YCeTkVTxcxuTNqAT6A
# v09uquzPv3BRGUvkYbYLEW3bpECKC3r0lN89/x+tlTDrzeMUmbzZmgSCXYIuZkWx
# eEWJhF+nclJB1i0rKpjJ0Q==
# SIG # End signature block
