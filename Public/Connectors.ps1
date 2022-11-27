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
        [switch]$NoAntiSpamWhiteListing = $false,
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
        #region OutboundConnector
        $param = Get-SM365OutboundConnectorSettings
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
                $param.Comment += "`n#Created with SEPPmail365 PowerShell Module version $ModuleVersion on $now"

                if ($TLSCertificateName.Length -gt 0) {
                    $param.TlsDomain = $TLSCertificateName
                }

                [void](New-OutboundConnector @param)

                if(!$?)
                {throw $error[0]}
            }
        }
        #endregion OutboundConnector

        #region - Inbound Connector
        Write-Verbose "Read Inbound Connector Settings"
        $inbound = Get-SM365InboundConnectorSettings
        
        if ($PSCmdLet.ParametersetName -eq 'FqdnTls') {
            $inbound.TlsSenderCertificateName = $InboundTlsDomain
        }
        
        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($disabled) {
            $inbound.Enabled = $false
        }

        Write-Verbose "Setting SEPPmail IP Address(es) $SEPPmailIP for EFSkipIP´s and Anti-SPAM Whitelist"
        [string[]]$SEPPmailIpRange = $SEPPmailIP
        $inbound.EFSkipIPs = $SEPPmailIpRange

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
                throw [System.Exception] "Inbound connector $($inbound.Name) already exists"
            }
        }
        else
        {Write-Verbose "No existing Inbound Connector found"}

        if($createInbound)
        {
            # necessary assignment for splatting
            $param = $inbound

            Write-Verbose "Modify params based on ParameterSet"
            Write-Verbose "IP based Config, using $SenderIPAdresses"
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
                $ModuleVersion = $myInvocation.MyCommand.Version
                $param.Comment += "`n#Created with SEPPmail365 PowerShell Module version $ModuleVersion on $now"
                [void](New-InboundConnector @param)

                if(!$?) {
                    throw $error[0]
                } else {
                    #region - Add SMFQDN to hosted Connection Filter Policy Whitelist
                    if ($NoAntiSpamWhiteListing -eq $true)
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
# MIIL/AYJKoZIhvcNAQcCoIIL7TCCC+kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIa92deUOW3Z+N
# tsyoWt09Vu+2PKukCWkx2ysYg6Sfd6CCCUAwggSZMIIDgaADAgECAhBxoLc2ld2x
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
# BgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBJzagrv4PAC9aHSH8X+ZnyoN2z
# 0WTbZV19b7LJTgyceDANBgkqhkiG9w0BAQEFAASCAQCLyGpGtiqIEDFLpJU94dXz
# WJJjJcBJS/oLKcb5KJecA5vzvtiiUFqy0LnpqW2JJ8OexVxyIEUi6rwVUji32NiY
# EPDt7s9usLAYSnEB1/CJTzwuK4UGZ+TzoGxtXPxz82wVc/CG5yfELf1NXGR99eBk
# ux72vHJlp+Wf1Gd3+PgkMFokiygzBHneiuFXxZW3W3bDsV8jEi2rBPtZPbvGN4ks
# CYCFDpyYzqAVI/O0VZtxASE8C80538LfxvjKIC9+fH22NAIUPlmYmCQ/UzmhdcO/
# Hl3rbEcr0bn59mx+2dEuMq7/i4+bpAP1nGM/nG5JTg2SulWrNflX0gNkmTECA94Q
# SIG # End signature block
