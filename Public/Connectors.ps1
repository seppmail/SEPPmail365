﻿
<#
.SYNOPSIS
    Adds SEPPmail Exchange Online connectors
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online
    This commandlet will create the connectors for you.

    The -SEPPmailFQDN must point to a SEPPmail Appliance with a valid certificate to establish the TLS connection.
    The parameter -TlsDomain is required, if the SEPPmailFQDN differs from the one in the SSL certificate.

.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com'
#>
function New-SM365Connectors
{
    [CmdletBinding(
         SupportsShouldProcess = $true,
         ConfirmImpact = 'Medium',
         DefaultParameterSet = 'FQDN'
     )]

    param
    (
        #region FQDN
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'FQDN of the SEPPmail Appliance',
            ParameterSetName = 'FQDN',
            Position = 0
        )]
        [Parameter(
           Mandatory = $true,
           HelpMessage = 'FQDN of the SEPPmail Appliance',
           ParameterSetName = 'CommonTlsDomain',
           Position = 0
        )]
        [Parameter(
             Mandatory = $true,
             HelpMessage = 'FQDN of the SEPPmail Appliance',
             ParameterSetName = 'DualTlsDomain',
             Position = 0
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("FQDN")]
        [String] $SEPPmailFQDN,
        #endregion FQDN

        #region CommonTls
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'If different from SEPPmailFQDN, subject of the SEPPmail SSL certificate (used for both in- and outbound connectors)',
            ParameterSetName = 'FQDN',
            Position = 1
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'If different from SEPPmailFQDN, subject of the SEPPmail SSL certificate (used for both in- and outbound connectors)',
            ParameterSetName = 'CommonTls',
            Position = 1
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("Tls")]
        [string] $TlsDomain,
        #endregion CommonTls

        #region DualTls
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'If different from SEPPmailFQDN/TLSDomain, subject of the SEPPmail SSL certificate for the inbound connector',
            ParameterSetName = 'DualTls',
            Position = 1
            )]
         [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
         [string] $InboundTlsDomain,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'If different from SEPPmailFQDN/TLSDomain, subject of the SEPPmail SSL certificate for the outbound connector',
            ParameterSetName = 'DualTls',
            Position = 1
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [string] $OutboundTlsDomain,
        #endregion DualTls

        #region Version
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Which configuration version to use',
            ParameterSetname = 'FQDN',
            Position = 2
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Which configuration version to use',
            ParameterSetname = 'CommonTls',
            Position = 2
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Which configuration version to use',
            ParameterSetname = 'DualTls',
            Position = 2
         )]
       [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Latest,
        #endregion Version

        #region Option
        [Parameter(
            Mandatory=$false,
            HelpMessage='Additional config options to activate',
            ParameterSetname = 'FQDN',
            Position = 3
        )]
        [Parameter(
            Mandatory=$false,
            HelpMessage='Additional config options to activate',
            ParameterSetname = 'CommonTls',
            Position = 3
        )]
        [Parameter(
            Mandatory=$false,
            HelpMessage='Additional config options to activate',
            ParameterSetname = 'DualTls',
            Position = 3
        )]
        [SM365.ConfigOption[]] $Option,
        #endregion Option

        #region Disabled
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Should the connectors be created active or inactive',
            ParameterSetName = 'FQDN',
            Position = 4
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Should the connectors be created active or inactive',
            ParameterSetName = 'CommonTls',
            Position = 4
        )]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Should the connectors be created active or inactive',
            ParameterSetName = 'DualTls',
            Position = 4
        )]
        [switch]$Disabled
        #endregion Disabled
    )

    begin
    {
        if(!(Test-SM365ConnectionStatus))
        {throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet"}

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        # Getting SEPPmail IP Address(es) for Anti-SPAM Whitelist and other steps of the connector command
        Write-Verbose "Resolving $SEPPmailFQDN to IP Addresses"
        [string[]]$smFqdnIps = [System.Net.Dns]::GetHostAddresses($SEPPmailFQDN).IPAddressToString

        Write-Verbose "Provide defaults for TlsDomains, if not specified"
        if(!$TlsDomain)
        {$TlsDomain = $SEPPmailFQDN}

        if(!$InboundTlsDomain)
        {$InboundTlsDomain = $TlsDomain}

        if(!$OutboundTlsDomain)
        {$OutboundTlsDomain = $TlsDomain}

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
    }

    process
    {
        #Region - Add SMFQDN to hosted Connection Filter Policy Whitelist
        if ($version -eq 'Oct21')
        {
            Write-Verbose "Trying to add SEPPmail Appliance to Whitelist in 'Hosted Connection Filter Policy'"
            Write-Verbose "Collecting existing WhiteList"
            $hcfp = Get-HostedConnectionFilterPolicy
            [string[]]$existingAllowList = $hcfp.IPAllowList
            Write-verbose "Adding SEPPmail Appliance to Policy $($hcfp.Id)"
            if ($existingAllowList) {
                    $FinalIPList = ($existingAllowList + $IPs)|sort-object -Unique
            }
            else {
                $FinalIPList = $IPs
            }
            Write-verbose "Adding IPaddress list with content $finalIPList to Policy $($hcfp.Id)"
            if ($FinalIPList) {
                Set-HostedConnectionFilterPolicy -Identity $hcfp.Id -IPAllowList $finalIPList
            }
        }
        #endRegion - Hosted Connection Filter Policy WhiteList

        #region - Inbound Connector
        $inbound = Get-SM365InboundConnectorSettings -Version $Version Option $Option
        $inbound.TlsSenderCertificateName = $InboundTlsDomain
        
        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($disabled) {
            $inbound.Enabled = $false
        }

        Write-Verbose "Setting SEPPmail IP Address(es) $smFqdnIps for EFSkipIP´s and Anti-SPAM Whitelist"
        $inbound.EFSkipIPs.AddRange($smFqdnIps)

        Write-Verbose "Read existing SEPPmail Inbound Connector"
        $existingSMInboundConn = $allInboundConnectors | Where-Object Name -EQ $inbound.Name

        # only $false if the user says so interactively
        [bool] $createInbound = $true

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

            Write-Verbose "Creating SEPPmail Inbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($($param.Name), 'Creating Inbound Connector'))
            {
                Write-Debug "Inbound Connector settings:"
                $param.GetEnumerator() | Foreach-Object {
                    Write-Debug "$($_.Key) = $($_.Value)"
                }
                New-InboundConnector @param | Out-Null

                if(!$?)
                {throw $error[0]}
            }
        }
        #endRegion InboundConnector

        #region OutboundConnector
        $outbound = Get-SM365OutboundConnectorSettings -Version $Version Option $Option
        $outbound.SmartHosts = $SEPPmailFQDN
        $outbound.TlsDomain = $OutboundTlsDomain
        
        Write-verbose "if -disabled switch is used, the connector stays deactivated"
        if ($Disabled) {
            $outbound.Enabled = $false
        }

        Write-Verbose "Read existing SEPPmail outbound connector"
        $existingSMOutboundConn = $allOutboundConnectors | Where-Object Name -EQ $outbound.Name
        # only $false if the user says so interactively
        
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
            # necessary assignment for splatting
            $param = $outbound.ToHashtable()

            Write-Verbose "Creating SEPPmail Outbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($($param.Name), 'Creating Outbound Connector'))
            {
                Write-Debug "Outbound Connector settings:"
                $param.GetEnumerator() | ForEach-Object{
                    Write-Debug "$($_.Key) = $($_.Value)"
                }

                New-OutboundConnector @param | Out-Null

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
    Updates existing SEPPmail Exchange Online connectors
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online
    This commandlet will update the connectors for you.

    The -SEPPmailFQDN must point to a SEPPmail Appliance with a valid certificate to establish the TLS connection.
    The parameter -TlsDomain is required, if the SEPPmailFQDN differs from the one in the SSL certificate.

.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.consoso.com'
#>
function Set-SM365Connectors
{
    [CmdletBinding(
         SupportsShouldProcess = $true,
         ConfirmImpact = 'Medium'
     )]
    param
    (
        [Parameter(
             Mandatory = $false,
             HelpMessage = 'FQDN of the SEPPmail Appliance'
         )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("FQDN")]
        [String] $SEPPmailFQDN,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'IP addresses or ranges of the SEPPmail appliances'
        )]
        [string[]] $TrustedIPs,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Internal Mail Domains, the connectors allow sending for'
        )]
        [string[]] $SenderDomains,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'External Mail Domains, the connectors allow sending to'
         )]
        [string[]] $RecipientDomains,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'The subject of the SEPPmail SSL certificate (used for both in- and outbound connectors)'
        )]
        [string] $TlsDomain,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'The subject of the SEPPmail SSL certificate for the inbound connector'
         )]
        [string] $InboundTlsDomain,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'The subject of the SEPPmail SSL certificate for the outbound connector'
        )]
        [string] $OutboundTlsDomain,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'Also sets all other connector settings to the SEPPmail default'
         )]
        [switch] $SetDefaults,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'Which configuration version to use'
         )]
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Latest,

        [Parameter(
             Mandatory=$false,
             HelpMessage='Additional config options to activate'
         )]
        [SM365.ConfigOption[]] $Option,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Should the connectors be set to active or inactive'
        )]
        [switch] $Enabled = $true
    )

    begin
    {
        if (!(Test-SM365ConnectionStatus))
        { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        # provide defaults for parameters, if not specified
        if(!$TlsDomain)
        {$TlsDomain = $SEPPmailFQDN}

        if(!$InboundTlsDomain)
        {$InboundTlsDomain = $TlsDomain}

        if(!$OutboundTlsDomain)
        {$OutboundTlsDomain = $TlsDomain}
    }

    process
    {
        [SM365.InboundConnectorSettings] $inbound = $null
        [SM365.OutboundConnectorSettings] $outbound = $null

        if($SetDefaults)
        {
            if($Version -eq "None")
            {throw [System.Exception] "-SetDefaults but no -Version specified - this won't work!"}

            $inbound = Get-SM365InboundConnectorSettings -Version $Version -Option $Option
            $outbound = Get-SM365OutboundConnectorSettings -Version $Version -Option $Option
        }
        # don't think this is necessary anymore
        #else
        #{
        #    $inbound = Get-SM365InboundConnectorSettings -Version "None" -Option $Option
        #    $outbound = Get-SM365OutboundConnectorSettings -Version "None" -Option $Option
        #}

        $inbound.Enabled = $Enabled
        $outbound.Enabled = $Enabled

        # Getting SEPPmail IP Address(es) for Anti-SPAM Whitelist
        Write-Verbose "No IPs provided - trying to resolve $SEPPmailFQDN"
        [string[]] $smFqdnIps = [System.Net.Dns]::GetHostAddresses($SEPPmailFQDN) | ForEach-Object { $_.IPAddressToString }

        if($TrustedIPs)
        {
            $inbound.EFSkipIPs.AddRange($TrustedIPs)
        }

        if($PSBoundParameters.ContainsKey("SEPPmailFQDN"))
        {$outbound.SmartHosts = $SEPPmailFQDN}

        if($OutboundTlsDomain)
        {$outbound.TlsDomain = $OutboundTlsDomain}

        if($InboundTlsDomain)
        {$inbound.TlsSenderCertificateName = $InboundTlsDomain}

        if($PSBoundParameters.ContainsKey("SenderDomains"))
        {$inbound.SenderDomains = $SenderDomains}

        if($PSBoundParameters.ContainsKey("RecipientDomains"))
        {$outbound.RecipientDomains = $RecipientDomains}

        if ($version -ne 'SkipSpf')
        {
            Write-Verbose "Trying to add SEPPmail Appliance to Whitelist in 'Hosted Connection Filter Policy'"
            Write-Verbose "Collecting existing WhiteList"
            $hcfp = Get-HostedConnectionFilterPolicy
            [string[]]$existingAllowList = $hcfp.IPAllowList
            Write-verbose "Adding SEPPmail Appliance to Policy $($hcfp.Id)"
            if ($existingAllowList) {
                    $FinalIPList = ($existingAllowList + $IPs)|sort-object -Unique
            }
            else {
                $FinalIPList = $IPs
            }
            Write-verbose "Adding IPaddress list with content $finalIPList to Policy $($hcfp.Id)"
            if ($FinalIPList) {
                Set-HostedConnectionFilterPolicy -Identity $hcfp.Id -IPAllowList $finalIPList
            }
        }

        Write-Verbose "Read existing SEPPmail Inbound Connector"
        $existingSMInboundConn = Get-InboundConnector $inbound.Name -ErrorAction SilentlyContinue

        if(!$existingSMInboundConn)
        {throw [System.Exception] "No existing SEPPmail inbound connector found"}
        else
        {
            if($SetDefaults)
            {
                # make sure we only add to existing EFSkipIPs, if defaults are requested
                $existingSMInboundConn.EFSkipIPs | % {
                    if ($inbound.EFSkipIPs -notcontains $_)
                    { $inbound.EFSkipIPs.Add($_) }
                }

                # make sure the appliance itself is registered in EFSkipIPs, if defaults are requested
                [System.Net.Dns]::GetHostAddresses($existingSMInboundConn.TlsSenderCertificateName) | % {
                    if ($existingSMInboundConn.EFSkipIPs -notcontains $_.IPAddressToString) {
                        Write-Verbose "Appliance IP is not in EFSkipIPs - adding..."
                        $inbound.EFSkipIPs.Add($_.IPAddressToString)
                    }
                }
            }

            $param = $inbound.ToHashtable("Update")
            Write-Verbose "Updating SEPPmail Inbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($inbound.Name, "Updating Inbound Connector")) {
                Write-Debug "Inbound Connector settings:"
                $param.GetEnumerator() | % {
                    Write-Debug "$($_.Key) = $($_.Value)"
                }

                Set-InboundConnector @param

                if(!$?)
                {throw [System.Exception] $error[0]}
            }
        }

        Write-Verbose "Read existing SEPPmail outbound connector"
        $existingSMOutboundConn = Get-OutboundConnector $outbound.Name -ErrorAction SilentlyContinue

        if(!$existingSMOutboundConn)
        {throw [System.Exception] "No existing SEPPmail outbound connector found"}
        else
        {
            $param = $outbound.ToHashtable("Update")
            Write-Verbose "Updating SEPPmail Outbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($outbound.Name, "Updating Outbound Connector")) {
                Write-Debug "Outbound Connector settings:"
                $param.GetEnumerator() | % {
                    Write-Debug "$($_.Key) = $($_.Value)"
                }

                Set-OutboundConnector @param

                if(!$?)
                {throw [System.Exception] $error[0]}
            }
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
    Remove-SM365Connectors
#>
function Remove-SM365Connectors
{
    [CmdletBinding(SupportsShouldProcess=$true,
                   ConfirmImpact='Medium')]
    Param
    (

    )

    if (!(Test-SM365ConnectionStatus))
    { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

    Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

    $inbound = Get-SM365InboundConnectorSettings -Version "None"
    $outbound = Get-SM365OutboundConnectorSettings -Version "None"

    if($PSCmdlet.ShouldProcess($outbound.Name, "Remove SEPPmail connector"))
    {Remove-OutboundConnector $outbound.Name}

    if($PSCmdlet.ShouldProcess($inbound.Name, "Remove SEPPmail connector"))
    {Remove-InboundConnector $inbound.Name}
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
        [Alias("Folder")]
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

        Get-InboundConnector | %{
            $n = $_.Name
            $n = $n -replace "[\[\]*\\/?:><`"]"

            $p = "$OutFolder\inbound_connector_$n.json"

            Write-Verbose "Backing up $($_.Name) to $p"
            ConvertTo-Json -InputObject $_ | Out-File $p
        }

        Get-OutboundConnector | % {
            $n = $_.Name
            $n = $n -replace "[\[\]*\\/?:><`"]"

            $p = "$OutFolder\outbound_connector_$n.json"
            Write-Verbose "Backing up $($_.Name) to $p"
            ConvertTo-Json -InputObject $_ | Out-File $p
        }
    }
}


# SIG # Begin signature block
# MIIL1wYJKoZIhvcNAQcCoIILyDCCC8QCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjSpK0tO+zQVpJLG/mAtJm4/E
# tLGggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
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
# MRYEFB6ww6gJWZ2nmm38FP+Adeqtzxm2MA0GCSqGSIb3DQEBAQUABIIBADF9FiTi
# 2aJiZyJrOLxcquFwy1wO74npfUl3kxXEV2mLgEaMFKRPuPodJ+sTnTPSIOmO5dhE
# WeCpxeY8nLYxkHAVmv1mihBHvndM6WFhJXHLhoJq5T1k56I5aM/1HBvCgpzfSk00
# ixtz2n/bbJSe348ZJ196ezfQisrUFEyVZjkGv+S0dVNdGUtYyhF76DN5i4Hu1VUT
# 1qU/84rmpkciMmpl81AwUfXG22MQYSF1MaSYx/hFQxIJrH1htfd9wYJAu4acGgj8
# xrodiJ3BhUm/4SYEwPB/BBjMgmpyusWonD/O1A064WmgezOvjznPAVmdllFSw5yR
# TeOPsbq7s7BW3Gg=
# SIG # End signature block
