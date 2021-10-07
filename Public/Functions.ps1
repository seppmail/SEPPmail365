. "$PSScriptRoot\..\Private\Functions.ps1"

# Request terminating errors by default
$PSDefaultParameterValues['*:ErrorAction'] = [System.Management.Automation.ActionPreference]::Stop

$InteractiveSession = [System.Environment]::UserInteractive

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
         ConfirmImpact = 'Medium'
     )]

    param
    (
        [Parameter(
             Mandatory = $true,
             HelpMessage = 'FQDN of the SEPPmail Appliance'
         )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("FQDN")]
        [String] $SEPPmailFQDN,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'Internal Mail Domains, the connector will take E-Mails from'
         )]
        [string[]] $SenderDomains,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'External Mail Domains, the connector will send E-Mails to'
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
            HelpMessage = 'IP addresses or ranges of the SEPPmail appliances'
        )]
        [string[]] $TrustedIPs,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'Which configuration version to use'
         )]
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Default,

        [Parameter(
             Mandatory = $false,
             HelpMessage = 'Should the connectors be created active or inactive'
         )]
        [switch] $Enabled = $true
    )

    begin
    {
        if(!(Test-SM365ConnectionStatus))
        {throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet"}

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        # provide defaults for parameters, if not specified
        if(!$TlsDomain)
        {$TlsDomain = $SEPPmailFQDN}

        if(!$InboundTlsDomain)
        {$InboundTlsDomain = $TlsDomain}

        if(!$OutboundTlsDomain)
        {$OutboundTlsDomain = $TlsDomain}

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
        $outbound = Get-SM365OutboundConnectorSettings -Version $Version
        $outbound.SmartHosts = $SEPPmailFQDN
        $outbound.TlsDomain = $OutboundTlsDomain
        $outbound.Enabled = $Enabled

        $inbound = Get-SM365InboundConnectorSettings -Version $Version
        $inbound.TlsSenderCertificateName = $InboundTlsDomain
        $inbound.Enabled = $Enabled
        
        # Getting SEPPmail IP Address(es) for EFSkipIP´s and Anti-SPAM Whitelist
        Write-Verbose "No IPs provided - trying to resolve $SEPPmailFQDN"
        [string[]] $ips = [System.Net.Dns]::GetHostAddresses($SEPPmailFQDN) | ForEach-Object { $_.IPAddressToString }
        Write-Verbose "Found following IP addresses: $ips"
        $inbound.EFSkipIPs.AddRange($ips)

        if($SenderDomains -and !($SenderDomains -eq '*'))
        {
            $inbound.AssociatedAcceptedDomains = $SenderDomains
            $inbound.SenderDomains = $SenderDomains
        }

        if($RecipientDomains)
        {
            $outbound.RecipientDomains = $RecipientDomains
        }

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
                $param.GetEnumerator() | % {
                    Write-Debug "$($_.Key) = $($_.Value)"
                }
                New-InboundConnector @param | Out-Null

                if(!$?)
                {throw $error[0]}
            }
        }

        Write-Verbose "Read existing SEPPmail outbound connector"
        $existingSMOutboundConn = $allOutboundConnectors | Where-Object Name -EQ $outbound.Name

        # only $false if the user says so interactively
        [bool] $createOutbound = $true
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
                $param.GetEnumerator() | %{
                    Write-Debug "$($_.Key) = $($_.Value)"
                }

                New-OutboundConnector @param | Out-Null

                if(!$?)
                {throw $error[0]}
            }
        }
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
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Default,

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

            $inbound = Get-SM365InboundConnectorSettings -Version $Version
            $outbound = Get-SM365OutboundConnectorSettings -Version $Version
        }
        else
        {
            $inbound = Get-SM365InboundConnectorSettings -Version "None"
            $outbound = Get-SM365OutboundConnectorSettings -Version "None"
        }

        $inbound.Enabled = $Enabled
        $outbound.Enabled = $Enabled

        # Getting SEPPmail IP Address(es) for Anti-SPAM Whitelist
        Write-Verbose "No IPs provided - trying to resolve $SEPPmailFQDN"
        [string[]] $ips = [System.Net.Dns]::GetHostAddresses($SEPPmailFQDN) | ForEach-Object { $_.IPAddressToString }

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
    Create SEPPmail transport rules
.DESCRIPTION
    Creates rules to direct the mailflow between Exchange Online and SEPPmail.
.EXAMPLE
    PS C:\> New-SM365Rules
    Creates the needed ruleset to integrate SEPPmail with Exchange online
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
        [SM365.PlacementPriority] $PlacementPriority = [SM365.PlacementPriority]::Top,

        [Parameter(Mandatory=$false,
                   HelpMessage='Which configuration version to use')]
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Default,

        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Should the rules be created active or inactive'
        )]
        [switch] $Enabled = $true
    )

    begin
    {
        if (!(Test-SM365ConnectionStatus))
        { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        $outboundConnectors = Get-OutboundConnector | ?{ $_.Name -match "^\[SEPPmail\]" }
        if(!($outboundConnectors))
        {
            throw [System.Exception] "No SEPPmail outbound connector found. Run `"New-SM365Connectors`" to add the proper SEPPmail connectors"
        }
    }

    process
    {
        try
        {
            Write-Verbose "Read existing custom transport rules"
            $existingTransportRules = Get-TransportRule | Where-Object Name -NotMatch '^\[SEPPmail\].*$'
            [int] $placementPrio = @(0, $existingTransportRules.Count)[!($PlacementPriority -eq "Top")] <# Poor man's ternary operator #>
            if ($existingTransportRules)
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
            $existingSMTransportRules = Get-TransportRule | Where-Object Name -Match '^\[SEPPmail\].*$'
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
                Get-SM365TransportRuleSettings -Version $Version | Foreach-Object {
                    $setting = $_

                    $setting.Priority = $placementPrio
                    $setting.Enabled = $Enabled

                    if ($PSCmdlet.ShouldProcess($setting.Name, "Create transport rule"))
                    {
                        $param = $setting.ToHashtable()

                        Write-Debug "Transport rule settings:"
                        $param.GetEnumerator() | % {
                            Write-Debug "$($_.Key) = $($_.Value)"
                        }

                        New-TransportRule @param
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
function Set-SM365Rules
{
    [CmdletBinding(
         SupportsShouldProcess = $true,
         ConfirmImpact = 'Medium'
     )]
    param
    (
        [Parameter(Mandatory=$false,
                   HelpMessage='Which configuration version to use')]
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Default,

        [Parameter(Mandatory=$false,
                   HelpMessage='Should missing rules be created')]
        [switch] $FixMissing
    )

    begin
    {
        if (!(Test-SM365ConnectionStatus))
        { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

        Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

        if(!(Get-TransportRule | ?{$_.Name -match "^\[SEPPmail\]"}))
        {throw [System.Exception] "No SEPPmail transport rules found. Please run `"New-SM365Rules`" to create them."}
    }

    process
    {
        try
        {
            Get-SM365TransportRuleSettings -Version $Version | %{
                $setting = $_
                $rule = Get-TransportRule $setting.Name -ErrorAction SilentlyContinue

                if ($rule -and $PSCmdlet.ShouldProcess($setting.Name, "Update transport rule"))
                {
                    $parameters = $setting.ToHashtable("Update")

                    Write-Debug "Transport rule settings:"
                    $parameters.GetEnumerator() | % {
                        Write-Debug "$($_.Key) = $($_.Value)"
                    }

                    Set-TransportRule @parameters

                    if(!$setting.Enabled -and $rule.State -eq "Enabled")
                    {
                        Write-Verbose "Disabling rule $($rule.name)..."
                        $rule | Disable-TransportRule -Confirm:$false
                    }
                    elseif($setting.Enabled -and $rule.State -ne "Enabled")
                    {
                        Write-Verbose "Activating rule $($rule.name)..."
                        $rule | Enable-TransportRule -Confirm:$false
                    }
                }
                elseif($PSCmdlet.ShouldProcess($setting.Name, "Create missing transport rule"))
                {
                    $parameters = $setting.ToHashtable()

                    Write-Debug "Transport rule settings:"
                    $parameters.GetEnumerator() | % {
                        Write-Debug "$($_.Key) = $($_.Value)"
                    }

                    New-TransportRule @parameters
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
    Removes the SEPPmail transport rules
.DESCRIPTION
    Convenience function to remove the SEPPmail transport rules
.EXAMPLE
    Remove-SM365TransportRules
#>
function Remove-SM365Rules {
    [CmdletBinding(SupportsShouldProcess = $true,
                   ConfirmImpact = 'Medium'
                  )]
    param
    (

    )

    if (!(Test-SM365ConnectionStatus))
    { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }

    Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue

    $settings = Get-SM365TransportRuleSettings -Version "None"
    foreach($setting in $settings)
    {
        if($PSCmdlet.ShouldProcess($setting.Name, "Remove transport rule"))
        {
            $rule = Get-TransportRule $setting.Name -ErrorAction SilentlyContinue
            if($rule)
            {$rule | Remove-TransportRule -Confirm:$false}
            else
            {Write-Verbose "Rule $($setting.Name) does not exist"}
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

<#
.SYNOPSIS
    Backs up all existing transport rules to individual json files
.DESCRIPTION
    Convenience function to perform a backup of all existing transport rules
.EXAMPLE
    Backup-SM365Rules -OutFolder "C:\temp"
#>
function Backup-SM365Rules
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

        Get-TransportRule | %{
            $n = $_.Name
            $n = $n -replace "[\[\]*\\/?:><`"]"

            $p = "$OutFolder\rule_$n.json"
            Write-Verbose "Backing up $($_.Name) to $p"
            ConvertTo-Json -InputObject $_ | Out-File $p
        }
    }
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
        # Define output Filapath
        [Parameter(   Mandatory = $true,
                    HelpMessage = 'Path of the HTML report on disk'
        )]
        $FilePath
    )

    begin
    {
        if (!(Test-SM365ConnectionStatus))
        { throw [System.Exception] "You're not connected to Exchange Online - please connect prior to using this CmdLet" }
        else {
            Write-Information "Connected to Exchange Organization `"$Script:ExODefaultDomain`"" -InformationAction Continue
        }
        Write-verbose 'Defining Function fo read Exo Data and return an info Message in HTML even if nothing is retrieved'
        function Get-ExoHTMLData {
            param (
                [Parameter(
                      Mandatory = $true,
                    HelpMessage = 'Enter Cmdlte to ')]
                [string]$ExoCmd
            )
            $rawData = Invoke-Expression -Command $exoCmd
            if ($null -eq $rawData) {
                $ExoHTMLData = New-object -type PSobject -property @{Result = '--- no information available ---'}|Convertto-HTML -Fragment
            } else {
                $ExoHTMLData = $rawData|Convertto-HTML -Fragment
            } 
            return $ExoHTMLData    
        }
    }

    process
    {
        try {
            if ($pscmdlet.ShouldProcess("Target", "Operation")) {
                #"Whatis is $Whatif and `$pscmdlet.ShouldProcess is $($pscmdlet.ShouldProcess) "
                #For later Use
            }
            $mv = Get-module SEPPmail365 |select-object -expandproperty version
            $Top = "<p><h1>Exchange Online Report created with SEPPmail365 Module</h1><p>"
            $now = Get-Date
            $RepCreationDateTime = "<p><body>Report created: $now</body><p>"
            $moduleVersion = "<p><body>Module Version: $mv</body><p>"

            Write-Verbose "Collecting Accepted Domains"
            $hSplitLine = '<p><h2>---------------------------------------------------------------------------------------------------------------------------</h2><p>'
            #region General infos
            $hGeneral =  '<p><h2>General Exchange Online and Subscription Information</h2><p>'
            
            $hA = '<p><h3>Accepted Domains</h3><p>'
            $A = Get-ExoHTMLData -ExoCmd 'Get-AcceptedDomain |select-object Domainname,DomainType,Default,EmailOnly,ExternallyManaged,OutboundOnly‘
            # Find out Office Configuration
            Write-Verbose "Collecting M365 Configuration"
            $hB = '<p><h3>ExO Configuration Details</h3><p>'
            $B = Get-ExoHTMLData -ExoCmd 'Get-OrganizationConfig |Select-Object DisplayName,ExchangeVersion,AllowedMailboxRegions,DefaultMailboxRegion'

            # Find out possible Sending Limits for LFT
            Write-Verbose "Collecting Send and Receive limits for SEPPmail LFT configuration"
            $hP = '<p><h3>Send and Receive limits (for SEPPmail LFT configuration)</h3><p>'
            $P = Get-ExoHTMLData -ExoCmd  'Get-TransportConfig |Select-Object MaxSendSize,MaxReceiveSize'

            # Find out possible Office Message Encryption Settings
            Write-Verbose "Collecting Office Message Encryption Settings"
            $hP = '<p><h3>Office Message Encryption Settings</h3><p>'
            $P = Get-ExoHTMLData -ExoCmd 'Get-OMEConfiguration'
            
            # Get MX Record Report for each domain
            $hO = '<p><h3>MX Record for each Domain</h3><p>'
            $O = $Null
            $oTemp = Get-AcceptedDomain
            Foreach ($AcceptedDomain in $oTemp.DomainName) {
                    $O += (Get-MxRecordReport -Domain $AcceptedDomain|Select-Object -Unique|Select-Object HighestPriorityMailhost,HighestPriorityMailhostIpAddress,Domain|Convertto-HTML -Fragment)
            }

            #endregion
            
            #region Security 
            $hSecurity = '<p><h2>Security related Information</h2><p>'
            $hC = '<p><h3>DKIM Settings</h3><p>'
            $C = Get-ExoHTMLData -ExoCmd 'Get-DkimSigningConfig|Select-Object Domain,Enabled,Status,Selector1CNAME,Selector2CNAME'
            
            Write-Verbose "Collecting Phishing and Malware Policies"
            $hD = '<p><h3>Anti Phishing Policies</h3><p>'
            $D = Get-ExoHTMLData -ExoCmd 'Get-AntiPhishPolicy|Select-Object Identity,isDefault,IsValid,AuthenticationFailAction'
            
            $hE = '<p><h3>Anti Malware Policies</h3><p>'
            $E = Get-ExoHTMLData -ExoCmd 'Get-MalwareFilterPolicy|Select-Object Identity,Action,IsDefault,Filetypes'

            $hk = '<p><h3>Content Filter Policy</h3><p>'
            $k= Get-ExoHTMLData -ExoCmd 'Get-HostedContentFilterPolicy'

            Write-Verbose "Blocked Sender Addresses"
            $hH = '<p><h3>Show Senders which are locked due to outbound SPAM</h3><p>'
            $h = Get-ExoHTMLData -ExoCmd 'Get-BlockedSenderAddress'
            
            Write-Verbose "Get Outbound SPAM Filter Policy"
            $hJ = '<p><h3>Outbound SPAM Filter Policy</h3><p>'
            $J = Get-ExoHTMLData -ExoCmd 'Get-HostedOutboundSpamFilterPolicy|Select-Object Name,IsDefault,Enabled,ActionWhenThresholdReached'
            
            Write-Verbose "Get Filter Policy"
            $hJ1 = '<p><h3>SPAM Filter Policy</h3><p>'
            $J1 = Get-ExoHTMLData -ExoCmd 'Get-HostedConnectionFilterPolicy|select-Object Name,IsDefault,Enabled,IPAllowList,IPBlockList'
            #endregion Security

            #region other connectors
            $hOtherConn = '<p><h2>Hybrid and other Connectors</h2><p>'
            Write-Verbose "Get-HybridMailflow"
            $hG = '<p><h3>Hybrid Mailflow Information</h3><p>'
            $g = Get-ExoHTMLData -ExoCmd 'Get-HybridMailflow'

            Write-Verbose "Get-IntraorgConnector"
            $hI = '<p><h3>Intra Org Connector Settings</h3><p>'
            $I = Get-ExoHTMLData -ExoCmd 'Get-IntraOrganizationConnector|Select-Object Identity,TargetAddressDomains,DiscoveryEndpoint,IsValid'
            #endregion

            #region connectors
            $hConnectors = '<p><h2>Existing Exchange Connectors</h2><p>'
            
            Write-Verbose "InboundConnectors"
            $hL = '<p><h3>Inbound Connectors</h3><p>'
            $L = Get-ExoHTMLData -ExoCmd 'Get-InboundConnector |Select-Object Identity,Enabled,SenderDomains,OrganizationalUnitRootInternal,TlsSenderCertificateName,IsValid'
            
            Write-Verbose "OutboundConnectors"
            $hM = '<p><h3>Outbound Connectors</h3><p>'
            $M = Get-ExoHTMLData -ExoCmd 'Get-OutboundConnector|Select-Object Identity,Enabled,SmartHosts,TlsDomain,TlsSettings,RecipientDomains,OriginatingServer,IsValid'
            #endregion connectors
            
            #region mailflow rules
            $hTransPortRules = '<p><h2>Existing Mailflow Rules</h2><p>'
            Write-Verbose "TransportRules"
            $hN = '<p><h3>Existing Transport Rules</h3><p>'
            $N = Get-ExoHTMLData -ExoCmd 'Get-TransportRule | select-object Name,State,Mode,Priority,FromScope,SentToScope'
            #endregion transport rules


            if ($psversiontable.PSedition -eq 'Desktop') {
                $HeaderLogo = [Convert]::ToBase64String((Get-Content -path $PSScriptRoot\..\HTML\SEPPmailLogo.jpg -encoding byte ))
            } else {
                $HeaderLogo = [Convert]::ToBase64String((Get-Content -path $PSScriptRoot\..\HTML\SEPPmailLogo.jpg -AsByteStream))
            }


            $LogoHTML = @"
<img src="data:image/jpg;base64,$($HeaderLogo)" style="left:150px alt="Exchange Online System Report">
"@

            $hEndOfReport = '<p><h2>--- End of Report ---</h2><p>'
            $style = Get-Content $PSScriptRoot\..\HTML\SEPPmailReport.css
            Convertto-HTML -Body "$LogoHTML $Top $RepCreationDatetime $moduleVersion`
                   $hSplitLine $hGeneral $hSplitLine $hA $a $hB $b $hP $P $hO $o`
                  $hSplitLine $hSecurity $hSplitLine $hC $c $hd $d $hE $e $hK $k $hH $h $hJ $j $hJ1 $J1 `
                 $hSplitLine $hOtherConn $hSplitLine $hG $g $hI $i `
                $hSplitLine $hConnectors $hSplitLine $hL $l $hM $m `
            $hSplitLine $hTransPortRules $hSplitLine $hN $n $hEndofReport " -Title "SEPPmail365 Exo Report" -Head $style|Out-File -FilePath $filePath

        }
        catch {
            throw [System.Exception] "Error: $($_.Exception.Message)"
        }
    }
    end {
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
