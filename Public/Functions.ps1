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
             HelpMessage = 'IP addresses or ranges of the SEPPmail appliances'
         )]
        [string[]] $TrustedIPs,

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
        $DebugPreference = "Continue"

        $domains = Get-AcceptedDomain
        if(!$domains)
        {throw [System.Exception] "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"}

        # provide defaults for parameters, if not specified
        if(!$TlsDomain)
        {$TlsDomain = $SEPPmailFQDN}

        if(!$InboundTlsDomain)
        {$InboundTlsDomain = $TlsDomain}

        if(!$OutboundTlsDomain)
        {$OutboundTlsDomain = $TlsDomain}

        $defdomain = ($domains | Where-Object Default -Like 'True').DomainName
        Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue

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


        if($TrustedIPs)
        {
            $inbound.EFSkipLastIP = $false
            $inbound.EFSkipIPs = $TrustedIPs
        }
        else
        {$inbound.EFSkipLastIP = $true}

        if($SenderDomains -and !($SenderDomains -eq '*'))
        {
            $inbound.AssociatedAcceptedDomains = $SenderDomains
            $inbound.SenderDomains = $SenderDomains
        }

        if($RecipientDomains)
        {
            $outbound.RecipientDomains = $RecipientDomains
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
        [switch] $Enabled
    )

    begin
    {
        $domains = Get-AcceptedDomain
        if(!$domains)
        {throw [System.Exception] "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"}

        # provide defaults for parameters, if not specified
        if(!$TlsDomain)
        {$TlsDomain = $SEPPmailFQDN}

        if(!$InboundTlsDomain)
        {$InboundTlsDomain = $TlsDomain}

        if(!$OutboundTlsDomain)
        {$OutboundTlsDomain = $TlsDomain}

        $defdomain = ($domains | Where-Object Default -Like 'True').DomainName
        Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue
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

        if($TrustedIPs)
        {
            $inbound.EFSkipLastIP = $false
            $inbound.EFSkipIPs = $TrustedIPs
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


        Write-Verbose "Read existing SEPPmail Inbound Connector"
        $existingSMInboundConn = Get-InboundConnector $inbound.Name -ErrorAction SilentlyContinue

        if(!$existingSMInboundConn)
        {throw [System.Exception] "No existing SEPPmail inbound connector found"}
        else
        {
            $param = $inbound.ToHashtable()
            Write-Verbose "Updating SEPPmail Inbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($param.Name, "Updating Inbound Connector")) {
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
            $param = $outbound.ToHashtable()
            Write-Verbose "Updating SEPPmail Outbound Connector $($param.Name)!"
            if ($PSCmdLet.ShouldProcess($param.Name, "Updating Outbound Connector")) {
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
        $domains = Get-AcceptedDomain
        if (!$domains)
        {throw [System.Exception] "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"}

        $defdomain = ($domains | Where-Object Default -Like 'True').DomainName
        Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue

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
                Get-SM365TransportRuleSettings -Version $Version | %{
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
        [SM365.ConfigVersion] $Version = [SM365.ConfigVersion]::Default
    )

    begin
    {
        $domains = Get-AcceptedDomain
        if (!$domains)
        { throw [System.Exception] "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'" }

        $defdomain = ($domains | Where-Object Default -Like 'True').DomainName
        Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue

        if(!(Get-TransportRule | ?{$_.Name -match "^\[SEPPmail\]"}))
        {throw [System.Exception] "No SEPPmail transport rules found. Please run `"New-SM365Rules`" to create them."}
    }

    process
    {
        try
        {
            Get-SM365TransportRuleSettings | %{
                $setting = $_

                # Don't reset the outbound connector, 'cause admin might have
                # changed it intentionally
                $setting.RouteMessageOutboundConnector = $null

                $parameters = $setting.ToHashtable()

                # Resetting priority might be dangerous, so we don't do that here
                $parameters.Remove("Priority")

                # Set-TransportRule has no way of disabling existing rules
                $parameters.Remove("Enabled")

                if ($PSCmdlet.ShouldProcess($setting.Name, "Update transport rule"))
                {
                    Write-Debug "Transport rule settings:"
                    $parameters.GetEnumerator() | % {
                        Write-Debug "$($_.Key) = $($_.Value)"
                    }

                    Set-TransportRule $setting.Name @parameters
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
        $domains = Get-AcceptedDomain
        if(!$domains)
        {throw [System.Exception] "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"}

        $defdomain = ($domains | Where-Object Default -Like 'True').DomainName
        Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue
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
        $domains = Get-AcceptedDomain
        if(!$domains)
        {throw [System.Exception] "Cannot retrieve Exchange Domain Information, please reconnect with 'Connect-ExchangeOnline'"}

        $defdomain = ($domains | Where-Object Default -Like 'True').DomainName
        Write-Information "Connected to Exchange Organization `"$defdomain`"" -InformationAction Continue
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

    begin {
    }

    process {
        try {
            if ($pscmdlet.ShouldProcess("Target", "Operation")) {
                #"Whatis is $Whatif and `$pscmdlet.ShouldProcess is $($pscmdlet.ShouldProcess) "
                #For later Use
            }
            $Top = "<p><h1>Exchange Online Report</h1><p>"
            Write-Verbose "Collecting Accepted Domains"
            $hA = '<p><h2>Accepted Domains</h2><p>'
            $A = Get-AcceptedDomain |select-object Domainname,DomainType,Default,EmailOnly,ExternallyManaged,OutboundOnly|Convertto-HTML -Fragment
            Write-Verbose "Collecting Audit Log and Dkim Settings"
            $hB = '<p><h2>Audit Log Settings</h2><p>'
            $B = Get-AdminAuditLogConfig |Select-Object Name,AdminAuditLogEnabled,LogLevel,AdminAuditLogAgeLimit |Convertto-HTML -Fragment

            $hC = '<p><h2>DKIM Settings</h2><p>'
            $C = Get-DkimSigningConfig|Select-Object Domain,Status|Convertto-HTML -Fragment

            Write-Verbose "Collecting Phishing and Malware Policies"
            $hD = '<p><h2>Phishing and Malware Policies</h2><p>'
            $D = Get-AntiPhishPolicy|Select-Object Identity,isDefault,IsValid|Convertto-HTML -Fragment
            $E = Get-MalwareFilterPolicy|Select-Object Identity,Action,IsDefault|Convertto-HTML -Fragment

            Write-Verbose "ATP Information"
            $hF = '<p><h2>ATP Information</h2><p>'
            $F = Get-ATPTotalTrafficReport|Select-Object Organization,Eventtype,Messagecount|Convertto-HTML -Fragment

            Write-Verbose "Get-HybridMailflow"
            $hG = '<p><h2>Hybrid Mailflow Information</h2><p>'
            $G = Get-HybridMailflow|Convertto-HTML -Fragment

            #Write-Verbose " Get-HybridMailflowDatacenterIPs"
            #Get-HybridMailflowDatacenterIPs|Select-Object -ExpandProperty DatacenterIPs|Format-Table
            #$H = Get-IntraOrganizationConfiguration|Select-Object OnlineTargetAddress,OnPremiseTargetAddresses,IsValid|Convertto-HTML -Fragment

            Write-Verbose "Get-IntraorgConnector"
            $hI = '<p><h2>Intra Org Connector Settings</h2><p>'
            $I = Get-IntraOrganizationConnector|Select-Object Identity,TargetAddressDomains,DiscoveryEndpoint,IsValid|Convertto-HTML -Fragment

            Write-Verbose "Get-MigrationConfig"
            $hJ = '<p><h2>Migration Configuration Settings</h2><p>'
            $J = Get-MigrationConfig|Select-Object Identity,Features,IsValid|Convertto-HTML -Fragment

            Write-Verbose "Get-MigrationStatistics"
            $hK = '<p><h2>Migration Statistics</h2><p>'
            $K = Get-MigrationStatistics|Select-Object Identity,Totalcount,FinalizedCount,MigrationType,IsValid|Convertto-HTML -Fragment

            Write-Verbose "InboundConnectors"
            $hL = '<p><h2>Inbound Connectors</h2><p>'
            $L = Get-InboundConnector |Select-Object Identity,OrganizationalUnitRootInternal,TlsSenderCertificateName,ConnectorType,ConnectorSource,EFSkipLastIP,EFUsers,IsValid|Convertto-HTML -Fragment

            Write-Verbose "OutboundConnectors"
            $hM = '<p><h2>Outbound Connectors</h2><p>'
            $M = Get-OutboundConnector|Select-Object Identity,TlsDomain,OriginatingServer,TlsSettings,ConnectorType,ConnectorSource,EFSkipLastIP,EFUsers,IsValid|Convertto-HTML -Fragment

            Write-Verbose "TransportRules"
            $hN = '<p><h2>Existing Transport Rules</h2><p>'
            $N = Get-TransportRule | select-object Name,IsValid,Priority,FromScope,SentToScope,Comments |Convertto-HTML -Fragment

            # Get MX Record Report for each domain
            $hO = '<p><h2>MX Record for each Domain</h2><p>'
            $O = $Null
            $oTemp = Get-AcceptedDomain
            Foreach ($AcceptedDomain in $oTemp.DomainName) {
                $O += (Get-MxRecordReport -Domain $AcceptedDomain|Select-Object -Unique|Select-Object HighestPriorityMailhost,HighestPriorityMailhostIpAddress,Domain|Convertto-HTML -Fragment)
            }

            # Find out possible Sending Limits for LFT
            Write-Verbose "Collecting Send and Receive limits for SEPPmail LFT configuration"
            $hN = '<p><h2>Send and Receive limits (for SEPPmail LFT configuration)</h2><p>'
            $N = Get-TransportConfig |Select-Object MaxSendSize,MaxReceiveSize |Convertto-HTML -Fragment


            $HeaderLogo = [Convert]::ToBase64String((Get-Content -path $ModulePath\HTML\SEPPmailLogo.jpg -encoding byte ))
            $LogoHTML = @"
<img src="data:image/jpg;base64,$($HeaderLogo)" style="left:150px alt="Exchange Online System Report">
"@
            $style = Get-Content $ModulePath\HTML\SEPPmailReport.css
            Convertto-HTML -Body "$LogoHTML $Top $hA $a $hB $b $hC $c $hd $d $e $hF $f $hG $g $hI $i $hJ $j $hK $k $hL $l $hM $m $hN $n $hO $o" -Title "SEPPmail365 Exo Report" -Head $style|Out-File -FilePath $filePath

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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU07N2gRmbgJAa1c0Rdk+BiWq5
# da2ggglAMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
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
# MRYEFGBlNAid38ZoGgpa9K3lRb6L4LaSMA0GCSqGSIb3DQEBAQUABIIBAGPrM7xb
# Flttd/xeu0B3cefK1OR+c8XP8hoayiUs/E2z0RqxGrXMl+qmfNLSk53cDlTL08IP
# o9jyrlblyOoMcr4WOq+BjQmyJLcQCiIrpoYsiADT0VOzywnBSQjt9iZmtrldnoyD
# Z2NMa+0TuWMVrYAFBGCS6Zyl/udwlqhj/j5oXFfmEIwJbY46JNxPSklc3bVmXjVd
# vJ/5GQDLUxicIEIKxcWrtHwbaVofvx9W4wn1vfzdVa3fB82wUCduzMwFi0bQa+hS
# YeD0+shMCd0KyoLvfqfNPHOxte0uaKE/Uf5nlUlNpy98GixrTauXGzo4aKQFWw6u
# Fh2YMoKW7ELaWLA=
# SIG # End signature block
