<#
.SYNOPSIS
    Adds SEPPmail Exchange Online connectors 
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online 
    This commandlet will create the connectors for you.

.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.consoso.com'
.EXAMPLE
    New-SM365Connectors -SEPPmailFQDN 'securemail.consoso.com' -maildomain 'contoso.com'
#>
function New-SM365Connectors
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'FQDN of the SEPPmail Appliance'
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("FQDN")]
        [String]$SEPPmailFQDN
<#
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Mail Domain of Exchange Online'
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("domain")]
        [String[]]$mailDomain
#>
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
        }
    }
    
    process
    {
        Write-Verbose "Load default connector settings from PSModule folder and transform into hashtables"
        $InboundConnParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Connectors\Inbound.json -Raw)).psobject.properties | ForEach-Object { $InboundConnParam[$_.Name] = $_.Value }
        $OutboundConnParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Connectors\Outbound.json -Raw)).psobject.properties | ForEach-Object { $OutboundConnParam[$_.Name] = $_.Value }

        Write-Verbose "Fill in values from Parameters"
        $OutboundConnParam.SmartHosts = $SEPPmailFQDN
        $OutboundConnParam.TlsDomain = $SEPPmailFQDN
        $InboundConnParam.TlsSenderCertificateName = $SEPPmailFQDN
        
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
                $existingSMInboundConn | Remove-InboundConnector -Whatif:$Whatif
                $InboundConn = New-InboundConnector @InboundConnParam -Whatif:$Whatif #|Out-Null
            }
            else
            {
                Write-Warning "Leaving existing SEPPmail Inbound Connector `"$($existingSMInboundConn.Name)`" untouched."
            }
        }
        else
        {
            $InboundConn = New-InboundConnector @InboundConnParam -Whatif:$Whatif #|Out-Null
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
                $existingSMOutboundConn | Remove-OutboundConnector -Whatif:$Whatif
                $OutboundConn = New-OutboundConnector @OutboundConnParam -Whatif:$Whatif #|Out-Null
            }
            else
            {
                Write-Warning "Leaving existing SEPPmail outbound connector `"$($existingSMOutboundConn.Name)`" untouched."
            }
        }
        else
        {
            $OutboundConn = New-OutboundConnector @OutboundConnParam -Whatif:$Whatif #|Out-Null
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
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>
function New-SM365Rules
{
    [CmdletBinding(SupportsShouldProcess)]
    param(

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
        }
    }
    
    process
    {
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
                    [ValidateSet('Top', 'Bottom', 'Cancel')]$existingRulesAction = Read-Host -Prompt "Where shall we place the SEPPmail rules ? (Top/Bottom/Cancel)"
                }
                catch {                }
            }
            until ($?)

            switch ($existingRulesAction)
            {
                'Top' { $placementPrio = '0' }
                'Bottom' { $placementPrio = ($existingTransportRules).count }
                'Cancel' { exit }
            }
        }
        else
        {
            Write-Verbose 'No existing custom rules found'
        }
        Write-Verbose "Placement Prio is $placementPrio"

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

    end
    {
        
    }
}


<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    Example of how to use this cmdlet
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
.NOTES
    General notes
.COMPONENT
    The component this cmdlet belongs to
.ROLE
    The role this cmdlet belongs to
.FUNCTIONALITY
    The functionality that best describes this cmdlet
#>
function New-SM365ExOReport {
    [CmdletBinding(SupportsShouldProcess=$true,
                   ConfirmImpact='Medium')]
    Param (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false, 
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(0,5)]
        [ValidateSet("sun", "moon", "earth")]
        [Alias("p1")] 
        $Param1,
        
        # Param2 help description
        [Parameter(ParameterSetName='Parameter Set 1')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [ValidateScript({$true})]
        [ValidateRange(0,5)]
        [int]
        $Param2,
        
        # Param3 help description
        [Parameter(ParameterSetName='Another Parameter Set')]
        [ValidatePattern("[a-z]*")]
        [ValidateLength(0,15)]
        [String]
        $Param3
    )
    
    begin {
    }
    
    process {
        if ($pscmdlet.ShouldProcess("Target", "Operation")) {
            
        }
    }
    
    end {
    }
}