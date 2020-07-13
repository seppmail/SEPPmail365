<#
.SYNOPSIS
    Adds SEPPmail Exchange Online connectors and  transport rules
.DESCRIPTION
    SEPPmail uses 2 Connectors to transfer messages between SEPPmail and Exchange Online and some transport rules to control the message flow. This commandlet will create the connectors and rules for you.

.EXAMPLE
    Add-SEConnAndRules -SEPPmailFQDN 'securemail.consoso.com'
.EXAMPLE
    Another example of how to use this cmdlet
#>
function Add-SEConnAndRules
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            ParameterSetName                = 'bottom',
            Mandatory                       = $true,
            HelpMessage                     = 'FQDN of the SEPPmail Appliance'
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("FQDN")]
        [String]$SEPPmailFQDN,

        [Parameter(
            Mandatory                       = $false,
            HelpMessage                     = 'Mail Domain of Exchange Online'
        )]
        [ValidatePattern("^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")]
        [Alias("domain")]
        [String[]]$mailDomain

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
        Write-Verbose "Load default connector settings from Module folder and transform into hashtables"
        $InboundConnParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Connectors\Inbound.json -Raw)).psobject.properties | ForEach-Object { $InboundConnParam[$_.Name] = $_.Value }
        $OutboundConnParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Connectors\Outbound.json -Raw)).psobject.properties | ForEach-Object { $OutboundConnParam[$_.Name] = $_.Value }

        Write-Verbose "Fill in values from Parameters"
        $OutboundConnParam.SmartHosts = $SEPPmailFQDN
        $OutboundConnParam.TlsDomain = $SEPPmailFQDN
        $InboundConnParam.TlsSenderCertificateName = $SEPPmailFQDN
        
        Write-Verbose "Create Inbound and Outbound Connectors"
        New-InboundConnector @InboundConnParam
        New-OutboundConnector @OutboundConnParam

        #$InboundConnParam
        #$OutboundConnParam

<#        Write-Verbose "Read existing SEPPmail transport rules"
        $existingSMTransportRules = Get-TransportRule -Identity '[SEPPmail]*'
        if ($existingSMTransportRules) {
            Write-Warning 'Found existing [SEPPmail] Rules.'
            Do {
                try {
                    [ValidateSet('y','Y','n','N')]$recreateSMRules = Read-Host -Prompt "Shall we delete and recreate them ? (Y/N)"
                } catch {}
            }
            until ($?)
            
            "Here action, based on $recreateSMrules"
        }
#>
        Write-Verbose "Read existing non-SEPPmail transport rules"
        $existingTransportRules = Get-TransportRule |Where-Object Name -notLike '*SEPPmail*' 
        if ($existingTransportRules) {
            Write-Warning 'Found existing non-[SEPPmail] transport rules.'
            Write-Warning '--------------------------------------------'
            foreach ($etpr in $existingTransportRules) {
                Write-Warning "Rule name `"$($etpr.Name)`" with state `"$($etpr.State)`" has priority `"$($etpr.Priority)`""
            }
            Write-Warning '--------------------------------------------'
            Do {
                try {
                    [ValidateSet('Top','Bottom','Cancel')]$existingRulesAction = Read-Host -Prompt "Where shall we place the SEPPmail rules ? (Top/Bottom/Cancel)"
                } catch {                }
            }
            until ($?)

            switch ($existingRulesAction)
            {
                'Top'       {$placementPrio = '0' }
                'Bottom'    {$placementPrio = ($existingTransportRules).count}
                'Cancel'    {exit}
            }
        } else {
            Write-Verbose 'No existing non-SEPPmail rules found'
        }
        Write-Verbose "Placement Prio is $placementPrio"

        Write-Verbose "Load default transport rules from module folder and transform into hashtables"
        $outgoingHeaderCleaningParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-outgoing-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$outgoingHeaderCleaningParam[$_.Name] = $_.Value}
        $decryptedHeaderCleaningParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-decrypted-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$decryptedHeaderCleaningParam[$_.Name] = $_.Value}
        $encryptedHeaderCleaningParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-encrypted-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$encryptedHeaderCleaningParam[$_.Name] = $_.Value}
        $InternalParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\internal.json -Raw)).psobject.properties | ForEach-Object {$InternalParam[$_.Name] = $_.Value}
        $OutboundParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\outbound.json -Raw)).psobject.properties | ForEach-Object {$OutboundParam[$_.Name] = $_.Value}
        $InboundParam = [ordered]@{}
        (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\inbound.json -Raw)).psobject.properties | ForEach-Object {$InboundParam[$_.Name] = $_.Value}

        Write-Verbose "Adapt Transport rules with connector information"
        $InternalParam.RouteMessageOutboundConnector = $OutboundConnParam.Name
        $OutboundParam.RouteMessageOutboundConnector = $OutboundConnParam.Name
        $InboundParam.RouteMessageOutboundConnector = $OutboundConnParam.Name

        Write-Verbose "Set rules priority"
        $outgoingHeaderCleaningParam.Priority = $placementPrio
        $decryptedHeaderCleaningParam.Priority = $placementPrio
        $encryptedHeaderCleaningParam.Priority = $placementPrio
        $InternalParam.Priority = $placementPrio
        $OutboundParam.Priority = $placementPrio
        $InboundParam.Priority = $placementPrio

        Write-Verbose "Create Transport Rules"
        New-TransportRule @outgoingHeaderCleaningParam -ErrorAction Stop |Out-Null
        New-TransportRule @decryptedHeaderCleaningParam -ErrorAction Stop |Out-Null
        New-TransportRule @encryptedHeaderCleaningParam -ErrorAction Stop |Out-Null
        New-TransportRule @InternalParam -ErrorAction Stop |Out-Null
        New-TransportRule @OutboundParam -ErrorAction Stop |Out-Null
        New-TransportRule @InboundParam -ErrorAction Stop |Out-Null

<#        $outgoingHeaderCleaningParam
        $decryptedHeaderCleaningParam
        $encryptedHeaderCleaningParam
        $InternalParam
        $OutboundParam
        $InboundParam
#>
    }
    
    end
    {
        
    }
}

function Test-MyInvoc
{
    [CmdletBinding()]
    param ()
    process
    {
        $Myinvocation
    }
}

