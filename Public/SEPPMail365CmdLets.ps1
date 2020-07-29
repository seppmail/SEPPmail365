<#
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