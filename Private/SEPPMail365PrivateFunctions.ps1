function Get-SM365TransportRuleDefaults {
    #[CmdLetBinding(SupportsShouldProcess)]
    Write-Verbose "Load default transport rules from module folder and transform into hashtables"
    $script:outgoingHeaderCleaningParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-outgoing-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$outgoingHeaderCleaningParam[$_.Name] = $_.Value}
    $script:decryptedHeaderCleaningParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-decrypted-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$decryptedHeaderCleaningParam[$_.Name] = $_.Value}
    $script:encryptedHeaderCleaningParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\X-SM-encrypted-header-cleaning.json -Raw)).psobject.properties | ForEach-Object {$encryptedHeaderCleaningParam[$_.Name] = $_.Value}
    $script:InternalParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\internal.json -Raw)).psobject.properties | ForEach-Object {$InternalParam[$_.Name] = $_.Value}
    $script:OutboundParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\outbound.json -Raw)).psobject.properties | ForEach-Object {$OutboundParam[$_.Name] = $_.Value}
    $script:InboundParam = [ordered]@{}
    (ConvertFrom-Json (Get-Content -Path $ModulePath\ExOConfig\Rules\inbound.json -Raw)).psobject.properties | ForEach-Object {$InboundParam[$_.Name] = $_.Value}
}
function Remove-SM365TransportRules {

    [CmdletBinding(SupportsShouldProcess = $true,
                           ConfirmImpact = 'Medium'
                    )]
    param()
    Get-SM365TransportRuleDefaults
    if ($PSCmdlet.ShouldProcess($($outgoingHeaderCleaningParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($outgoingHeaderCleaningParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($decryptedHeaderCleaningParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($decryptedHeaderCleaningParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($encryptedHeaderCleaningParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($encryptedHeaderCleaningParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($InternalParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($InternalParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($OutboundParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($OutboundParam.Name)
    }
    if ($PSCmdlet.ShouldProcess($($InboundParam.Name),'Remove transportrule')) {
        Remove-TransportRule -Identity $($InboundParam.Name)
    }

}
function New-SM365TransportRules {
    [CmdletBinding(SupportsShouldProcess = $true,
                           ConfirmImpact = 'Medium'
                )]
    param()

    Write-Verbose "Read Outbound Connector Information"
    $outboundConn = Get-OutboundConnector |Where-Object Name -match '^\[SEPPmail\].*$'
    if (!($outboundconn)) {
        Write-Error "No SEPPmail outbound connector found. Run `"Add-SEConnector`" to add the proper SEPPmail connectors"
    } 
    else 
        {
        Get-SM365TransportRuleDefaults
        Write-Verbose "Adapt Transport rules with outbound connector information"
        $InternalParam.RouteMessageOutboundConnector = $OutboundConn.Name
        $OutboundParam.RouteMessageOutboundConnector = $OutboundConn.Name
        $InboundParam.RouteMessageOutboundConnector = $OutboundConn.Name

        Write-Verbose "Set rules priority"
        $outgoingHeaderCleaningParam.Priority = $placementPrio
        $decryptedHeaderCleaningParam.Priority = $placementPrio
        $encryptedHeaderCleaningParam.Priority = $placementPrio
        $InternalParam.Priority = $placementPrio
        $OutboundParam.Priority = $placementPrio
        $InboundParam.Priority = $placementPrio

        Write-Verbose "Create Transport Rules"
        if ($PSCmdlet.ShouldProcess($($outgoingHeaderCleaningParam.Name),'Create transportrule')) {
            New-TransportRule @outgoingHeaderCleaningParam
        }
        if ($PSCmdlet.ShouldProcess($($decryptedHeaderCleaningParam.Name),'Create transportrule')) {
            New-TransportRule @decryptedHeaderCleaningParam
        }
        if ($PSCmdlet.ShouldProcess($($encryptedHeaderCleaningParam.Name),'Create transportrule')) {
            New-TransportRule @encryptedHeaderCleaningParam
        }
        if ($PSCmdlet.ShouldProcess($($InternalParam.Name),'Create transportrule')) {
            New-TransportRule @InternalParam
        }
        if ($PSCmdlet.ShouldProcess($($OutboundParam.Name),'Create transportrule')) {
            New-TransportRule @OutboundParam
        }
        if ($PSCmdlet.ShouldProcess($($InboundParam.Name),'Create transportrule')) {
            New-TransportRule @InboundParam
        }
    }
}
