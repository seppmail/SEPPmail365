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
    Remove-TransportRule -Identity $($outgoingHeaderCleaningParam.Name) -Whatif:$Whatif
    Remove-TransportRule -Identity $($decryptedHeaderCleaningParam.Name) -Whatif:$Whatif
    Remove-TransportRule -Identity $($encryptedHeaderCleaningParam.Name) -Whatif:$Whatif
    Remove-TransportRule -Identity $($InternalParam.Name) -Whatif:$Whatif
    Remove-TransportRule -Identity $($OutboundParam.Name) -Whatif:$Whatif
    Remove-TransportRule -Identity $($InboundParam.Name) -Whatif:$Whatif
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
        New-TransportRule @outgoingHeaderCleaningParam -whatif:$whatif # -ErrorAction Stop |Out-Null
        New-TransportRule @decryptedHeaderCleaningParam -Whatif:$Whatif # -ErrorAction Stop |Out-Null
        New-TransportRule @encryptedHeaderCleaningParam -Whatif:$Whatif # -ErrorAction Stop |Out-Null
        New-TransportRule @InternalParam -Whatif:$Whatif # -ErrorAction Stop |Out-Null
        New-TransportRule @OutboundParam -Whatif:$Whatif # -ErrorAction Stop |Out-Null
        New-TransportRule @InboundParam -Whatif:$Whatif # -ErrorAction Stop |Out-Null
    }
}
