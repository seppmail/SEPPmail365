[CmdLetBinding()]
$ModulePath = Split-Path ((Get-Module -Name SEPPmail365 -Listavailable).Path) 
. $ModulePath\Public\SEPPMail365CmdLets.ps1
. $ModulePath\Private\SEPPMail365PrivateFunctions.ps1
If (!(Get-Module -Name 'tmp_*')) {
    Write-Warning "It seems you are not connected to Exchange Online. Connect using 'Connect-ExchangeOnline'"
}