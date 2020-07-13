[CmdLetBinding()]
$ModulePath = Split-Path ((Get-Module -Name SMExo -Listavailable).Path) 
. $ModulePath\Public\SmExoCmdLets.ps1
#. $ModulePath\Private\SmExOPrivate.ps1
If (!(Get-Module -Name 'tmp_*')) {
    Write-Warning "It seems you are not connected to Exchange Online. Connect using 'Connect-ExchangeOnline'"
}