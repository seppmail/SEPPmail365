<#
.SYNOPSIS
    Example setup script that configures a SEPPmail with Exchange Online
.DESCRIPTION
    The script uses the module, connects to Exchange oNline and seps up the complete environment.
.EXAMPLE
    PS C:\> setupscript.ps1
    Explanation of what the example does
#>

# Dev Pfad einstellen
$env:PSModulePath = $env:PSModulePath + ';C:\Users\roman.THEGALAXY\GitRepo'

# SEPPmail365 DEMO

# Provide Admin-credential
$acred = Get-Credential

# Load module and conenct to exchange online
Import-Module SEPPmail365
Connect-Exchangeonline -Credential $acred

# Get a Statusreport
New-SM365ExOReport

Read-Host 'Continue and create connectors and rules ?'
# Create SPPmail connectors
New-SM365Connectors -SEPPmailFQDN secmail.contoso.de -InboundAcceptedDomains '*'

# Create SEPPmail rules
New-SM365Rules
