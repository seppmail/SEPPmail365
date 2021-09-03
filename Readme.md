- [Abstract](#orgeaf4ba8)
- [Prerequisites](#org8f4a707)
- [Module Installation](#org88ae7e3)
- [Preparation](#orgdd7c058)
- [SEPPmail365 CmdLets](#org003f0ef)
  - [Test-SM365ConnectionStatus](#orgf8badef)
  - [New-SM365Connectors](#orgb92507f)
  - [Set-SM365Connectors](#org98c55e6)
  - [Remove-SM365Connectors](#org65d7b60)
  - [New-SM365Rules](#org3980fbe)
  - [Set-SM365Rules](#orgf4ad813)
  - [Remove-SM365Rules](#org22b1f28)
  - [Backup-SM365Connectors](#orgd3308b0)
  - [Backup-SM365Rules](#orgdb40348)
  - [New-SM365ExOReport](#org6f463cb)
- [Examples](#org6dc166f)
  - [First Use](#org0d16067)
  - [Upgrading from a previous version](#org6e80204)

<p id="document-version">Module Version: 1.1.3<br>
<a href="https://www.seppmail.ch">SEPPmail Home Page</a></p>


<a id="orgeaf4ba8"></a>

# Abstract

The SEPPmail365 PowerShell module helps customers and partners to smoothly integrate  
their SEPPmail appliance with Exchange Online.  

Integration with Exchange Online requires the configuration of an inbound and  
outbound connector, to route mails from Exchange Online to the appliance and  
vice versa, as well as transport rules for necessary mail manipulation (e.g.  
headers).  

This module provides means to create and update default connectors, rules, and  
backing up existing configuration, as well as generating a report about the  
current state of the environment.  

**GENERAL NOTE:**  
Please note that Exchange Online is a relatively fast paced environment and  
subject to change. In pratice that means that a working setup can suddenly stop  
behaving correctly, as soon as the cloud infrastructure has been updated.  
This may affect you and thus will require a certain amount of patience.  
We try to adapt to these changes ASAP, but can't guarantee that this module will  
be up to date immediately after Microsoft has deployed new changes.  

**A NOTE ON SPAM:**  
As per the previous note you might experience spam after deploying the default  
set of transport rules.  
If that is the case please try to switch the transport rules to the version  
`WithSpf` as follows:  

```powershell
Set-SM365Rules -Version WithSpf
```


<a id="org8f4a707"></a>

# Prerequisites

The module requires at least PowerShell 5.1 (64bit) and the  
[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module of version 1.0.1 or higher.  

Future versions of the [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module should also work.  


<a id="org88ae7e3"></a>

# Module Installation

Installing the module is as easy as executing:  

```powershell
Install-Module "SEPPmail365"
```

If you want to use the newest version, that might not be production ready  
yet, go to the [SEPPmail365 Github repository](https://github.com/seppmail/SEPPmail365), download the source code and  
execute:  

```powershell
Import-Module "C:\path\to\module\SEPPmail365.psd1"
```


<a id="orgdd7c058"></a>

# Preparation

Prior to using this module you need to connect to your Exchange Online  
organization.  
Use either one of the following commands, depending on whether multi factor  
authentication is enabled for your account or not:  

**Without multi factor authentication:**  

```powershell
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true
```

**With multi factor authentication:**  

```powershell
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName frank@contoso.com -ShowProgress $true
```


<a id="org003f0ef"></a>

# SEPPmail365 CmdLets

Version specific configuration can be requested via the `-Version` parameter.  

**Note about parameters:**  
All CmdLets support the PowerShell [common parameters](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7) `-Confirm`, `-Whatif`,  
`-Verbose`, etc.  


<a id="orgf8badef"></a>

## Test-SM365ConnectionStatus

**Synopsis:**  
Internally used to check whether the user is connected to Exchange Online, and  
trigger the respective login prompt, if it is an interactive session.  

Returns `$true/$false` depending on whether the user is connected or not, or  
throws an exception if the ExchangeOnlineManagement module could not be found.  

**Parameter List:**  
None  

**Examples:**  

```powershell
Test-SM365ConnectionStatus
```


<a id="orgb92507f"></a>

## New-SM365Connectors

**Synopsis:**  
Two connectors are required to route mail flow between the SEPPmail appliance  
and Exchange Online. This CmdLet will create the necessary connectors.  

**Parameter List:**  
`-SEPPmailFQDN [string] (mandatory)`  
The FQDN your SEPPmail appliance is reachable under.  

`-TrustedIPs [string[]] (optional)`  
The IP address(es) of your SEPPmail appliance(s). If not provided, the CmdLet  
will attempt to resolve the `-SEPPmailFQDN` and add the IP addresses automatically.  

`-SenderDomains [string[]] (optional)`  
Internal mail domains, the inbound connector will take emails from.  

`-RecipientDomains [string[]] (optional)`  
External mail domains, the outbound connector will send emails to.  

`-TlsDomain [string] (optional)`  
Subject the SEPPmail appliance's ssl certificate has been issued to.  
Default is to use the SEPPmailFQDN, but in case you're using a wildcard  
certificate (or the subject differs from the hostname) you will need this parameter.  
This parameter applies to the inbound and outbound connector.  

`-InboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the inbound connector.  

`-OutboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the outbound connector.  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

`-Enabled [Switch] (optional)`  
Allows for the connectors to be created in an inactive state, in case you just  
want to prepare your environment.  

**Examples:**  

```powershell
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com"
```

```powershell
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com" -TlsDomain "*.contoso.com"
```

```powershell
# Create the new connectors in an inactive state
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com" -Enabled:$false
```


<a id="org98c55e6"></a>

## Set-SM365Connectors

**Synopsis:**  
This CmdLet provides a method of updating the SEPPmail connectors.  

**Parameter List:**  
Same as [New-SM365Connectors](#orgb92507f), and additionally:  

`-SetDefaults [switch] (optional)`  
The default behaviour is to only set the provided parameters, but this switch  
causes all other parameters be set to the default values, provided by  
[New-SM365Connectors](#orgb92507f).  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

`-Enabled [Switch] (optional)`  
Sets the connectors to an inactive state.  

**Examples:**  

```powershell
# update smart host information
Set-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com"
```

```powershell
# only update tls domain for the inbound connector
Set-SM365Connectors -InboundTlsDomain "*.contoso.com"
```

```powershell
# set everything else back to default values
Set-SM365Connectors -SetDefaults
```


<a id="org65d7b60"></a>

## Remove-SM365Connectors

**Synopsis:**  
Removes the SEPPmail inbound and outbound connector.  
Please note that connectors can only be removed, if no transport rules reference  
it.  

**Parameter List:**  
No additional parameters.  

**Examples:**  

```powershell
# see which connectors would be deleted
Remove-SM365Connectors -Whatif
```

```powershell
# request confirmation before every deletion
Remove-SM365Connectors -Confirm
```


<a id="org3980fbe"></a>

## New-SM365Rules

**Synopsis:**  
Creates the required transport rules needed to correctly handle mails from and  
to the SEPPmail appliance.  

**Parameter List:**  
`-PlacementPriority [SM365.PlacementPriority] (optional)`  
Specifies whether new rules should be put in front or behind existing transport  
rules (if any). If not provided and in an interactive session, the CmdLet will  
ask for this information interactively.  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

`-Enabled [Switch] (optional)`  
Allows for the rules to be created in an inactive state, in case you just  
want to prepare your environment.  
**Examples:**  

```powershell
New-SM365Rules
```

```powershell
# Create the transport rules in an inactive state
New-SM365Rules -Enabled:$false
```


<a id="orgf4ad813"></a>

## Set-SM365Rules

**Synopsis:**  
Updates the SEPPmail transport rules to the default values, or a specific  
version.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance.  

`-FixMissing [switch] (optional)`  
Indicates that missing SEPPmail transport rules should be created with their  
default values.  

**Examples:**  

```powershell
# update rules to the latest version and create missing ones
Set-SM365Rules -FixMissing
```


<a id="org22b1f28"></a>

## Remove-SM365Rules

**Synopsis:**  
Removes the SEPPmail transport rules.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmaill appliance.  

**Examples:**  

```powershell
Remove-SM365Rules -Whatif
```


<a id="orgd3308b0"></a>

## Backup-SM365Connectors

**Synopsis:**  
Performs a backup of all connectors found to individual json files for every connector.  

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the connector information.  

**Examples:**  

```powershell
Backup-SM365Connectors -OutFolder C:\Temp
```


<a id="orgdb40348"></a>

## Backup-SM365Rules

**Synopsis:**  
Performs a backup of all transport rules found to individual json files for  
every rule.  

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the transport rule information.  

**Examples:**  

```powershell
Backup-SM365Rules -OutFolder C:\Temp
```


<a id="org6f463cb"></a>

## New-SM365ExOReport

**Synopsis:**  
Creates an HTML report about the current Exchange Online environment.  

**Parameter List:**  
`-FilePath [string] (mandatory)`  
Path of the HTML report on disk.  

**Examples:**  

```powershell
New-SM365ExOReport -FilePath C:\Temp\ExOReport.html
```


<a id="org6dc166f"></a>

# Examples


<a id="org0d16067"></a>

## First Use

If you're starting with a clean cloud environment, then you will need to issue  
two commands.  

The first one is to create the required connectors:  

```powershell
$seppFqdn = "securemail.contoso.com"
$seppIPs = [System.Net.Dns]::GetHostAddresses($seppFqdn) | %{$_.IPAddressToString}
$tlsDomain = $seppFqdn # change this if the SSL certificate's subject differs from the hostname

# change this if you're using separate appliances for sending/receiving to/from Exchange Online
$inboundTlsDomain = $tlsDomain 
$outboundTlsDomain = $tlsDomain

New-SM365Connectors `
  -SEPPmailFQDN $seppFqdn `
  -TrustedIPs $seppIPs `
  -InboundTlsDomain $inboundTlsDomain `
  -OutboundTlsDomain $outboundTlsDomain `
  -Verbose
```

The second one is to create the required transport rules:  

```powershell
# No more parameters required (:
New-SM365Rules
```


<a id="org6e80204"></a>

## Upgrading from a previous version

Usually it should be enough to upgrade the settings of existing connectors and  
transport rules to the newest version like this:  

**Note:**  
Depending on your DNS settings, it might be necessary to add the external IP  
address of your appliance, as seen by Exchange Online, to the parameter  
`-TrustedIPs`.  
The CmdLet will automatically try to resolve the FQDN of your appliance, but  
depending on whether this yields an internal or external IP address, SPF checks  
might still fail, because Exchange Online doesn't know about the correct IP  
address.  

```powershell
# This will update the connectors to the latest settings.
# If you have to change additional settings you can just append parameters as used by New-SM365Connectors
# The CmdLet will then combine the default and your settings.
Set-SM365Connectors -SetDefaults -Verbose
```

After that you will have to ugprade the transport rules to the newest version:  

```powershell
# -FixMissing causes non existent rules to be created with default settings
Set-SM365Rules -FixMissing -Verbose
```

Your environment has now been upgraded to the newest version.  
If you're experiencing problems, or the upgrade doesn't work, you will  
unfortunately have to delete the connectors and rules and create them again.  

If that still doesn't work, please leave us a bug report!