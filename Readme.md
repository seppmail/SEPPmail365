- [Abstract](#orgb461d83)
- [Prerequisites](#org1cda273)
- [Module Installation](#org69a6365)
- [Preparation](#org8465bc6)
- [Exchange Online Settings](#org7b14410)
  - [Connectors](#org8df1044)
    - [Inbound](#org6812cbc)
    - [Outbound](#orgf29a056)
  - [Transport Rules](#org5f5773a)
- [SEPPmail365 CmdLets](#org61f8551)
  - [New-SM365Connectors](#org81bcd1b)
  - [Set-SM365Connectors](#orgbf5a06d)
  - [Remove-SM365Connectors](#org9e602cc)
  - [New-SM365Rules](#org8727a2b)
  - [Set-SM365Rules](#orgbf76863)
  - [Remove-SM365Rules](#orgb21246d)
  - [Backup-SM365Connectors](#orgd0f69e1)
  - [Backup-SM365Rules](#orgf1cbf2d)
  - [New-SM365ExOReport](#orgd6f6692)
- [Examples](#org467c684)

<div class="html">

</div>

<div class="html">

</div>

<p id="document-version">Module Version: 1.1.0<br>
<a href="https://www.seppmail.ch">SEPPmail Home Page</a></p>


<a id="orgb461d83"></a>

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


<a id="org1cda273"></a>

# Prerequisites

The module requires at least PowerShell 5.1 (64bit) and the  
[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module of version 1.0.1 or higher.  

Future versions of the [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module should also work.  


<a id="org69a6365"></a>

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


<a id="org8465bc6"></a>

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


<a id="org7b14410"></a>

# Exchange Online Settings


<a id="org8df1044"></a>

## Connectors

For the setup to work, two connectors have to be created.  
An inbound connector (routing from the SEPPmail appliance(s) to Exchange Online)  
and an outbound connector (routing from Exchange Online to the SEPPmail  
appliance(s))  

Please note, that the terms *inbound* and *outbound* are used from an Exchange  
Online point of view, i.e an inbound connector specifies how a connection from  
an external entity is made to Exchange.  
If you're looking at the terms from a mail flow point of view, they are actually  
reversed (i.e. an inbound connector routes outgoing mails).  


<a id="org6812cbc"></a>

### Inbound

Exchange Online CmdLet: [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)  
SEPPmail CmdLet: [New-SM365Connectors](#org81bcd1b)  

**Parameters in Use:**  

`-AssociatedAcceptedDomains`  
Restricts sender domains, the connector accepts mails from.  
Set via: `-SenderDomains`  
Default: `$null`  

`-SenderDomains`  
Restricts sender domains, the connector accepts mails from.  
Set via: `-SenderDomains`  
Default: `*`  

`-ConnectorSource`  
Specifies how the connector has been created.  
Set via: <none>  
Default: `Default` (meaning *manually created*)  

`-ConnectorType`  
Specifies if the connector handles mails external or internal to your  
organization.  
Set via: <none>  
Default: `OnPremises`  

`-EFSkipIPs`  
IPs for which enhanced filtering should be skipped.  
Set via: `-TrustedIPs`  
Default: `$null`  

`-EFSkipLastIP`  
Automatically skips enhanced filtering the last connecting IP.  
Set to `$false` if the parameter `-TrustedIPs` is used.  
Set via: <none>  
Default: `$true`  

`-EFUsers`  
Specifies recipients that enhanced filtering applies to.  
Set via: <none>  
Default: `$null` (applies to all recipients)  

`-RequireTls`  
TLS transmission is required for this connector.  
Set via: <none>  
Default: `$true`  

`-RestrictDomainsToCertificate`  
Verify the TLS certificate's subject.  
Set via: <none>  
Default: `$true`  

`-RestrictDomainsToIPAddresses`  
Restrict incoming connections to these IP addresses.  
Set via: <none>  
Default: `$false`  

`-TlsSenderCertificateName`  
The subject of the SEPPmail appliance's TLS certificate.  
Set via: `-SEPPmailFQDN` or `-InboundTlsDomain`  
Default: <none>  

`-CloudServicesMailEnabled`  
Specifies, that this connector is used for hybrid mail flow, thus preserving  
internal Microsoft headers.  
Set via: <none>  
Default: `$true`  


<a id="orgf29a056"></a>

### Outbound


<a id="org5f5773a"></a>

## Transport Rules


<a id="org61f8551"></a>

# SEPPmail365 CmdLets

Version specific configuration can be requested via the `-Version` parameter.  

**Note about parameters:**  
All CmdLets support the PowerShell [common parameters](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7) `-Confirm`, `-Whatif`,  
`-Verbose`, etc.  


<a id="org81bcd1b"></a>

## New-SM365Connectors

**Synopsis:**  
Two connectors are required to route mail flow between the SEPPmail appliance  
and Exchange Online. This CmdLet will create the necessary connectors.  

**Parameter List:**  
`-SEPPmailFQDN [string] (mandatory)`  
The FQDN your SEPPmail appliance is reachable under.  

`-TrustedIPs [string[]] (optional)`  
If multiple SEPPmail appliances are in use, specify their IP addresses here, to  
exempt them from enhanced filtering (corresponds to the parameter `-EFSkipIPs`  
of [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)).  

`-SenderDomains [string[]] (optional)`  
Internal mail domains, the inbound connector will take emails from.  

`-RecipientDomains [string[]] (optional)`  
External mail domains, the outbound connector will send emails to.  

`-TlsDomain [string] (optional)`  
Subject the SEPPmail appliance's ssl certificate has been issued to.  
Default is to use the SEPPmailFQDN, but in case you're using a wildcard  
certificate you will need this parameter.  
This parameter applies to the inbound and outbound connector.  

`-InboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the inbound connector.  

`-OutboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the outbound connector.  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

**Examples:**  

```powershell
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com"
```

```powershell
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com" -TlsDomain "*.contoso.com"
```


<a id="orgbf5a06d"></a>

## Set-SM365Connectors

**Synopsis:**  
This CmdLet provides a method of updating the SEPPmail connectors.  

**Parameter List:**  
`-SEPPmailFQDN [string] (optional)`  
The FQDN your SEPPmail appliance is reachable under.  

`-TrustedIPs [string[]] (optional)`  
If multiple SEPPmail appliances are in use, specify their IP addresses here, to  
exempt them from enhanced filtering (corresponds to the parameter `-EFSkipIPs`  
of [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)).  

`-SenderDomains [string[]] (optional)`  
Internal mail domains, the inbound connector will take emails from.  

`-RecipientDomains [string[]] (optional)`  
External mail domains, the outbound connector will send emails to.  

`-TlsDomain [string] (optional)`  
Subject the SEPPmail appliance's ssl certificate has been issued to.  
Default is to use the SEPPmailFQDN, but in case you're using a wildcard  
certificate you will need this parameter.  
This parameter applies to the inbound and outbound connector.  

`-InboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the inbound connector.  

`-OutboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the outbound connector.  

`-SetDefaults [switch] (optional)`  
The default behaviour is to only set the provided parameters, but this switch  
causes all other parameters be set to the default values, provided by  
[New-SM365Connectors](#org81bcd1b).  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

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


<a id="org9e602cc"></a>

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


<a id="org8727a2b"></a>

## New-SM365Rules

**Synopsis:**  
Creates the required transport rules needed to correctly handle mails from and  
to the SEPPmail appliance.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

**Examples:**  

```powershell
New-SM365Rules
```


<a id="orgbf76863"></a>

## Set-SM365Rules

**Synopsis:**  
Updates the SEPPmail transport rules to the default values, or a specific  
version.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance.  

**Examples:**  

```powershell
# update rules to the latest version
Set-SM365Rules -Version Default
```


<a id="orgb21246d"></a>

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


<a id="orgd0f69e1"></a>

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


<a id="orgf1cbf2d"></a>

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


<a id="orgd6f6692"></a>

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


<a id="org467c684"></a>

# Examples