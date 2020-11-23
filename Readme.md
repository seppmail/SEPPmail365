- [Abstract](#org502d0b5)
- [Prerequisites](#orgdbb67b3)
- [Module Installation](#orgd372e42)
- [Preparation](#orga8dea90)
- [Exchange Online Settings](#orgaa93821)
  - [Connectors](#orgf19ed8a)
    - [Inbound](#orgf5e49fe)
    - [Outbound](#org30639f2)
  - [Transport Rules](#org9da5b37)
- [SEPPmail365 CmdLets](#org86f07b3)
  - [New-SM365Connectors](#orgf4128c0)
  - [Set-SM365Connectors](#org455dc22)
  - [Remove-SM365Connectors](#orgf70c792)
  - [New-SM365Rules](#orge370bcc)
  - [Set-SM365Rules](#org105a8e2)
  - [Remove-SM365Rules](#orgc339eb1)
  - [Backup-SM365Connectors](#org7fc8f0d)
  - [Backup-SM365Rules](#orgff3b440)
  - [New-SM365ExOReport](#org9eec97d)
- [Examples](#org55895c6)

<div class="html">

</div>

<div class="html">

</div>

<p id="document-version">Module Version: 1.1.0<br>
<a href="https://www.seppmail.ch">SEPPmail Home Page</a></p>


<a id="org502d0b5"></a>

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


<a id="orgdbb67b3"></a>

# Prerequisites

The module requires at least PowerShell 5.1 (64bit) and the  
[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module of version 1.0.1 or higher.  

Future versions of the [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module should also work.  


<a id="orgd372e42"></a>

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


<a id="orga8dea90"></a>

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


<a id="orgaa93821"></a>

# Exchange Online Settings


<a id="orgf19ed8a"></a>

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


<a id="orgf5e49fe"></a>

### Inbound

Exchange Online CmdLet: [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)  
SEPPmail CmdLet: [New-SM365Connectors](#orgf4128c0)  

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


<a id="org30639f2"></a>

### Outbound


<a id="org9da5b37"></a>

## Transport Rules


<a id="org86f07b3"></a>

# SEPPmail365 CmdLets

Version specific configuration can be requested via the `-Version` parameter.  

**Note about parameters:**  
All CmdLets support the PowerShell [common parameters](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7) `-Confirm`, `-Whatif`,  
`-Verbose`, etc.  


<a id="orgf4128c0"></a>

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


<a id="org455dc22"></a>

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
[New-SM365Connectors](#orgf4128c0).  

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


<a id="orgf70c792"></a>

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


<a id="orge370bcc"></a>

## New-SM365Rules

**Synopsis:**  
Creates the required transport rules needed to correctly handle mails from and  
to the SEPPmail appliance.  

**Parameter List:**  
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


<a id="org105a8e2"></a>

## Set-SM365Rules

**Synopsis:**  
Updates the SEPPmail transport rules to the default values, or a specific  
version.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance.  

`-Enabled [Switch] (optional)`  
Sets the transport rules to an inactive state.  
**Examples:**  

```powershell
# update rules to the latest version
Set-SM365Rules -Version Default
```

```powershell
# Set the tranport rules to an inactive state
Set-SM365Rules -Enabled:$false
```


<a id="orgc339eb1"></a>

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


<a id="org7fc8f0d"></a>

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


<a id="orgff3b440"></a>

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


<a id="org9eec97d"></a>

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


<a id="org55895c6"></a>

# Examples