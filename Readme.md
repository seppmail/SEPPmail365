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

<p id="document-version">Module Version: 1.2.0<br>
<a href="https://www.seppmail.ch">SEPPmail Home Page</a></p>


<a id="orgeaf4ba8"></a>

# Abstract

The SEPPmail365 PowerShell module helps customers and partners to smoothly integrate  
their SEPPmail appliance with Exchange Online.  

Integration with Exchange Online requires the configuration of an inbound and  
outbound connector to route mails from Exchange Online to the appliance and  
vice versa, as well as transport rules for necessary mail flow control.
  
This module provides means to create and update connectors, rules, and  
backing up existing configuration, as well as generating a report about the  
current state of the Exchange Online environment.

## GENERAL NOTE
Please note that Exchange Online is a relatively fast paced environment and  
subject to change. In pratice that means that a working setup can suddenly stop  
behaving correctly, as soon as the cloud infrastructure has been updated.  
This may affect you and thus will require a certain amount of patience.  
We try to adapt to these changes ASAP, but can't guarantee that this module will  
be up to date immediately after Microsoft has deployed new changes.  

## November 2021 - Releasenotes 1.2:

Version 1.2 of this module is a release focussed on 3 topics
* Simplification based on best practices
* Make the configuration easier to read
* Adapt to Exchange Online Features


### Simplification based on best practices

1. The previous version worked pretty well for default configurations with a FQDN for the SEPPmail with a valid certificate. With version 1.2 we now add support for "Self-Signed Certificates" and the option to use also "No TLS verification" for outbound traffic. Even if this makes only sense in test and demo environments, or as a temporary solution, we added it to New-SM365Connectors.

Connector Settings offer the following options:

|Option| SEPPmail Addressed by|TLS Security|Certificate security |
|---------------|--|--|---------|
|default| Full Qualified Domain Name|yes|trusted |
|self signed| Full Qualified Domain Name|yes|trusted & self signed |
|no TLS| Full Qualified Domain Name|no|none|
|IP| IP Address|no|none|


**NOTE for PRODUCTION ENVIRONMENTS: Always procect the traffic with TLS and do not use Self-Signed Certificates !**  

2. The CmdLet Set-SM365Connectors is just an alias to New-SM365Connectors. Using Set-SM365Connectors just recreates the connectors based on new parameter settings with one Appliance. 
If you need more advanced configurations for your connectors like multiple IP Addresses or a SEPPmail CLuster, add this configuration after the initial creation in the UI or with the native PowerShell CmdLets.

3. **Adapt to Exchange Online Features** - 
Exchange Online allows it now to add IP Addresses in a Whitelist (Hosted Connection Filter Policy), that makes our previous SPF Rules unneccesary. Beginning from version 1.2 **we add the SEPPmail to this list by default**.  This tells Exchange online, that everything coming from SEPPmail is trusted (as it was scanned by M365 Defenders already). This policy is - as far as we investigated available for Exchange Online Plans 1 and 2 (and hopefully its successors). When using the -Option "NoAntiSpamWhiteListing" Parameter in New-SM365Connectors, this behavior can be surpressed.

## No SPF Rules anymore
The SPF Mailflow-rules which we used so far as a workaround to avoid SPAM are dremoved.

# Prerequisites

The module requires at least PowerShell 5.1 (64bit) and the  
[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/2.0.5) module of version 2.0.5 or higher.  

The module was developed on macOS and runs also on PowerShell Core 7.1.5+

<a id="org88ae7e3"></a>

# Module Installation

Installing the module from the PowerShellGallery is as easy as executing:  

```powershell
Install-Module "SEPPmail365"
```

If you want to use the newest (maybe instable) version, that might not be production ready  
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

The CmdLet resolves the SEPPmail-FQDN to check if the DNS entry is correct. **DNS-queries must NOT be done internally**, otherwise internal IP addresses may be used in Exchange Online config settings.

**Parameter List:**  
`-SEPPmailFQDN [string] (mandatory)`  
The FQDN your SEPPmail appliance is reachable under.  

`-SEPPmailIP [string] (mandatory)`  
The IP Address your SEPPmail appliance is reachable under.  

`-AllowSelfSignedCertificates (optional)`  
If you have a SEPPmail environment with a self signed certificate (demo and test) use this parameter.

`-NoOutBoundTlsCheck (optional)`  
Disable TSL connectivity on outbound TLS.

`-Option [ConfigOption] (optional)`  
Config options for specific variants. 

`-Disabled [Switch] (optional)`  
Allows for the connectors to be created in an inactive state, in case you just  
want to prepare your environment.

**Examples:**  

```powershell
New-SM365Connectors -SEPPmailFQDN "securemail.contoso.com"
```

```powershell
New-SM365Connectors -SEPPmailIP "123.124.125.126"
```

```powershell
New-SM365Connectors -SEPPmailFQDN "securemail.contoso.com" -noOutBoundTlsCheck
```

```powershell
New-SM365Connectors -SEPPmailFQDN "securemail.contoso.com" -AllowSelfSignedCertificates
```

```powershell
# Create the new connectors in an inactive state
New-SM365Connectors -SEPPmailFQDN "securemail.contoso.com" -disabled
```


<a id="org98c55e6"></a>

## Set-SM365Connectors

**Synopsis:**  
This CmdLet is **an alias** for New-SM365Connectors. This was an active design decision to bring all the logic of connector functionality into one commandlet. If you need to adapt existing connectors use either the web interface of the native Exchange Online CmdLets Set-InboundConnector or Set-OutBoundConnector.

<a id="org65d7b60"></a>

## Remove-SM365Connectors

**Synopsis:**  
Removes the SEPPmail inbound and outbound connector.  
Please note that connectors can only be removed, if no transport rules reference it. If this is not the case you will get an error message.  

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
New-SM365Rules -disabled
```

```powershell
# Create rules and exclude domains
New-SM365Rules -ExcludeEmailDomain 'contosode.onmicrosoft.com','testdomain.de'
```



<a id="org22b1f28"></a>

## Remove-SM365Rules

**Synopsis:**  
Removes the SEPPmail transport rules.  

**Examples:**  

```powershell
Remove-SM365Rules -Whatif
```


<a id="orgd3308b0"></a>

## Backup-SM365Connectors

**Synopsis:**  
Performs a backup of all connectors found to individual json files for every connector. **There is no Restore-SM365Connectors** CmdLets, because the JSON provided cannot be used to recreate connectors. The backup JSON-files can be used as written source to recreate connectors with the native Exchange Online CmdLets or the SEPPmail365 module.  

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
Performs a backup of all transport rules found to individual json files for every rule.  **There is no Restore-SM365rules** CmdLets, because the JSON provided cannot be used to recreate connectors. The backup JSON-files can be used as written source to recreate rules with the native Exchange Online CmdLets. 

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the transport rule information.  

**Examples:**  

```powershell
Backup-SM365Rules -OutFolder C:\Temp
```

### A note on RESTORING Connectors and Rules

The native Exchange Online CommandLets provide a way to read conector/rule settings, but emit everything a connector/rule contains. This makes it great to rebuild by hand, but difficult to build valid connector rule combinations in software.

For Restore, we recommend to manuelly read the JSON-exports and build the connectors/rules out od this information from scratch.

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

If you're starting with a clean cloud environment, then you will need to issue two commands.  

The first one is to create the required connectors:  

```powershell
$seppFqdn = "securemail.contoso.com"
$tlsDomain = $seppFqdn # change this if the SSL certificate's subject differs from the hostname

New-SM365Connectors `
  -SEPPmailFQDN $seppFqdn `
  -Verbose
```

The second one is to create the required transport rules:  

```powershell
# No more parameters required (:
New-SM365Rules
```

```powershell
# to create disaled rules
New-SM365Rules -Disabled
```



<a id="org6e80204"></a>

## Upgrading from a previous version

Backup and recreate Connectors and Rules. 

--- end of file ---