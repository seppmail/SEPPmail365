# Abstract

The SEPPmail365 PowerShell module helps customers and partners to smoothly integrate their SEPPmail appliance with Exchange Online.  

Integration with Exchange Online requires the configuration of an inbound and outbound connector to route mails from Exchange Online to the appliance and vice versa, as well as transport rules for necessary mail flow control via X-headers.
  
This module provides means to create and update connectors, rules, and backing up existing configuration, as well as generating a report about the current state of the Exchange Online environment.

## GENERAL NOTE

Please note that Exchange Online is a fast paced environment and subject to change. In pratice that means that a working setup can suddenly stop behaving correctly, as soon as the cloud infrastructure has been updated. This may affect you and thus will require a certain amount of patience.

We try to adapt to these changes ASAP, but can't guarantee that this module will be up to date immediately after Microsoft has deployed new changes.  

## November 2021 - Releasenotes 1.2.x

Version 1.2 of this module is a release focussed on 4 topics:

* Simplification based on best practices
* More flexible connectivity for test and demo environments
* Make the configuration easier to use and read
* Adapt to current Exchange Online Features

### Simplification based on best practices

#### Only parameters that make sense

In Version 1.1.x we had a couple of CmdLet parameters which confused people like the domain-specific parameter in connectors. So there will **only be parameters which actually make sense** to integrate SEPPmail into your Exchange Online environment in most customer cases. 

#### Domain limitation only in Transport-Rules

With this version we **do not limit domains in the connector** in general. But you are able to exclude E-Mail domains in transport rules.

#### Alias-CmdLets for Set-*

New-SM365Connectors and New-SM365Rules contain a lot of logic to prepare the Exchange Online environment as good as possible. The according "Set-" commandlets are now simply aliases for the "New-*" Commandlets. So whenever you "Set-" something, you simply recreate it.

#### No Restore

Having a backup of a configuration makes sense for many reasons (documentation, ...). Our Backup-Something CmdLets let you write connector and rules-configs to JSON files.

**Why is there no restore ?** JSON files are great to read but terrible to use for connector and rule recreation. To avoid mistakes and errors there is no Restore-Something CmdLet. If you need to restore some settings, read the JSON file and restore with the New-* CmdLets.

#### General note on simplification

As this PowerShell module is just a wrapper around the ExchangeOnline PowerShell Module, you still have the option to adjust the settings of connectors and rules by yourself with the ExchangeOnline PowerShell Module or via the Exchange-Admin Web-interface (https://admin.microsoft.com)

### More fliexible connectivity for test and demo environments

The previous version worked pretty well for default configurations with a FQDN for the SEPPmail with a valid certificate. With version 1.2.x we now add support for "Self-Signed Certificates" and the option to use also "No TLS verification" for outbound traffic. Even if this makes only sense in test and demo environments, or as a temporary solution, we added it to New-SM365Connectors.

Connector Settings offer the following options:

|Option|Parameter in New-SM365connectors| SEPPmail Addressed by|TLS Security|Certificate security |
|---------------|----------|--|--|---------|
|default|--no parameter required--| Full Qualified Domain Name|yes|trusted |
|self signed|-AllowSelfSignedCertificates| Full Qualified Domain Name|yes|trusted & self signed |
|no TLS|-NoOutboundTlsCheck| Full Qualified Domain Name|no|none|
|IP|-SEPPmailIP| IP Address|no|none|

**NOTE for PRODUCTION ENVIRONMENTS: Always procect the traffic with TLS and do not use Self-Signed Certificates !**  

The CmdLet Set-SM365Connectors is just an alias to New-SM365Connectors. Using Set-SM365Connectors just recreates the connectors based on new parameter settings with one Appliance.

If you need more advanced configurations for your connectors like multiple IP addresses or a SEPPmail cluster, add this configuration after the initial creation in the UI or with the native PowerShell CmdLets.

### Adapt to Exchange Online Features

#### Anti-SPAM IP Whitelisting

Exchange Online allows it now to add IP Addresses in a Whitelist (Hosted Connection Filter Policy), that makes our previous SPF Rules unneccesary. Beginning from version 1.2 **we add the SEPPmail to this list by default**.  This tells Exchange Online, that everything coming from SEPPmail is trusted (as it was scanned by M365 Defenders already). This policy is - as far as we investigated - available for Exchange Online Plans 1 and 2 (and hopefully its successors). 

To surpress this behavior use the -Option "NoAntiSpamWhiteListing" Parameter in New-SM365Connectors.
(Thanks to Alexander Tschanz from Smart-IT Swizerland for this hint!)

### No SPF Rules anymore

The SPF mailflow-rules which we used so far as a workaround to avoid SPAM are removed.

### No EFSKIP connection parameters in Connectors

The whole SPAM-configuration is simplified now and we do not need to configure Enhanced-Filtering (EF...) in connectors.

# Prerequisites

The module requires at least PowerShell 5.1 (64bit) and the  
[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/2.0.5) module of version 2.0.5 or higher.  

The module was developed on macOS and runs also on PowerShell Core 7.1.5+

_Note on PowerShell on debian_: There are scenarios where module installation fails with an error on incorrect module maifest. We are currently investigating this. Please try to run it on PowerShell Core on Windows or macOS.

_Note on Windows PowerShell_: Make sure you have the latest version of PowerShellGet installed.

```
Install-Module PowerShellGet -Scope CurrentUser
```

# Module Installation

## Installation on Windows

To installing execute:

```powershell
Install-Module "SEPPmail365"
```

## Installation on macOS and Linux

In addition to the main module you need to add PSWSMan which adds WSMan client libraries to linux and macOS for remote connectivity to Exchange Online.

```powershell
# Do this OUTSIDE Powershell in the shell !
sudo pwsh -command 'Install-Module PSWSMan' # Read more on this here https://github.com/jborean93/omi
sudo pwsh -Command 'Install-WSMan'
```

## Prereleases

If you want to use the newest version, that might not be production ready
yet, go to the [SEPPmail365 Github repository](https://github.com/seppmail/SEPPmail365), download the source code and execute:  

```powershell
Import-Module "C:\path\to\module\SEPPmail365.psd1"
```

# Preparation

Prior to using this module you need to connect to your Exchange Online  
organization.  
Use either one of the following commands, depending on whether multi factor  
authentication is enabled for your account or not:  

**Without multi factor authentication:**  

```powershell
Import-Module ExchangeOnlineManagement
$UserCredential = Get-Credential #Enter Exchange Admin userName and Password
Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true

# If you have stored your credentials in Secretmanagement it would read:
Connect-ExchangeOnline -Credential (Get-Secret mycredentials) -ShowProgress $true
```

**With multi factor authentication:**  

```powershell
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName frank@contoso.com -ShowProgress $true
```

**With DEVICE Login:**  

```powershell
Import-Module ExchangeOnlineManagement
# Login to the Exchange Environment with your Web-Browser
Connect-ExchangeOnline -Device
# Follow the instructions.
```


<a id="org003f0ef"></a>

# Setup SEPPmail with Exchange online

Version specific configuration can be requested via the `-Version` parameter.  

**Note about parameters:**  
All CmdLets support the PowerShell [common parameters](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7) `-Confirm`, `-Whatif`,  
`-Verbose`, etc.  


## 1 - Test-SM365ConnectionStatus

**Synopsis:**  
Internally used to check your conenction status to Exchange Online..  

Returns `$true` if you are connected and throws an exception if the connection is not ready.  

**Parameter List:**  
None  

**Examples:**  

```powershell
Test-SM365ConnectionStatus
```

<a id="orgb92507f"></a>

## 2 - Before you change something

### Check existing SEPPmail Rules and Connectors

```powershell
Get-SM365Rules # Shows existing SEPPmail Rules
Get-SM365Connectors # Shows existing SEPPmail Connectors
```

### Cleanup environment

```powershell
Remove-SM365Setup # Removes SEPPmail Rules and Connectors
(Get-HostedConnectionFilterpolicy).IpAllowList # Show existing IP Whitelist
```

### Report on Exchange Online Environment

```powershell
New-SM365ExOReport -FilePath /Users/roman/Desktop/Exorep0812.html
```

## 3 - Build Connectivity between Exchange Online and SEPPmail

In this part we create inbound and outbound connectors to allow E-Mail-flow between Exchange Online and SEPPmail. You have several options to establish connectivity.

### Option 1: FQDN with full SSL and optional "AllowSelfsigned" Option

Full SSL is the recommended setting for production environments. All else is for test and demo purposes.

```powershell
New-SM365Connectors [-SEPPmailFQDN] <String> [-TLSCertificateName] <String> [-AllowSelfSignedCertificates] [-Option {None | AntiSpamWhiteList}] [-Disabled] [-WhatIf] 
[-Confirm] [<CommonParameters>]
```

### Option 2: FQDN and NoTLS Option

```powershell
New-SM365Connectors [-SEPPmailFQDN] <String> [-NoOutBoundTlsCheck] [-Option {None | AntiSpamWhiteList}] [-Disabled] [-WhatIf] [-Confirm] 
[<CommonParameters>]
```

### Option 3: IP Option

```powershell
New-SM365Connectors [-SEPPmailIP] <String> [-Option {None | AntiSpamWhiteList}] [-Disabled] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## 4 - Addin Mailflow-Rules

When inbound- and outbound connectors are established, we need mailflow rules to route E-Mails via the SEPPmail appliance if necessary. The New-SM365Rules CmdLet handles this for you. The most convenient way to do this is running the following code:
```powershell
New-SM365Rules 

# If you want to know what happens in detail, run

New-SM365Rules -Verbose

```


For more info read details below.

# Using the Commandlets

## New-SM365Connectors

**Synopsis:**  
Two connectors are required to route mail flow between the SEPPmail appliance  
and Exchange Online. This CmdLet will create the necessary connectors. 

The CmdLet resolves the SEPPmail-FQDN to check if the DNS entry is correct. **DNS-queries must NOT be done internally**, otherwise internal IP addresses may be used in Exchange Online config settings.

**Examples:**

### Default with IP

```powershell
New-SM365Connectors -SEPPmailIP '20.56.204.137'
Get-SM365Connectors
```

### DNS Check included

```powershell
New-SM365Connectors -SEPPmailFQDN wronghost.contoso.com
# This will raise an error because wronghost.west .... doesnt exist.
Get-SM365Connectors
```

### Default with FQDN and wildcard certificate

```powershell
New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -TLSCertificatename *.contoso.com
Get-SM365Connectors # Shows DomainValidation
```

### Default with FQDN and single host SSL certificate

```powershell
New-SM365Connectors -SEPPmailFQDN securemail.contoso.com
# Creates the connector using securemail.contoso.com as TLSCertificatename
Get-SM365Connectors # Shows DomainValidation
```

### FQDN with self-signed Certificate

```powershell
New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -AllowSelfSignedCertificates
Get-SM365Connectors # Shows EncryptionOnly
```

### FQDN with no outbound TLS

```powershell
New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -NoOutBoundTlsCheck
Get-SM365Connectors # Shows NO Tls
```

### FQDN with no outbound TLS and DISABLED

```powershell
New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -NoOutBoundTlsCheck -disabled
Get-SM365Connectors #Shows disabled
```

### Default with FQDN and no ANTISPAM Whitelisting

```powershell
New-SM365Connectors -SEPPmailFQDN securemail.contoso.com -Option NoAntiSpamWhiteListing
(Get-HostedConnectionFilterpolicy).IpAllowList # Show IP Whitelist
Get-SM365Connectors
```

## Set-SM365Connectors

**Synopsis:**  
This CmdLet is **an alias** for New-SM365Connectors. This was an active design decision to bring all the logic of connector functionality into one commandlet. If you need to adapt existing connectors, use either the web interface or the native Exchange Online CmdLets Set-InboundConnector or Set-OutBoundConnector.

## Cleaning Up Connectors

```powershell
Remove-SM365Connector -LeaveAntiSpamWhiteList
(Get-HostedConnectionFilterpolicy).IpAllowList # Show IP Whitelist
# or
Remove-SM365Connector # Cleans up IP Adresses from hosted connection filter policy
```

## Final Note on connectors-parameters you can use in **ANY** parameterset

```powershell
-disabled # Is be used to create "disabled" connectors. Makes sense for sensitive environment with step-by-step implementation.

-Option NoAntiSpamWhiteListing # Is used to disable whitelisting
```

**Note on Disable/enable:** To enable the connectors, either recreate them, use the admin interface of Exchange Online or use the native Exchange Online PowerShell CmdLets `Set-InboundConnector` and `Set-OutBoundConnector`.

## New-SM365Rules

**Synopsis:**  
Creates the required transport rules needed to correctly handle mails from and to the SEPPmail appliance.  

**Parameter List:**  
`-PlacementPriority [SM365.PlacementPriority] (optional)`  
Specifies whether new rules should be put in front or behind existing transport rules (if any). If not provided and in an interactive session, the CmdLet will ask for this information interactively.  

`-ExcludeEmailDomain [String[]] (optional)`  
Specifies one or more (comma-seperated) E-Mail domains that should be excluded in SEPPmail traffic. 


`-Disabled [Switch] (optional)`  
Allows for the rules to be created in an inactive state, in case you just want to prepare your environment.  

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

## Remove-SM365Rules

**Synopsis:**  
Removes the SEPPmail transport rules.  

**Examples:**  

```powershell
Remove-SM365Rules -Whatif
```

## Backup-SM365Connectors

**Synopsis:**  
Performs a backup of all connectors found to individual json files for every connector. **There is no Restore-SM365Connectors** CmdLet, because the JSON provided cannot be used to recreate connectors. The backup JSON-files can be used as written source to recreate connectors with the native Exchange Online CmdLets or the SEPPmail365 module.  

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the connector information.  

**Examples:**  

## BACKUP connector settings

```powershell
Backup-SM365Connectors -OutFolder /Users/roman/Desktop/ExoBackup
$backupfiles = Get-ChildItem /Users/roman/Desktop/ExoBackup
foreach ($file in $backupfiles) {Get-Content $file}
```

## Backup-SM365Rules

**Synopsis:**  
Performs a backup of all transport rules found to individual json files for every rule.  **There is no Restore-SM365rules** CmdLet, because the JSON provided cannot be used to recreate connectors. The backup JSON-files can be used as written source to recreate rules with the native Exchange Online CmdLets. 

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the transport rule information.  

**Examples:**  

```powershell
Backup-SM365Rules -OutFolder /Users/roman/Desktop/ExoBackup
$backupfiles = Get-ChildItem /Users/roman/Desktop/ExoBackup
foreach ($file in $backupfiles) {Get-Content $file}
```

### A note on RESTORING Connectors and Rules

The native Exchange Online CommandLets provide a way to read connector/rule settings, but emit everything a connector/rule contains. This makes it great to rebuild by hand, but difficult to build valid connector rule combinations in software.

For Restore, we recommend to manually read the JSON-exports and build the connectors/rules out of this information from scratch.

# Clustering and multi-host configurations

The current version only supports the usage of one SEPPmail per Connector-command. This might be an SMTP load-balancer for a cluster or a single node. If you want to use multiple hosts for Exchange Online-SEPPmail connectivity, create the connectors with one host and add the others in the UI or PowerShell CmdLets "Set-OutboundConnector" and "Set-InboundConnector". Furthermore adapt the Anti-SPAM Whitelist with "Set-HostedConnectionFilterPolicy".

# Upgrading from a previous version

1.) Backup and Connectors and Rules.

2.) Uninstall old SEPPMail365 Module

3.) Install newest module

4.) Remove SEPPmail Transport-Rules

5.) Remove SEPPmail Connectors

6.) Create Connectors

7.) Create Rules

--- end of file ---
