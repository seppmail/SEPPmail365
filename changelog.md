# CHANGES in SEPPmail365 Module

## ANNOUNCED FOR 28.November 2022 - Releasenotes 1.2.5

### BREAKING Changes

- Add Support for ExchangeOnlineManagement 3.0.0
- No more Windows Powershell Support - PowerShell CORE Only !
- New-SM365Rules: Transport rules will be setup DISABLED by default
- New-SM365Rules: Domains specified are not the exclusion, you need to specify the INCLUDE-list (similar to the cloud module)

### Enhancements

- New-SM365ExoReport similar to cloud-module
- Test-SM365ConnectionStatus similar to cloud-module
- Removed Backup and Setup CmdLets
- Add test for external name resolution and write error if it fails.

## September 2022 - Releasenotes 1.2.3

- Add rule for setting identification header
- Add generating a Code for identification

## January 2022 - Releasenotes 1.2.2

- Add "Update available" notification on module startup
- Create Outbound-Connector first to avoid Excange Online warning message
- Remove-SM365rules now removes also rules created with earlier module versions

## November 2021 - Releasenotes 1.2.1

Version 1.2 of this module is a release focussed on 4 topics:

- Simplification based on best practices
- More flexible connectivity for test and demo environments
- Make the configuration easier to use and read
- Adapt to current Exchange Online Features

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

| Option      | Parameter in New-SM365connectors | SEPPmail Addressed by      | TLS Security | Certificate security  |
| ----------- | -------------------------------- | -------------------------- | ------------ | --------------------- |
| default     | --no parameter required--        | Full Qualified Domain Name | yes          | trusted               |
| self signed | -AllowSelfSignedCertificates     | Full Qualified Domain Name | yes          | trusted & self signed |
| no TLS      | -NoOutboundTlsCheck              | Full Qualified Domain Name | no           | none                  |
| IP          | -SEPPmailIP                      | IP Address                 | no           | none                  |

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
