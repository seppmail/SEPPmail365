# CHANGES in SEPPmail365 Module

## Version 1.2.9.1

Maintenance release of 1.2.9. This version was not correctly signed.

## Version 1.2.9: July 2025 - Fix for 100 inbound rule

### Inbound Rule 100 now matches on Header or Envelope

Based on SEPPmail internal ticket #1932 the value was changed from Header to HeaderorEnvelope

### Inbound Rule 100 checks for crypto-content by default

From now on, only E-Mails that require cryptographic handling are sent to the appliance.

### New Rule 110 for PGP detection and Header spoof-blocking

This new rule checks if there are any keywords in the subject ([secure] or [HIN]) and sends those e-Mails to the appliance to clean them before delivery to the mailbox. Furthermore it checks if there are e-mails that are cryptographically handled by PGP "BGP----..." and sends them to the appliance for decryption.

### New parameter -cryptocontentonly on new-sm365rules

This parameter is $true by default, so only e-mails that require appliance.based handling are sent to the appliance inbound. If you switch this OFF by setting it to $false, all E-Mails will be sent to the appliance.

### ExchangeOnlineManagement Module version changed to 3.8.0

## Version 1.2.8: Git Maintenance Release

## Version 1.2.7: November 2024 - Support ARC and CBC-Connectors

### Exchange online ARC requires EFSkipLastIP Setting #40957

The change to CBC requires the setting EFSkipLastIP to be set to true on the inbound connector and EFSKipIPs needs to be empty.
Module version 1.2.7 includes the inbound connector to have this setting set by default upon initial installation. Existing installations can be analyzed with the command "Get-SM365ARCSetting" and changed with "Set-SM365ARCSetting".

### ARC in MSP Setups required to use managed domain certificates - new parameter -CBCCertName

In ARC Setups with multiple customers using M365, the ExO-Inbound Connector requires to use the machine-certificate (securemail.greatmsp.com), but the ExO-Outbound Connector need to use the managed domain certificate, (i.e. manageddomain.fabrikam.com). Use the Parameter -CBCCertName to apply this configuration.

Example:

```powershell
New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.com' -TLSCertName '*.contoso.com' -CBCCertname '*.contoso.com'
```

See <https://docs.seppmail.com/de/09_ht_mso365_ssl_certificate.html?q=CBC> for the SEPPmail manual to setup CBC.

### Changed Default Auditseverity from "DoNotAudit" to "Low" to see details in MS-Logs

## Version 1.2.6: November 2023 - Info on Appliance Version 13.0.8++

### ARC-Sealing support

ARC-Sealing is the technology we leverage when a SEPPmail Appliance is connected in parallel to Exchange Online. Messages sent to the SEPPmail-Appliance for cryptographic processing are sealed with an signature so that failed SPF and DKIM checks can be avoided.

If you want to use ARC-Sealing, you have to configure trusted ARC-sealers in Exchange Online of the target tenant. Use the following command:

```powershell
Set-ARCconfig -Identity Default -ArcTrustedSealers 'yourseppmailfqdn.domain.tld'
```

More info and a detailed explanation of this CmdLet and its impacts van be found on [Microsoft learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-arc-configure?view=o365-worldwide).

See [Extended Release Notes](https://downloads.seppmail.com/extrelnotes/130/ERN13.0.html#arc-sealing--signing-of-emails-possible) and the [SEPPmail online manual](https://docs.seppmail.com/de/index.html?07_mi_06_ms_04_aemd__add-edit-managed-domain.htm#arcsettings)

### Certificate based connectors

Especially in MSP environments, its important to have a trustworthy connection between Exchange Online and a SEPPmail-Appliance. Therefore its now possible to create a separate SSL-certificate per managed domain.

If you do this you need to configure this specific certificate in the connectors.

In the OnPremise-Inbound Connector specify the certificate under "Edit sent email identity".
![Alt text](<./visuals/CBC-Inbound.png>)

The Outbound-Connector stays untouched, the certificate which is presented by the SEPPmail-Appliance is not relevant n this case because the appliance accepts traffic from Exchange online anyway.

See [Extended Release Notes](https://downloads.seppmail.com/extrelnotes/130/ERN13.0.html#separate-certificate-for-each-managed-domain-for-encrypting-smtp-traffic-via-tls) or the [SEPPmail online manual](https://docs.seppmail.com/de/index.html?07_mi_06_ms_04_aemd__add-edit-managed-domain.htm)


## March 2023 - Release Notes 1.2.6

## Maintenance

- Update Code Signing Certificate to avoid install-Module errors
- Removed Processor Architecture in manifest to avoid issues on macOS

## December 2022 - Release notes 1.2.5.1

### Enhancements

- CmdLet Help updated. i.e. Get-help New-SM365Rules will provide valuable details and examples now.

## Bugfixes

none

## Maintenance

- Typos in manifest cleared.

## November 2022 - Release notes 1.2.5

### BREAKING Changes

- Add Support for ExchangeOnlineManagement 3.0.0
- No more Windows Powershell Support - PowerShell CORE Only !
- New-SM365Rules: Transport rules will be setup DISABLED by default
- New-SM365Rules: Domains specified are not the exclusion, you need to specify the INCLUDE-list (similar to the cloud module)

### Enhancements

- New-SM365ExoReport similar to cloud-module
- Test-SM365ConnectionStatus similar to cloud-module
- New-SM365Rules has -SCL Parameter now. By default we do not route detected SPAM by Microsoft (SCL >=5), you may change this during creation.
- New-SM365Rules parameter for Domains is now called 'SEPPmailDomain'
- Removed Backup and Setup CmdLets
- Add test for external name resolution and write error if it fails.
- BETA CmdLet: Get-SM365MessageTrace to get detailed info on the mailflow through Exchange and SEPPmail

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
