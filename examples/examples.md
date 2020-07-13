# Examples on how to use the SMExO Module

After importing the module you need to authenticate to Exchange Online.

## Get an overview of your ExO Environment

```powershell
Get-SMExOInfo
``` 

### Reporting Infos Overview

* Azure AD Tenant Name and Tenant ID
* List of managed Domains (Settings -> Domains) and definition of the default domain and status
* Service status of Exchange Online
* Connectors
* Existing Mailflow rules
* Accepted Domains and type
* Remote domains

### Details (-Details)

* Number of Online-Mailboxes
* Malware rules
* Connection rules
* Incoming Spamfilter rules
* Outgoing SpamFilter rules
* Quarantine
* dkim rules
* Number of Contacts

## Read existing Mailrules

```powershell
Get-SMExoMailRules
```

## Add necessary SEPPmail Connectors and Rules to make SEPPmail and Exchange Online work together

The below command will add the new connectors and default rules so that messages in-, and outbound, routed to SEPPmail for Mail processing. Rules will be placed on top of all other rules. The -force parameter will skip existing rules check.

```powershell
Add-SEConnAndRules -SQPPmailFQDN 'securemail.contoso.de' -force -top
```

If you want to read existing mailflow-rules and decide if you want to place the SEPPmail rules before of after the existing rules. You will be asked for every change.

```powershell
Add-SEConnAndRules -SQPPmailFQDN 'securemail.contoso.de'
```

```powershell
Add-SEConnAndRules -SQPPmailFQDN 'securemail.contoso.de' -force -bottom
```

## Remove SEPPmail Connectors and Rules

```powershell
Remove-SEConnAndRules
```

This will remove the SEPPmail Connectors and rules, but warn you of the consequences. Without contacting support@seppmail.de and coordinate this change in a productive environment, your E-Mails from other SEPPmail customers to your E-Mail domain may not work anymore.

