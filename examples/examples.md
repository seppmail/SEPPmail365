# Examples on how to use the SMExO Module

After importing the module you need to authenticate to Exchange Online. See the Documentation of the ExchangeOnline Module here 
<https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps>

## Get an overview of your ExO Environment

```powershell
New-SM365ExOReport
```

### Reporting Infos Overview

* List of managed Domains (Settings -> Domains) and definition of the default domain and status
* Connectors
* Existing Mailflow rules
* Accepted Domains and type
* Remote domains

## Add necessary SEPPmail Connectors

The below command will add new connectors to SEPPmail for Mail processing.

```powershell
New-SM365Connectors -SQPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains *
```

If you want to add specific domains use:

```powershell
New-SM365Connectors -SQPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains 'domain1.de','domain2.de'
```

## Add SEPPmail Rules to make SEPPmail and Exchange Online work together

The below command will add the new connectors and default rules so that messages in-, and outbound, routed to SEPPmail for Mail processing. Rules will be placed on top of all other rules. The -force parameter will skip existing rules check.

```powershell
New-SM365Rules
```

## More help and examples

Look at the help and examples for each CmdLet with Get-Help.
