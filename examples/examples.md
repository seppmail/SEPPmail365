# Examples on how to use the SMExO Module

After importing the module you need to authenticate to Exchange Online. See the Documentation of the ExchangeOnline Module here 
<https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps>

## Get an overview of your ExO Environment

Before you change anything, run the report to get insights into your ExO environment.

```powershell
New-SM365ExOReport -FilePath $env:temp\ExOReport.html

# To display the report in your default browser execute:
& $env:temp\ExOReport.html
```

### Report content overview

* List of managed Domains (Settings -> Domains) and definition of the default domain and status
* Connectors
* Existing Mailflow rules
* Accepted Domains and type
* Remote domains
* and much more ...

## Integrating a SEPPmail Appliance

Before you continue the steps below, your SEPPmail must be configured accordingly to be able to process E-Mails for the ExO environment for all or some specified domains. Typically this would be:

* <contosode.onmicrosoft.com>
* <contoso.de>
* <contosotest.de>

Please see <https://docs.seppmail.com> for more.

### Step 1 - Add necessary SEPPmail Connectors

The below command will add new connectors to SEPPmail for Mail processing.

```powershell
New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains *
```

If you want to limit the usage to specific domains use:

```powershell
New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains 'contoso.de','contosotest.de'
```

Remember, before changing the something you always can run the CmdLetr with the `-WhatIf` option:

```powershell
New-SM365Connectors -SEPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains 'contoso.de','contosotest.de' -WhatIf
```


## Step 2 - Add SEPPmail rules to make SEPPmail and ExO work together

The below command will add the new connectors and default rules so that messages in-, and outbound, routed to SEPPmail for E-Mail processing. Rules will be placed on top of all other rules by default. You are able to decide the rukl placement during the `New-SM365` CmdLet flow. The `-Whatif` parameter will simulate the changes.

```powershell
# Simulate changes
New-SM365Rules -Whatif

# Add SEPPmail Rules
New-SM365Rules
```

## Removing Connectors and Rules

We are working on an extension to this module to allow also the removal of the changes we do. For now, use the ExchangeOnline administration webpage. First remove the rules, and then the connectors, because some rules depend on connectors.

## More help and examples

Look at the help and examples for each CmdLet with `Get-Help` to get more infos.

```powershell
Get-help New-SM365Rules
Get-help New-SM365Connectors
```

If you want to pack the whole process into a script, see this example:
<https://github.com/seppmail/SEPPmail365/blob/master/examples/setupscript.ps1>
