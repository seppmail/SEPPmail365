# Examples on how to use the SMExO Module

After importing the module you need to authenticate to Exchange Online. See the Documentation of the ExchangeOnline Module here 
<https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps>

## Get an overview of your ExO Environment

Before you change anything, run the report to get insights into your ExO environment.

```powershell
New-SM365ExOReport
```

### Report content overview

* List of managed Domains (Settings -> Domains) and definition of the default domain and status
* Connectors
* Existing Mailflow rules
* Accepted Domains and type
* Remote domains

## Integrating a SEPPmail Appliance

Before you continue the steps below, your SEPPmail must be configure accordingly to be able to process E-Mails for the ExO environment. Please see <https://docs.seppmail.com> for more.

### Step 1 - Add necessary SEPPmail Connectors

The below command will add new connectors to SEPPmail for Mail processing.

```powershell
New-SM365Connectors -SQPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains *
```

If you want to limit the usage to specific domains use:

```powershell
New-SM365Connectors -SQPPmailFQDN 'securemail.contoso.de' -InboundAcceptedDomains 'domain1.de','domain2.de'
```

## Step 2 - Add SEPPmail rules to make SEPPmail and ExO work together

The below command will add the new connectors and default rules so that messages in-, and outbound, routed to SEPPmail for Mail processing. Rules will be placed on top of all other rules. The -force parameter will skip existing rules check.

```powershell
New-SM365Rules
```

## More help and examples

Look at the help and examples for each CmdLet with Get-Help to get more infos.

If you want to pack the whole process into a script, see this example:
<https://github.com/seppmail/SEPPmail365/blob/master/examples/setupscript.ps1>
