# SEPPmail Microsoft 365 and Exchange Online Module

## General

This module helps customer and partners to smoothly integrate the SEPPmail-Appliance (SMA) with Exchange Online (ExO).

## Prerequisites

The module only works on Windows PowerShell 5.1 (64Bit), because it depends on the ExchangeOnlineManagement Module which currently works also only on Windows PowerShell 5.1.

## Functionality

## Authentication

As Microsoft will soon deprecate basic authentication with ExO, the Module will support Multi-Factor or APP/Certificate-based authentication (https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps).

So you can login without MFA with:
```powershell
Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true
```

And with MFA:
```powershell
Connect-ExchangeOnline -UserPrincipalName frank@contoso.com -ShowProgress $true
```

Fact is, without an established implicit remoting session to Exchange Online, the module will not work.

## ExO Infos

Before the change in the ruleset is implemented the module shall provide information about the current Exo environment. Things like
Tenant-ID, Mail-domains, existing rules ... shall be listed for decision making on how to implement the SEPPmail ruleset.

New-Sm365ExOReport will generate a report of the existing ExO environment.

## Ruleset update option

As SEPPmail continues to adapt and refine the rulset, based on customer feedback, the Module shall offer an option to update
the current ruleset to a defined of the latest version. If a ruleset applies to a specific SMA-Version, the user shall have the option to deploy the ruleset for that specific SMA version.

Example:
```powershell
Update-SMExORulset -SMVersion '11.1.8'
```

## Ruleset order

Customers may have existing rules in ExO already, the Module shall give the option to set the priority of the rulset - and therefor the position of the rulset in the mailflow. Same applies for connectors

Example:
```powershell
New-SMExORuleset -SMVersion latest -Position first
```

## Whatif option

Before the actual changes happen, all CmdLets, which to configuration changes, must have a `-Whatif` Option to simulate the change in advance.

## Ruleset and Connector Backup

Before any change happens in ExO, users should have the option to backup the connector settings and rulsesets to a local file and restore this configuration in case of mistake.
