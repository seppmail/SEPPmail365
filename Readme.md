# SEPPmail Exchange Online Module

## General

This module helps customer and partners to smootly integrate the SEPPmail-Appliance (SMA) with
Exchange Online (Exo).

## Functionality

## Authentication

As Microsoft will soon deprecate basic authentication with ExO, the Module will support Multi-Factor

## ExO Infos

Before the change in the rulset is implemented the module shall provide information about the current Exo environment. Things like
Tenant-ID, Mail-domains, Existing rules ... shall be listed for decision making on how to implement the SEPpmail ruleset

## Ruleset update option

As SEPPmail continues to adapt and refine the rulset, based on customer feedback, the Module shall offer an option to update
the current ruleset to a defined of the latest version. If a ruleset applies to a specific SMA-Version, the user shall have the option to deploy the ruleset for that specific SMA version.

Example:
Update-SMExORulset -SMVersion '11.1.8'

## Ruleset order

Customers may have existing rules in ExO already, the Module shall give the option to set the priorit of the rulset - and therefor the position
of the rulset in the mailflow.
Same applies for connectors

Example:
New-SMExORuleset -SMVersion latest -Position first

## Whatif option

Before the actual changes happen, all CmdLets, which to configuration changes, must have a -Whatif Option to simulate the change in advance.

## Ruleset and Connector Backup

Before any change happens in ExO, users ahould have the option to backup the connector settings and rulsesets to a local file
and restore this configuration in case of mistake.




