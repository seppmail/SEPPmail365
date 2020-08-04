# SEPPmail Microsoft 365 and Exchange Online Module

## General

This module helps customer and partners to smoothly integrate a SEPPmail-Appliance (SMA) with Exchange Online (ExO).

## Prerequisites

The module only works on Windows PowerShell 5.1 (64Bit), because it depends on the ExchangeOnlineManagement Module which currently works also only on Windows PowerShell 5.1.

The ExchangeOnlineManagement module must be installed with the minimum Version 1.0.1, we also tested this with 2.0.3-Preview and will support future versions of ExchangeOnlineManagement.

## Installation

To install the module from the Powershell Gallery use:

```powershell
Install-Module SEPPmail365
```

This will install the module in the user scope.

## Functionality

The module has a basic overview report of the existing ExO environment, as well as 2 commands to create Connectors and Rules to make ExO work seamlessly with the SMA.

## Authentication

As Microsoft will soon deprecate basic authentication with ExO, the module will support multi-factor (MFA) or app/certificate based authentication (https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps).

So you can login without MFA with:

```powershell
Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true
```

And with MFA:

```powershell
Connect-ExchangeOnline -UserPrincipalName frank@contoso.com -ShowProgress $true
```

Fact is, without an established implicit remoting session to Exchange Online, the module will not work.

## Usage

For examples on how to use the module see <https://github.com/seppmail/SEPPmail365/blob/master/examples/examples.md> and an example of a complete setup script here: <https://github.com/seppmail/SEPPmail365/blob/master/examples/setupscript.ps1>

## Whatif option

Before the actual changes happen, all CmdLets, which to configuration changes, must have a `-Whatif` Option to simulate the change in advance.

## Verbose Option

To know in detail what happens during the CommandLet works, use any CmdLet with the `-Verbose` option.
