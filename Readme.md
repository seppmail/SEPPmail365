- [Abstract](#org5397315)
- [Prerequisites](#org9824a29)
- [Module Installation](#orgef2cdf1)
- [Preparation](#orgf75dbed)
- [Exchange Online Settings](#orgc0ead57)
  - [Connectors](#org15b8dd0)
    - [Inbound](#org04b7ec5)
    - [Outbound](#org700d8e6)
  - [Transport Rules](#orge91fc06)
- [SEPPmail365 CmdLets](#org2ccd88a)
  - [New-SM365Connectors](#org4a79779)
  - [Set-SM365Connectors](#org688c404)
  - [Remove-SM365Connectors](#orgb5c74b4)
  - [New-SM365Rules](#org4c6ac36)
  - [Set-SM365Rules](#orga15d112)
  - [Remove-SM365Rules](#orge4be2f6)
  - [Backup-SM365Connectors](#org0139703)
  - [Backup-SM365Rules](#org8c34f68)
  - [New-SM365ExOReport](#org3bc487a)
- [Examples](#org55ea827)

<script type="text/javascript">

function fallbackCopyTextToClipboard(text) {
  var textArea = document.createElement("textarea");
  textArea.value = text;
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();

  try {
    var successful = document.execCommand('copy');
    var msg = successful ? 'successful' : 'unsuccessful';
    console.log('Fallback: Copying text command was ' + msg);
  } catch (err) {
    console.error('Fallback: Oops, unable to copy', err);
  }

  document.body.removeChild(textArea);
}
function copyTextToClipboard(text) {
  if (!navigator.clipboard) {
    fallbackCopyTextToClipboard(text);
    return;
  }
  navigator.clipboard.writeText(text).then(function() {
    console.log('Async: Copying to clipboard was successful!');
  }, function(err) {
      console.error('Async: Could not copy text: ', err);
      console.error('Trying fallback method...');

      fallbackCopyTextToClipboard(text);
  });
}

</script>

<script type="text/javascript">
function setupCopyToClipboard()
{
    var srcs = document.getElementsByClassName("org-src-container");

    for(var i = 0; i < srcs.length; ++i)
    {
        var header = document.createElement("div");
        header.classList.add("copy-to-clipboard-header");

        var tmp = document.createElement("button");
        tmp.classList.add("copy-to-clipboard-button");
        tmp.innerHTML = "<!--<div class='copy-to-clipboard-button-icon'></div>--><span class='copy-to-clipboard-text'>Copy</span>";

        tmp.addEventListener("click", function(){
            copyTextToClipboard(this.parentNode.nextElementSibling.innerText);
        });

        header.appendChild(tmp);

        srcs[i].prepend(header);
    } 
}
</script>

<script type="text/javascript">
    function setupImageZoom()
    {
        var imgs = document.getElementsByTagName("img");

        var modalDiv = document.createElement("div");
        modalDiv.id = "modal-container";
        modalDiv.classList.add("modal-container");

        modalDiv.innerHTML = `
<!--<span class="modal-container-close" onclick="function(){document.getElementById(\"modal-container\").style.display = \"none\";}">&times;</span>-->
<img class="modal-container-content" id="modal-container-content">
<div id="modal-container-caption"></div>
`;

        document.body.appendChild(modalDiv);

        for(var i = 0; i < imgs.length; ++i)
        {
            imgs[i].addEventListener("click", function() {
                let modal = document.getElementById("modal-container");
                if(modal.style.display === "block")
                {
                    modal.style.display = "none";
                }
                else
                {
                    modal.style.display = "block";
                    document.getElementById("modal-container-content").src = this.src;
                    document.getElementById("modal-container-caption").innerHTML = this.parentNode.nextElementSibling.innerText;
                }
            });
        }
    }
</script>


<style type="text/css">
img {
    border-radius: 5px;
    cursor: pointer;
    transition: 0.3s;
}

img:hover {opacity: 0.95;}

.modal-container {
    display: none;
    position: fixed;
    z-index: 1000;
    padding-top: 100px;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgb(0,0,0);
    background-color: rgba(0,0,0,0.9);
}

.modal-container-content {
    margin: auto;
    display: block;
    width: 80%;
    max-width: 1400px;
}

#modal-container-caption {
    margin: auto;
    display: block;
    width: 80%;
    max-width: 1400px;
    text-align: center;
    color: #ccc;
    padding: 10px 0;
    height: 150px;
}

.modal-container-content, #modal-container-caption {
    animation-name: zoom;
    animation-duration: 0.6s;
}

@keyframes zoom {
    from {transform: scale(0)}
    to {transform: scale(1)}
}

.modal-container-close:hover,
.modal-container-close:focus {
    color: #bbb;
    text-decoration: none;
    cursor: pointer;
}

@media only screen and (max-width: 1400px) {
    .modal-container-content {
        width: 100%;
    }
}
</style>

<script type="text/javascript">
function setupDocumentVersion()
{
    var pa = document.getElementById("postamble");
    var el = document.getElementById("document-version");
    if(el && pa)
    {
        pa.insertBefore(el, pa.lastElementChild.previousElementSibling);
    }
    else
    {
        //console.log("oops");
    }
}
</script>

<script type="text/javascript">
var img = document.createElement("img");
img.id = "corporate-logo";
img.src = 'data:image/png;base64,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';
img.alt = "SEPPmail Logo"
document.body.prepend(img);
</script>

<p id="document-version">Module Version: 1.1.0<br>
<a href="https://www.seppmail.ch">SEPPmail Home Page</a></p>


<a id="org5397315"></a>

# Abstract

The SEPPmail365 PowerShell module helps customers and partners to smoothly integrate  
their SEPPmail appliance with Exchange Online.  

Integration with Exchange Online requires the configuration of an inbound and  
outbound connector, to route mails from Exchange Online to the appliance and  
vice versa, as well as transport rules for necessary mail manipulation (e.g.  
headers).  

This module provides means to create and update default connectors, rules, and  
backing up existing configuration, as well as generating a report about the  
current state of the environment.  


<a id="org9824a29"></a>

# Prerequisites

The module requires at least PowerShell 5.1 (64bit) and the  
[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module of version 1.0.1 or higher.  

Future versions of the [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/1.0.1) module should also work.  


<a id="orgef2cdf1"></a>

# Module Installation

Installing the module is as easy as executing:  

```powershell
Install-Module "SEPPmail365"
```

If you want to use the newest version, that might not be production ready  
yet, go to the [SEPPmail365 Github repository](https://github.com/seppmail/SEPPmail365), download the source code and  
execute:  

```powershell
Import-Module "C:\path\to\module\SEPPmail365.psd1"
```


<a id="orgf75dbed"></a>

# Preparation

Prior to using this module you need to connect to your Exchange Online  
organization.  
Use either one of the following commands, depending on whether multi factor  
authentication is enabled for your account or not:  

**Without multi factor authentication:**  

```powershell
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true
```

**With multi factor authentication:**  

```powershell
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName frank@contoso.com -ShowProgress $true
```


<a id="orgc0ead57"></a>

# Exchange Online Settings


<a id="org15b8dd0"></a>

## Connectors

For the setup to work, two connectors have to be created.  
An inbound connector (routing from the SEPPmail appliance(s) to Exchange Online)  
and an outbound connector (routing from Exchange Online to the SEPPmail  
appliance(s))  

Please note, that the terms *inbound* and *outbound* are used from an Exchange  
Online point of view, i.e an inbound connector specifies how a connection from  
an external entity is made to Exchange.  
If you're looking at the terms from a mail flow point of view, they are actually  
reversed (i.e. an inbound connector routes outgoing mails).  


<a id="org04b7ec5"></a>

### Inbound

Exchange Online CmdLet: [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)  
SEPPmail CmdLet: [New-SM365Connectors](#org4a79779)  

**Parameters in Use:**  

`-AssociatedAcceptedDomains`  
Restricts sender domains, the connector accepts mails from.  
Set via: `-SenderDomains`  
Default: `$null`  

`-SenderDomains`  
Restricts sender domains, the connector accepts mails from.  
Set via: `-SenderDomains`  
Default: `*`  

`-ConnectorSource`  
Specifies how the connector has been created.  
Set via: <none>  
Default: `Default` (meaning *manually created*)  

`-ConnectorType`  
Specifies if the connector handles mails external or internal to your  
organization.  
Set via: <none>  
Default: `OnPremises`  

`-EFSkipIPs`  
IPs for which enhanced filtering should be skipped.  
Set via: `-TrustedIPs`  
Default: `$null`  

`-EFSkipLastIP`  
Automatically skips enhanced filtering the last connecting IP.  
Set to `$false` if the parameter `-TrustedIPs` is used.  
Set via: <none>  
Default: `$true`  

`-EFUsers`  
Specifies recipients that enhanced filtering applies to.  
Set via: <none>  
Default: `$null` (applies to all recipients)  

`-RequireTls`  
TLS transmission is required for this connector.  
Set via: <none>  
Default: `$true`  

`-RestrictDomainsToCertificate`  
Verify the TLS certificate's subject.  
Set via: <none>  
Default: `$true`  

`-RestrictDomainsToIPAddresses`  
Restrict incoming connections to these IP addresses.  
Set via: <none>  
Default: `$false`  

`-TlsSenderCertificateName`  
The subject of the SEPPmail appliance's TLS certificate.  
Set via: `-SEPPmailFQDN` or `-InboundTlsDomain`  
Default: <none>  

`-CloudServicesMailEnabled`  
Specifies, that this connector is used for hybrid mail flow, thus preserving  
internal Microsoft headers.  
Set via: <none>  
Default: `$true`  


<a id="org700d8e6"></a>

### Outbound


<a id="orge91fc06"></a>

## Transport Rules


<a id="org2ccd88a"></a>

# SEPPmail365 CmdLets

Version specific configuration can be requested via the `-Version` parameter.  

**Note about parameters:**  
All CmdLets support the PowerShell [common parameters](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters?view=powershell-7) `-Confirm`, `-Whatif`,  
`-Verbose`, etc.  


<a id="org4a79779"></a>

## New-SM365Connectors

**Synopsis:**  
Two connectors are required to route mail flow between the SEPPmail appliance  
and Exchange Online. This CmdLet will create the necessary connectors.  

**Parameter List:**  
`-SEPPmailFQDN [string] (mandatory)`  
The FQDN your SEPPmail appliance is reachable under.  

`-TrustedIPs [string[]] (optional)`  
If multiple SEPPmail appliances are in use, specify their IP addresses here, to  
exempt them from enhanced filtering (corresponds to the parameter `-EFSkipIPs`  
of [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)).  

`-SenderDomains [string[]] (optional)`  
Internal mail domains, the inbound connector will take emails from.  

`-RecipientDomains [string[]] (optional)`  
External mail domains, the outbound connector will send emails to.  

`-TlsDomain [string] (optional)`  
Subject the SEPPmail appliance's ssl certificate has been issued to.  
Default is to use the SEPPmailFQDN, but in case you're using a wildcard  
certificate you will need this parameter.  
This parameter applies to the inbound and outbound connector.  

`-InboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the inbound connector.  

`-OutboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the outbound connector.  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

**Examples:**  

```powershell
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com"
```

```powershell
New-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com" -TlsDomain "*.contoso.com"
```


<a id="org688c404"></a>

## Set-SM365Connectors

**Synopsis:**  
This CmdLet provides a method of updating the SEPPmail connectors.  

**Parameter List:**  
`-SEPPmailFQDN [string] (optional)`  
The FQDN your SEPPmail appliance is reachable under.  

`-TrustedIPs [string[]] (optional)`  
If multiple SEPPmail appliances are in use, specify their IP addresses here, to  
exempt them from enhanced filtering (corresponds to the parameter `-EFSkipIPs`  
of [New-InboundConnector](https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboundconnector?view=exchange-ps)).  

`-SenderDomains [string[]] (optional)`  
Internal mail domains, the inbound connector will take emails from.  

`-RecipientDomains [string[]] (optional)`  
External mail domains, the outbound connector will send emails to.  

`-TlsDomain [string] (optional)`  
Subject the SEPPmail appliance's ssl certificate has been issued to.  
Default is to use the SEPPmailFQDN, but in case you're using a wildcard  
certificate you will need this parameter.  
This parameter applies to the inbound and outbound connector.  

`-InboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the inbound connector.  

`-OutboundTlsDomain [string] (optional)`  
Same as -TlsDomain, but applies only to the outbound connector.  

`-SetDefaults [switch] (optional)`  
The default behaviour is to only set the provided parameters, but this switch  
causes all other parameters be set to the default values, provided by  
[New-SM365Connectors](#org4a79779).  

`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

**Examples:**  

```powershell
# update smart host information
Set-SM365Connectors -SEPPmailFQDN "seppmail.contoso.com"
```

```powershell
# only update tls domain for the inbound connector
Set-SM365Connectors -InboundTlsDomain "*.contoso.com"
```

```powershell
# set everything else back to default values
Set-SM365Connectors -SetDefaults
```


<a id="orgb5c74b4"></a>

## Remove-SM365Connectors

**Synopsis:**  
Removes the SEPPmail inbound and outbound connector.  
Please note that connectors can only be removed, if no transport rules reference  
it.  

**Parameter List:**  
No additional parameters.  

**Examples:**  

```powershell
# see which connectors would be deleted
Remove-SM365Connectors -Whatif
```

```powershell
# request confirmation before every deletion
Remove-SM365Connectors -Confirm
```


<a id="org4c6ac36"></a>

## New-SM365Rules

**Synopsis:**  
Creates the required transport rules needed to correctly handle mails from and  
to the SEPPmail appliance.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance. You most likely won't need this  
parameter, but if version specific configuration is required, you will have to  
supply this parameter with the respective version.  

**Examples:**  

```powershell
New-SM365Rules
```


<a id="orga15d112"></a>

## Set-SM365Rules

**Synopsis:**  
Updates the SEPPmail transport rules to the default values, or a specific  
version.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmail appliance.  

**Examples:**  

```powershell
# update rules to the latest version
Set-SM365Rules -Version Default
```


<a id="orge4be2f6"></a>

## Remove-SM365Rules

**Synopsis:**  
Removes the SEPPmail transport rules.  

**Parameter List:**  
`-Version [ConfigVersion] (optional)`  
The major version of your SEPPmaill appliance.  

**Examples:**  

```powershell
Remove-SM365Rules -Whatif
```


<a id="org0139703"></a>

## Backup-SM365Connectors

**Synopsis:**  
Performs a backup of all connectors found to individual json files for every connector.  

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the connector information.  

**Examples:**  

```powershell
Backup-SM365Connectors -OutFolder C:\Temp
```


<a id="org8c34f68"></a>

## Backup-SM365Rules

**Synopsis:**  
Performs a backup of all transport rules found to individual json files for  
every rule.  

**Parameter List:**  
`-OutFolder [string] (mandatory)`  
The folder in which to store the transport rule information.  

**Examples:**  

```powershell
Backup-SM365Rules -OutFolder C:\Temp
```


<a id="org3bc487a"></a>

## New-SM365ExOReport

**Synopsis:**  
Creates an HTML report about the current Exchange Online environment.  

**Parameter List:**  
`-FilePath [string] (mandatory)`  
Path of the HTML report on disk.  

**Examples:**  

```powershell
New-SM365ExOReport -FilePath C:\Temp\ExOReport.html
```


<a id="org55ea827"></a>

# Examples