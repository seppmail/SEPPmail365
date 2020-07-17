#
# Module manifest for module 'SEPPmail365'
#
# Generated by: Roman Stadmair
#
# Generated on: 10.07.2020
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'SEPPMail365.psm1'

# Version number of this module.
ModuleVersion = '0.3.0'

# Supported PSEditions
CompatiblePSEditions = @('Desktop')

# ID used to uniquely identify this module
GUID = '485013db-02ab-4bf7-9161-7119e152c297'

# Author of this module
Author = 'Roman Stadlmair - SEPPmail Deutschland GmbH'

# Company or vendor of this module
CompanyName = 'SEPPmail AG'

# Copyright statement for this module
Copyright = '(c) SEPPmail AG. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Integrate and maintain SEPPmail in Microsoft 365 and Exchange Online'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
ProcessorArchitecture = 'Amd64'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @(
    @{
        ModuleName = 'ExchangeOnlineManagement'
        ModuleVersion = '2.0.3'
    }
)

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'New-SM365Connectors'
    'New-SM365Rules'
    'New-SM365ExOReport'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @(
                'SEPPmail',
                'Exchange Online',
                'Microsoft 365',
                'PSEdition_Desktop',
                'Windows')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/seppmail/SEPPmail365/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/seppmail/SEPPmail365'

        # A URL to an icon representing this module.
        IconUri = 'https://seppmail.de/wp-content/uploads/logo_seppmail_V1_Screen_S2.png'

        # ReleaseNotes of this module
        ReleaseNotes = 
@'
17.07.20    0.2.0 Build same functionality as the existing SEPPmail O365 deployment script
'@

        # Prerelease string of this module
        Prerelease = 'alpha-2'

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

