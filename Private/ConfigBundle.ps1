# This file defines config bundles, i.e. a named combination of
# a config version and options

# Specified in the same way as versions and options are specified already
# e.g. New-SM365Setup -Config "NoSkipSpf"
# in which case the actual ConfigBundleSettings object has to be looked up via it's id.

$Script:ConfigBundles = @{}

function New-ConfigBundle
{
    Param
    (
        [SM365.ConfigBundle] $Id,
        [SM365.ConfigVersion] $Version,
        [SM365.ConfigOption[]] $Option
    )

    $Script:ConfigBundles[$Id] = New-Object -TypeName SM365.ConfigBundleSettings -ArgumentList ($Id, $Version, ([List[SM365.ConfigOption]]$Option))
    return $Script:ConfigBundles[$Id]

}

function Get-ConfigBundle
{
    Param
    (
        [SM365.ConfigBundle] $Id
    )

    if(!$Script:ConfigBundles.ContainsKey($Id))
    {
        throw [System.Exception] "Config bundle $Id is not known to be defined"
    }

    return $Script:ConfigBundles[$Id]
}

# Example definition
# New-ConfigBundle -Id [SM365.ConfigBundle]::BestBundle -Version BaseVersion -Option Opt1, Opt2, Opt3
