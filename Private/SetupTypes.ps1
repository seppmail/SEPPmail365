# PS5 Enums and Classes are still kinda broken (especially the export).
# So, in order to achieve widest range compatibility, we use classical C# defined types.
Add-Type -Path $PSScriptRoot\Types.cs -Verbose:$false -Debug:$false

###############################################################
# array
#
#  Convenience function that creates a strongly typed generic
#  list if a type is specified, or a generic ArrayList that
#  is capable of holding any value if none is specified.
#
#  Strongly typed lists should be preferred over generic
#  PowerShell arrays (like @()) because they provide a
#  performance benefit.
#
# Parameters:
#  -Type [string]
#    The type that should be stored in the list
#
#  -Capacity [int]
#    Specifies the initial amount of elements the list should
#    be capable of holding without allocating new memory
#
#  -ArgumentList [object[]]
#    Not implemented
#
#  -AsString [switch]
#    Causes the function to return the string that would be
#    used to create the object with the New-Object CmdLet
#
# Output:
#    [System.Collections.Generic.List[$Type]]
#    [System.Collections.ArrayList]
#    [string]
#
#--------------------------------------------------------------

Function array
{
    Param
    (
        [string]   $Type,
        [int]      $Capacity = 10,
        [Object[]] $ArgumentList,
        [switch]   $AsString
    )

    if ($AsString)
    { return "System.Collections.Generic.List[$Type]" }

    if ($Type)
    { return New-Object System.Collections.Generic.List[$Type]($Capacity) }
    else
    { return New-Object System.Collections.ArrayList($Capacity) }
}
