@{
    # Module manifest for MftFileSearch

    # Script module file associated with this manifest
    RootModule = 'MftFileSearch.psm1'

    # Version number of this module
    ModuleVersion = '1.5.0'

    # ID used to uniquely identify this module
    GUID = 'a3f7c8d1-5e2b-4a9f-b6d4-1c8e3f5a7b90'

    # Author of this module
    Author = 'b0tmtl'

    # Copyright statement for this module
    Copyright = '(c) 2026. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Blazingly fast file search for Windows using direct MFT (Master File Table) reading. Searches entire NTFS drives in seconds by filename or path. Returns PowerShell objects. Supports local and remote computer search.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @('Search-MftFile')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            Tags = @('MFT', 'NTFS', 'Search', 'FileSearch', 'Fast', 'Windows')
            LicenseUri = 'https://github.com/b0tmtl/MftFileSearch/blob/main/LICENSE'
            ProjectUri = 'https://github.com/b0tmtl/MftFileSearch'
            ReleaseNotes = 'Initial release with fragmented MFT support and remote computer search'
        }
    }
}
