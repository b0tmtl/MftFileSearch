# MftFileSearch

**Blazingly fast file search for Windows using direct MFT (Master File Table) reading.**

Search entire drives in seconds, not minutes. MftFileSearch bypasses the slow Windows file system APIs by reading the NTFS Master File Table directly, providing near-instant search results even on the largest drives.

## Performance

| Method | 500K files | 2M+ files |
|---|---|---|
| `Get-ChildItem -Recurse` | 30-120 sec | 5-15 min |
| `dir /s` | 20-60 sec | 3-10 min |
| **Search-MftFile** | **1-3 sec** | **3-8 sec** |

## Installation

### From PowerShell Gallery (Recommended)

```powershell
Install-Module -Name MftFileSearch
```

### Manual Installation

Copy the `MftFileSearch` folder to a PowerShell module path:

```powershell
$env:PSModulePath -split ';'

# Common location:
# C:\Users\<YourName>\Documents\WindowsPowerShell\Modules\MftFileSearch\
```

Then import:

```powershell
Import-Module MftFileSearch
```

## Usage

### Basic Search

```powershell
# Search by filename
Search-MftFile -SearchTerm "test123"

# Search on a different drive
Search-MftFile -SearchTerm "backup" -DriveLetter D

# Search within full paths (slower, checks all paths)
Search-MftFile -SearchTerm "users\admin" -SearchPath
```

### Filtering Results

```powershell
# Only files (no directories)
Search-MftFile -SearchTerm "config" -Type File

# Only directories
Search-MftFile -SearchTerm "backup" -Type Directory

# Filter by extension
Search-MftFile -SearchTerm "report" -Extension ".xlsx"

# Find large files
Search-MftFile -SearchTerm ".tmp" | Where-Object { $_.SizeMB -gt 100 }

# Case-sensitive search
Search-MftFile -SearchTerm "ReadMe" -CaseSensitive
```

### Remote Computers

```powershell
# Single remote computer
Search-MftFile -SearchTerm "config" -ComputerName "Server01"

# Multiple computers
Search-MftFile -SearchTerm "backup" -ComputerName "Server01","Server02"

# With credentials
Search-MftFile -SearchTerm "logs" -ComputerName "Server01" -Credential (Get-Credential)

# Pipeline input
"Server01","Server02" | Search-MftFile -SearchTerm ".log" -DriveLetter D
```

### Exporting

```powershell
# Export to CSV
Search-MftFile -SearchTerm ".log" | Export-Csv -Path "SearchResults.csv" -NoTypeInformation

# Export to JSON
Search-MftFile -SearchTerm "config" | ConvertTo-Json | Out-File "SearchResults.json"

# Format as table
Search-MftFile -SearchTerm "notepad" | Format-Table FileName, SizeFormatted, FullPath -AutoSize
```

## Output Properties

| Property | Type | Description |
|---|---|---|
| `ComputerName` | String | Name of the searched computer |
| `FileName` | String | Name of the file or directory |
| `FullPath` | String | Full path to the file or directory |
| `FileSize` | Long | Size in bytes |
| `SizeFormatted` | String | Human-readable size (e.g., "5.23 MB") |
| `SizeKB` | Double | Size in kilobytes |
| `SizeMB` | Double | Size in megabytes |
| `SizeGB` | Double | Size in gigabytes |
| `Type` | String | "File" or "Directory" |
| `Extension` | String | File extension (e.g., ".txt") |
| `IsDirectory` | Bool | True if the result is a directory |
| `ScanDate` | DateTime | When the search was performed |

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SearchTerm` | String | *(required)* | Text to search for in filenames |
| `-DriveLetter` | String | `C` | Drive letter to search (without colon) |
| `-SearchPath` | Switch | `$false` | Also match against full file paths |
| `-CaseSensitive` | Switch | `$false` | Perform case-sensitive search |
| `-Type` | String | `All` | Filter: File, Directory, or All |
| `-Extension` | String | | Filter by file extension |
| `-ComputerName` | String[] | Local | Target computer(s) to search |
| `-Credential` | PSCredential | Current | Credentials for remote connections |

## Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+**
- **Administrator privileges** (required for raw disk access)
- **NTFS formatted drives**
- **PowerShell Remoting** enabled on remote targets (for `-ComputerName`)

## How It Works

Traditional file search tools (`Get-ChildItem`, `dir /s`, Windows Search) traverse the directory tree using file system APIs — each folder requires a separate system call.

MftFileSearch takes a different approach:

1. Opens the volume with raw disk access
2. Reads the NTFS Master File Table (MFT) directly
3. Parses file records to extract filenames, parent references, and sizes
4. Filters matches by search term during the scan
5. Reconstructs full paths only for matching files

This reads a single contiguous data structure instead of millions of scattered file system calls.
