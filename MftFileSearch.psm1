#Requires -Version 5.1

$MftFileSearcherSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

public class MftFileSearcher
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile, long liDistanceToMove,
        out long lpNewFilePointer, uint dwMoveMethod);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;

    public class MftSearchResult
    {
        public string ComputerName { get; set; }
        public string FileName { get; set; }
        public string FullPath { get; set; }
        public long FileSize { get; set; }
        public string SizeFormatted { get; set; }
        public double SizeKB { get; set; }
        public double SizeMB { get; set; }
        public double SizeGB { get; set; }
        public bool IsDirectory { get; set; }
        public string Type { get; set; }
        public string Extension { get; set; }
        public DateTime ScanDate { get; set; }
    }

    // Represents one contiguous extent of the MFT on disk
    private struct MftExtent
    {
        public long StartByte;
        public long LengthBytes;
    }

    // Parse NTFS data runs from a non-resident $DATA attribute
    private static List<MftExtent> ParseDataRuns(byte[] buffer, int dataRunOffset, int attrEnd, uint bytesPerCluster)
    {
        var extents = new List<MftExtent>();
        int pos = dataRunOffset;
        long prevLcn = 0;

        while (pos < attrEnd)
        {
            byte header = buffer[pos];
            if (header == 0) break;

            int lengthSize = header & 0x0F;
            int offsetSize = (header >> 4) & 0x0F;
            pos++;

            if (lengthSize == 0 || pos + lengthSize + offsetSize > attrEnd) break;

            // Read run length (unsigned)
            long runLength = 0;
            for (int b = 0; b < lengthSize; b++)
                runLength |= ((long)buffer[pos + b]) << (b * 8);
            pos += lengthSize;

            // Read run offset (signed, relative to previous LCN)
            long runOffset = 0;
            if (offsetSize > 0)
            {
                for (int b = 0; b < offsetSize; b++)
                    runOffset |= ((long)buffer[pos + b]) << (b * 8);
                // Sign-extend if the high bit is set
                if ((buffer[pos + offsetSize - 1] & 0x80) != 0)
                {
                    for (int b = offsetSize; b < 8; b++)
                        runOffset |= ((long)0xFF) << (b * 8);
                }
                pos += offsetSize;
            }
            else
            {
                // Sparse run - skip
                continue;
            }

            long absoluteLcn = prevLcn + runOffset;
            prevLcn = absoluteLcn;

            extents.Add(new MftExtent
            {
                StartByte = absoluteLcn * bytesPerCluster,
                LengthBytes = runLength * bytesPerCluster
            });
        }

        return extents;
    }

    // Read MFT record 0 and extract the $DATA attribute data runs
    private static List<MftExtent> GetMftExtents(SafeFileHandle hVolume, long mftStartByte, uint bytesPerMftRecord, uint bytesPerCluster)
    {
        byte[] rec0 = new byte[bytesPerMftRecord];
        long newPos;
        SetFilePointerEx(hVolume, mftStartByte, out newPos, 0);
        uint bytesRead;
        if (!ReadFile(hVolume, rec0, bytesPerMftRecord, out bytesRead, IntPtr.Zero) || bytesRead < bytesPerMftRecord)
            throw new Exception("Failed to read MFT record 0");

        if (rec0[0] != 0x46 || rec0[1] != 0x49 || rec0[2] != 0x4C || rec0[3] != 0x45)
            throw new Exception("MFT record 0 has invalid signature");

        ushort attrOffset = BitConverter.ToUInt16(rec0, 20);
        int pos = attrOffset;
        int recEnd = (int)bytesPerMftRecord;

        while (pos + 4 <= recEnd)
        {
            uint attrType = BitConverter.ToUInt32(rec0, pos);
            if (attrType == 0xFFFFFFFF || attrType == 0) break;

            uint attrLen = BitConverter.ToUInt32(rec0, pos + 4);
            if (attrLen == 0 || pos + attrLen > recEnd) break;

            if (attrType == 0x80) // $DATA
            {
                byte nonResident = rec0[pos + 8];
                if (nonResident == 1)
                {
                    ushort dataRunOffset = BitConverter.ToUInt16(rec0, pos + 32);
                    return ParseDataRuns(rec0, pos + dataRunOffset, pos + (int)attrLen, bytesPerCluster);
                }
            }

            pos += (int)attrLen;
        }

        throw new Exception("Could not find non-resident $DATA attribute in MFT record 0");
    }

    public static List<MftSearchResult> Search(string driveLetter, string searchTerm, bool caseSensitive, bool searchPath)
    {
        string volumePath = @"\\.\" + driveLetter + ":";
        var results = new List<MftSearchResult>();
        var fileNames = new Dictionary<long, string>();
        var parentRefs = new Dictionary<long, long>();
        var fileSizes = new Dictionary<long, long>();
        var isDirectory = new Dictionary<long, bool>();

        string searchLower = caseSensitive ? searchTerm : searchTerm.ToLowerInvariant();

        using (SafeFileHandle hVolume = CreateFile(volumePath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
        {
            if (hVolume.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open volume " + volumePath + ". Ensure you are running as Administrator.");

            // Get NTFS volume data
            byte[] ntfsData = new byte[128];
            GCHandle hData = GCHandle.Alloc(ntfsData, GCHandleType.Pinned);
            uint bytesReturned;
            try
            {
                if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA, IntPtr.Zero, 0,
                    hData.AddrOfPinnedObject(), (uint)ntfsData.Length, out bytesReturned, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get NTFS volume data. Drive may not be NTFS formatted.");
            }
            finally { hData.Free(); }

            // NTFS_VOLUME_DATA_BUFFER correct offsets
            // Offsets 0-39: 5x LARGE_INTEGER (VolumeSerialNumber, NumberSectors, TotalClusters, FreeClusters, TotalReserved)
            // Offsets 40-55: 4x DWORD (BytesPerSector, BytesPerCluster, BytesPerFileRecordSegment, ClustersPerFileRecordSegment)
            // Offsets 56+: LARGE_INTEGERs (MftValidDataLength, MftStartLcn, Mft2StartLcn, MftZoneStart, MftZoneEnd)
            uint bytesPerSector = BitConverter.ToUInt32(ntfsData, 40);
            uint bytesPerCluster = BitConverter.ToUInt32(ntfsData, 44);
            uint bytesPerMftRecord = BitConverter.ToUInt32(ntfsData, 48);
            long mftValidDataLength = BitConverter.ToInt64(ntfsData, 56);
            long mftStartLcn = BitConverter.ToInt64(ntfsData, 64);

            long mftStartByte = mftStartLcn * bytesPerCluster;

            // Parse MFT data runs to handle fragmented MFT
            List<MftExtent> mftExtents = GetMftExtents(hVolume, mftStartByte, bytesPerMftRecord, bytesPerCluster);

            // Calculate total MFT bytes across all extents, capped to valid data length
            long totalMftBytes = 0;
            foreach (var ext in mftExtents)
                totalMftBytes += ext.LengthBytes;
            if (totalMftBytes > mftValidDataLength)
                totalMftBytes = mftValidDataLength;

            // Read MFT in chunks, walking through each extent
            int recordsPerChunk = 4096;
            uint chunkSize = (uint)(recordsPerChunk * bytesPerMftRecord);
            byte[] buffer = new byte[chunkSize];
            var matchedRecords = new HashSet<long>();

            long mftBytesProcessed = 0;
            int extentIndex = 0;
            long extentBytesConsumed = 0;

            while (mftBytesProcessed < totalMftBytes && extentIndex < mftExtents.Count)
            {
                MftExtent currentExtent = mftExtents[extentIndex];
                long extentRemaining = currentExtent.LengthBytes - extentBytesConsumed;

                if (extentRemaining <= 0)
                {
                    extentIndex++;
                    extentBytesConsumed = 0;
                    continue;
                }

                long globalRemaining = totalMftBytes - mftBytesProcessed;
                long toRead = Math.Min(chunkSize, Math.Min(extentRemaining, globalRemaining));

                // Align to MFT record boundary
                toRead = (toRead / bytesPerMftRecord) * bytesPerMftRecord;
                if (toRead == 0) { extentIndex++; extentBytesConsumed = 0; continue; }

                long seekPos = currentExtent.StartByte + extentBytesConsumed;
                long newPos;
                if (!SetFilePointerEx(hVolume, seekPos, out newPos, 0))
                    break;

                uint bytesRead;
                if (!ReadFile(hVolume, buffer, (uint)toRead, out bytesRead, IntPtr.Zero) || bytesRead == 0)
                    break;

                int actualRecords = (int)(bytesRead / bytesPerMftRecord);

                for (int i = 0; i < actualRecords; i++)
                {
                    int recOffset = (int)(i * bytesPerMftRecord);

                    // Verify FILE signature (0x46494C45)
                    if (buffer[recOffset] != 0x46 || buffer[recOffset + 1] != 0x49 ||
                        buffer[recOffset + 2] != 0x4C || buffer[recOffset + 3] != 0x45)
                        continue;

                    // Read the actual MFT record number from the header
                    long recordIndex = BitConverter.ToUInt32(buffer, recOffset + 44);

                    // Check flags - bit 0 = in use
                    ushort flags = BitConverter.ToUInt16(buffer, recOffset + 22);
                    if ((flags & 0x01) == 0) continue;

                    bool isDir = (flags & 0x02) != 0;
                    isDirectory[recordIndex] = isDir;

                    // Parse attributes
                    ushort attrOffset = BitConverter.ToUInt16(buffer, recOffset + 20);
                    int pos = recOffset + attrOffset;
                    int recEnd = recOffset + (int)bytesPerMftRecord;

                    string bestName = null;
                    byte bestNamespace = 0xFF;
                    long parentRef = -1;
                    long dataSize = 0;

                    while (pos + 4 <= recEnd)
                    {
                        uint attrType = BitConverter.ToUInt32(buffer, pos);
                        if (attrType == 0xFFFFFFFF || attrType == 0) break;

                        uint attrLen = BitConverter.ToUInt32(buffer, pos + 4);
                        if (attrLen == 0 || attrLen > bytesPerMftRecord || pos + attrLen > recEnd) break;

                        if (attrType == 0x30) // $FILE_NAME
                        {
                            byte nonResident = buffer[pos + 8];
                            if (nonResident == 0)
                            {
                                ushort contentOffset = BitConverter.ToUInt16(buffer, pos + 20);
                                int fnStart = pos + contentOffset;

                                if (fnStart + 66 <= recEnd)
                                {
                                    long pRef = BitConverter.ToInt64(buffer, fnStart) & 0x0000FFFFFFFFFFFF;
                                    byte nameLen = buffer[fnStart + 64];
                                    byte nameSpace = buffer[fnStart + 65];

                                    if (fnStart + 66 + nameLen * 2 <= recEnd && nameLen > 0)
                                    {
                                        // Prefer Win32 (1) or Win32+DOS (3) over DOS-only (2)
                                        if (bestName == null || nameSpace == 0x01 || nameSpace == 0x03 ||
                                            (nameSpace == 0x00 && bestNamespace == 0x02))
                                        {
                                            bestName = System.Text.Encoding.Unicode.GetString(
                                                buffer, fnStart + 66, nameLen * 2);
                                            bestNamespace = nameSpace;
                                            parentRef = pRef;
                                        }
                                    }
                                }
                            }
                        }
                        else if (attrType == 0x80) // $DATA
                        {
                            byte nonResident = buffer[pos + 8];
                            if (nonResident == 0)
                            {
                                if (pos + 16 + 4 <= recEnd)
                                    dataSize = BitConverter.ToUInt32(buffer, pos + 16);
                            }
                            else
                            {
                                if (pos + 48 + 8 <= recEnd)
                                    dataSize = BitConverter.ToInt64(buffer, pos + 48);
                            }
                        }

                        pos += (int)attrLen;
                    }

                    if (bestName != null)
                    {
                        // Store name/parent/size BEFORE skipping $-prefixed entries
                        // so system entries are available for path resolution
                        fileNames[recordIndex] = bestName;
                        if (parentRef >= 0) parentRefs[recordIndex] = parentRef;
                        fileSizes[recordIndex] = dataSize;

                        if (bestName.StartsWith("$"))
                            continue;

                        // Match on filename
                        string nameToCheck = caseSensitive ? bestName : bestName.ToLowerInvariant();
                        if (nameToCheck.Contains(searchLower))
                        {
                            matchedRecords.Add(recordIndex);
                        }
                    }
                }

                long consumed = (long)actualRecords * bytesPerMftRecord;
                extentBytesConsumed += consumed;
                mftBytesProcessed += consumed;
            }

            // If searchPath is enabled, also check full paths for all non-matched records
            if (searchPath)
            {
                foreach (var kvp in fileNames)
                {
                    if (matchedRecords.Contains(kvp.Key)) continue;
                    if (kvp.Value.StartsWith("$")) continue;

                    string fullPath = BuildPath(kvp.Key, fileNames, parentRefs, driveLetter);
                    string pathToCheck = caseSensitive ? fullPath : fullPath.ToLowerInvariant();

                    if (pathToCheck.Contains(searchLower))
                    {
                        matchedRecords.Add(kvp.Key);
                    }
                }
            }

            // Build results
            DateTime scanDate = DateTime.Now;
            foreach (long recIdx in matchedRecords)
            {
                string fullPath = BuildPath(recIdx, fileNames, parentRefs, driveLetter);
                long size = fileSizes.ContainsKey(recIdx) ? fileSizes[recIdx] : 0;
                bool dir = isDirectory.ContainsKey(recIdx) && isDirectory[recIdx];
                string name = fileNames[recIdx];
                string ext = "";
                int dotIdx = name.LastIndexOf('.');
                if (dotIdx >= 0 && !dir) ext = name.Substring(dotIdx);

                results.Add(new MftSearchResult
                {
                    FileName = name,
                    FullPath = fullPath,
                    FileSize = size,
                    SizeFormatted = FormatSize(size),
                    SizeKB = Math.Round(size / 1024.0, 2),
                    SizeMB = Math.Round(size / 1048576.0, 2),
                    SizeGB = Math.Round(size / 1073741824.0, 2),
                    IsDirectory = dir,
                    Type = dir ? "Directory" : "File",
                    Extension = ext,
                    ScanDate = scanDate
                });
            }
        }

        results.Sort((a, b) => string.Compare(a.FullPath, b.FullPath, StringComparison.OrdinalIgnoreCase));
        return results;
    }

    private static string BuildPath(long recordIndex, Dictionary<long, string> names,
        Dictionary<long, long> parents, string driveLetter)
    {
        var parts = new List<string>();
        long current = recordIndex;
        int maxDepth = 512;

        while (current >= 0 && maxDepth-- > 0)
        {
            if (!names.ContainsKey(current)) break;
            parts.Add(names[current]);

            if (!parents.ContainsKey(current)) break;
            long parent = parents[current];
            if (parent == current || parent == 5) break;
            current = parent;
        }

        parts.Reverse();
        return driveLetter + ":\\" + string.Join("\\", parts);
    }

    private static string FormatSize(long bytes)
    {
        if (bytes >= 1073741824L) return (bytes / 1073741824.0).ToString("F2") + " GB";
        if (bytes >= 1048576L) return (bytes / 1048576.0).ToString("F2") + " MB";
        if (bytes >= 1024L) return (bytes / 1024.0).ToString("F2") + " KB";
        return bytes + " B";
    }
}
'@

# Load C# type only once per session
if (-not ([System.Management.Automation.PSTypeName]'MftFileSearcher').Type) {
    Add-Type -TypeDefinition $MftFileSearcherSource
}

function Search-MftFile {
    <#
    .SYNOPSIS
        Blazingly fast file search for Windows using direct MFT (Master File Table) reading.

    .DESCRIPTION
        Searches for files and directories by name across an entire NTFS drive in seconds.
        Instead of using slow Windows file system APIs, this function reads the NTFS Master
        File Table directly, providing near-instant results even on large drives.

        Supports fragmented MFT by parsing data runs from MFT record 0, ensuring all file
        records are found even on heavily fragmented volumes.

        By default, the search matches against filenames only. Use -SearchPath to also
        match against the full file path (slower on large drives as it must reconstruct
        all paths).

    .PARAMETER SearchTerm
        The text to search for in filenames (or full paths if -SearchPath is used).
        Supports partial matches. For example, "test" will match "test123.txt",
        "mytest.log", and "testing" folder.

    .PARAMETER DriveLetter
        The drive letter to search. Default is C. Do not include the colon.

    .PARAMETER SearchPath
        When specified, also searches within the full file path, not just the filename.
        This is slower on large drives because it must reconstruct all file paths.
        Useful when searching for files within a specific folder structure.

    .PARAMETER CaseSensitive
        Perform a case-sensitive search. Default is case-insensitive.

    .PARAMETER Type
        Filter results by type: File, Directory, or All (default).

    .PARAMETER Extension
        Filter results by file extension. Example: ".log", ".txt"

    .PARAMETER ComputerName
        Target computer(s) to search. Requires PowerShell Remoting (WinRM).
        If not specified, searches the local computer.

    .PARAMETER Credential
        Credentials for remote connections. Required if your current account
        does not have admin access on the remote target.

    .EXAMPLE
        Search-MftFile -SearchTerm "test123"
        Searches for all files/folders containing "test123" in their name on C: drive.

    .EXAMPLE
        Search-MftFile -SearchTerm ".log" -DriveLetter D
        Searches for files with ".log" in their name on D: drive.

    .EXAMPLE
        Search-MftFile -SearchTerm "config" -Type File -Extension ".xml"
        Searches for XML files with "config" in the name.

    .EXAMPLE
        Search-MftFile -SearchTerm "users\admin" -SearchPath
        Searches for files whose full path contains "users\admin".

    .EXAMPLE
        Search-MftFile -SearchTerm "notepad" -ComputerName "Server01"
        Searches for "notepad" on a remote computer.

    .EXAMPLE
        "Server01","Server02" | Search-MftFile -SearchTerm "backup" -DriveLetter D
        Pipeline input for multiple remote computers.

    .EXAMPLE
        Search-MftFile -SearchTerm ".tmp" | Where-Object { $_.SizeMB -gt 100 } | Format-Table FileName, SizeFormatted, FullPath
        Find large temp files over 100 MB.

    .NOTES
        Requires Administrator privileges (raw disk access).
        Requires NTFS formatted drives.
        Requires PowerShell Remoting on remote targets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchTerm,

        [Parameter()]
        [ValidatePattern('^[A-Za-z]$')]
        [string]$DriveLetter = 'C',

        [Parameter()]
        [switch]$SearchPath,

        [Parameter()]
        [switch]$CaseSensitive,

        [Parameter()]
        [ValidateSet('File', 'Directory', 'All')]
        [string]$Type = 'All',

        [Parameter()]
        [string]$Extension,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Computer', 'Name')]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    begin {
        $DriveLetter = $DriveLetter.ToUpper()
        $timer = [System.Diagnostics.Stopwatch]::StartNew()

        # The full script block to execute locally or remotely
        $searchBlock = {
            param($src, $drive, $term, $caseSens, $searchP)

            Add-Type -TypeDefinition $src
            $results = [MftFileSearcher]::Search($drive, $term, $caseSens, $searchP)
            return $results
        }

        $allResults = [System.Collections.Generic.List[object]]::new()
    }

    process {
        # Determine targets
        if (-not $ComputerName) {
            $targets = @($env:COMPUTERNAME)
            $isLocal = $true
        }
        else {
            $targets = $ComputerName
            $isLocal = $false
        }

        foreach ($target in $targets) {
            $computerLabel = $target.ToUpper()

            try {
                if ($isLocal -or $target -eq $env:COMPUTERNAME -or $target -eq 'localhost' -or $target -eq '.') {
                    # Local execution
                    Write-Verbose "Searching MFT on local computer ($computerLabel) drive $DriveLetter`:..."
                    $results = [MftFileSearcher]::Search($DriveLetter, $SearchTerm, [bool]$CaseSensitive, [bool]$SearchPath)
                }
                else {
                    # Remote execution
                    Write-Verbose "Searching MFT on remote computer $computerLabel drive $DriveLetter`:..."
                    $sessionParams = @{
                        ComputerName = $target
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) { $sessionParams['Credential'] = $Credential }

                    $session = New-PSSession @sessionParams

                    try {
                        $results = Invoke-Command -Session $session -ScriptBlock $searchBlock -ArgumentList @(
                            $MftFileSearcherSource,
                            $DriveLetter,
                            $SearchTerm,
                            [bool]$CaseSensitive,
                            [bool]$SearchPath
                        )
                    }
                    finally {
                        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                    }
                }

                foreach ($r in $results) {
                    $r.ComputerName = $computerLabel

                    # Apply type filter
                    if ($Type -eq 'File' -and $r.IsDirectory) { continue }
                    if ($Type -eq 'Directory' -and -not $r.IsDirectory) { continue }

                    # Apply extension filter
                    if ($Extension) {
                        $ext = $Extension
                        if (-not $ext.StartsWith('.')) { $ext = ".$ext" }
                        if (-not $r.Extension.Equals($ext, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                    }

                    $r.PSObject.TypeNames.Insert(0, 'MftFileSearch.SearchResult')
                    $allResults.Add($r)
                }
            }
            catch {
                Write-Error "Failed to search $computerLabel`: $_"
            }
        }
    }

    end {
        $timer.Stop()
        Write-Verbose "Found $($allResults.Count) result(s) in $($timer.Elapsed.TotalSeconds.ToString('F2'))s"

        # Default display format
        $defaultDisplaySet = [System.Management.Automation.PSPropertySet]::new(
            'DefaultDisplayPropertySet',
            [string[]]@('FileName', 'SizeFormatted', 'Type', 'FullPath')
        )
        $memberInfo = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplaySet)

        foreach ($result in $allResults) {
            $result | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $memberInfo -Force
            $result
        }
    }
}

# Export
Export-ModuleMember -Function Search-MftFile