#Requires -Version 5.1

$MftFileSearcherSource = @'
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
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

    private const uint GENERIC_READ               = 0x80000000;
    private const uint FILE_SHARE_READ            = 0x01;
    private const uint FILE_SHARE_WRITE           = 0x02;
    private const uint OPEN_EXISTING              = 3;
    private const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;

    public static List<string> LastDiagnostics = new List<string>();

    public class MftSearchResult
    {
        public string   ComputerName  { get; set; }
        public string   FileName      { get; set; }
        public string   FullPath      { get; set; }
        public long     FileSize      { get; set; }
        public string   SizeFormatted { get; set; }
        public double   SizeKB        { get; set; }
        public double   SizeMB        { get; set; }
        public double   SizeGB        { get; set; }
        public bool     IsDirectory   { get; set; }
        public string   Type          { get; set; }
        public string   Extension     { get; set; }
        public DateTime ScanDate      { get; set; }
    }

    private struct MftExtent  { public long StartByte; public long LengthBytes; }
    private struct FileRecord { public string Name; public long ParentRef; public long DataSize; public bool IsDir; }
    private struct DirEntry   { public string Name; public long ParentRef; }

    // -------------------------------------------------------------------------
    // ProcessChunkState  - passed to each worker thread via ParameterizedThreadStart
    // Each thread gets its own private buffer slice so no locking is needed
    // during the hot parsing loop. Only ConcurrentDictionary writes are shared.
    // -------------------------------------------------------------------------
    private class ProcessChunkState
    {
        public byte[]   Buffer;
        public int      StartRecord;   // inclusive
        public int      EndRecord;     // exclusive
        public int      BytesPerMftRecord;
        public long     ChunkBaseRecord;
        public byte[]   SearchBytesLower;
        public byte[]   SearchBytesUpper;
        public bool     SearchPath;
        public ConcurrentDictionary<long, FileRecord> MatchedFileRecords;
        public ConcurrentDictionary<long, FileRecord> AllEntries;   // null when !SearchPath
        public int      LocalInUse;    // written only by owning thread, read after Join
    }

    // -------------------------------------------------------------------------
    // ParseDataRuns
    // -------------------------------------------------------------------------
    private static List<MftExtent> ParseDataRuns(byte[] buffer, int dataRunOffset, int attrEnd, uint bytesPerCluster)
    {
        var extents = new List<MftExtent>();
        int  pos     = dataRunOffset;
        long prevLcn = 0;
        while (pos < attrEnd)
        {
            byte header = buffer[pos];
            if (header == 0) break;
            int lengthSize = header & 0x0F;
            int offsetSize = (header >> 4) & 0x0F;
            pos++;
            if (lengthSize == 0 || pos + lengthSize + offsetSize > attrEnd) break;
            long runLength = 0;
            for (int b = 0; b < lengthSize; b++) runLength |= ((long)buffer[pos + b]) << (b * 8);
            pos += lengthSize;
            long runOffset = 0;
            if (offsetSize > 0)
            {
                for (int b = 0; b < offsetSize; b++) runOffset |= ((long)buffer[pos + b]) << (b * 8);
                if ((buffer[pos + offsetSize - 1] & 0x80) != 0)
                    for (int b = offsetSize; b < 8; b++) runOffset |= ((long)0xFF) << (b * 8);
                pos += offsetSize;
            }
            else continue;
            long lcn = prevLcn + runOffset;
            prevLcn = lcn;
            extents.Add(new MftExtent { StartByte = lcn * bytesPerCluster, LengthBytes = runLength * bytesPerCluster });
        }
        return extents;
    }

    // -------------------------------------------------------------------------
    // GetMftExtents  - reads MFT record 0, extracts $DATA data runs
    // -------------------------------------------------------------------------
    private static List<MftExtent> GetMftExtents(SafeFileHandle hVolume, long mftStartByte, uint bytesPerMftRecord, uint bytesPerCluster)
    {
        byte[] rec0 = new byte[bytesPerMftRecord];
        long dummy; uint br;
        SetFilePointerEx(hVolume, mftStartByte, out dummy, 0);
        if (!ReadFile(hVolume, rec0, bytesPerMftRecord, out br, IntPtr.Zero) || br < bytesPerMftRecord)
            throw new Exception("Failed to read MFT record 0");
        if (rec0[0] != 0x46 || rec0[1] != 0x49 || rec0[2] != 0x4C || rec0[3] != 0x45)
            throw new Exception("MFT record 0 has invalid signature");
        int pos    = BitConverter.ToUInt16(rec0, 20);
        int recEnd = (int)bytesPerMftRecord;
        while (pos + 4 <= recEnd)
        {
            uint attrType = BitConverter.ToUInt32(rec0, pos);
            if (attrType == 0xFFFFFFFF || attrType == 0) break;
            uint attrLen = BitConverter.ToUInt32(rec0, pos + 4);
            if (attrLen == 0 || pos + attrLen > recEnd) break;
            if (attrType == 0x80 && rec0[pos + 8] == 1)
            {
                ushort drOffset = BitConverter.ToUInt16(rec0, pos + 32);
                return ParseDataRuns(rec0, pos + drOffset, pos + (int)attrLen, bytesPerCluster);
            }
            pos += (int)attrLen;
        }
        throw new Exception("Could not find non-resident $DATA in MFT record 0");
    }

    // -------------------------------------------------------------------------
    // BytesContain  - raw UTF-16LE search, no string allocation (unsafe)
    // -------------------------------------------------------------------------
    private static unsafe bool BytesContain(byte* pStart, int lengthBytes, byte[] searchLower, byte[] searchUpper)
    {
        int sLen = searchLower.Length;
        if (lengthBytes < sLen) return false;
        int limit = lengthBytes - sLen;
        fixed (byte* pLower = searchLower)
        {
            if (searchUpper != null)
            {
                fixed (byte* pUpper = searchUpper)
                {
                    for (int i = 0; i <= limit; i += 2)
                    {
                        bool match = true;
                        for (int j = 0; j < sLen; j++)
                        {
                            byte b = pStart[i + j];
                            if (b != pLower[j] && b != pUpper[j]) { match = false; break; }
                        }
                        if (match) return true;
                    }
                }
            }
            else
            {
                for (int i = 0; i <= limit; i += 2)
                {
                    bool match = true;
                    for (int j = 0; j < sLen; j++)
                    {
                        if (pStart[i + j] != pLower[j]) { match = false; break; }
                    }
                    if (match) return true;
                }
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // ProcessChunk  - ParameterizedThreadStart target, no lambda, no closure
    // Each thread owns StartRecord..EndRecord of the shared buffer.
    // The buffer is read-only from threads' perspective (reader fills it before
    // signalling workers, workers never write to it).
    // -------------------------------------------------------------------------
    private static unsafe void ProcessChunk(object stateObj)
    {
        ProcessChunkState s = (ProcessChunkState)stateObj;
        int  bpr        = s.BytesPerMftRecord;
        bool searchPath = s.SearchPath;

        fixed (byte* pBuf = s.Buffer)
        {
            for (int i = s.StartRecord; i < s.EndRecord; i++)
            {
                byte* pRec = pBuf + i * bpr;

                if (*(uint*)pRec != 0x454C4946) continue;  // "FILE" signature

                ushort flags = *(ushort*)(pRec + 22);
                if ((flags & 0x01) == 0) continue;          // not in-use

                s.LocalInUse++;

                bool isDir       = (flags & 0x02) != 0;
                long recordIndex = (long)(*(uint*)(pRec + 44)) + s.ChunkBaseRecord;

                int pos    = *(ushort*)(pRec + 20);
                int recEnd = bpr;

                int  bestFnStart   = -1;
                int  bestNameLen   = 0;
                long bestParentRef = -1;
                byte bestNs        = 0xFF;
                long dataSize      = 0;

                while (pos + 4 <= recEnd)
                {
                    uint attrType = *(uint*)(pRec + pos);
                    if (attrType == 0xFFFFFFFF || attrType == 0) break;
                    uint attrLen = *(uint*)(pRec + pos + 4);
                    if (attrLen == 0 || attrLen > (uint)bpr || pos + (int)attrLen > recEnd) break;

                    if (attrType == 0x30 && pRec[pos + 8] == 0)  // $FILE_NAME, resident
                    {
                        int fnStart = pos + *(ushort*)(pRec + pos + 20);
                        if (fnStart + 66 <= recEnd)
                        {
                            long pRef = (*(long*)(pRec + fnStart)) & 0x0000FFFFFFFFFFFF;
                            byte nLen = pRec[fnStart + 64];
                            byte ns   = pRec[fnStart + 65];
                            if (fnStart + 66 + nLen * 2 <= recEnd && nLen > 0)
                            {
                                if (bestFnStart < 0 || ns == 0x01 || ns == 0x03 || (ns == 0x00 && bestNs == 0x02))
                                {
                                    bestFnStart   = fnStart;
                                    bestNameLen   = nLen;
                                    bestNs        = ns;
                                    bestParentRef = pRef;
                                }
                            }
                        }
                    }
                    else if (attrType == 0x80)  // $DATA
                    {
                        if (pRec[pos + 8] == 0) { if (pos + 20 <= recEnd) dataSize = *(uint*)(pRec + pos + 16); }
                        else                     { if (pos + 56 <= recEnd) dataSize = *(long*)(pRec + pos + 48); }
                    }

                    pos += (int)attrLen;
                    if (bestFnStart >= 0 && attrType > 0x80) break;
                }

                if (bestFnStart < 0) continue;

                int nameByteOffset = i * bpr + bestFnStart + 66;

                if (searchPath)
                {
                    string n = System.Text.Encoding.Unicode.GetString(s.Buffer, nameByteOffset, bestNameLen * 2);
                    var rec  = new FileRecord { Name = n, ParentRef = bestParentRef, DataSize = dataSize, IsDir = isDir };
                    s.AllEntries.TryAdd(recordIndex, rec);
                    if (!n.StartsWith("$") && BytesContain(pRec + bestFnStart + 66, bestNameLen * 2, s.SearchBytesLower, s.SearchBytesUpper))
                        s.MatchedFileRecords.TryAdd(recordIndex, rec);
                }
                else
                {
                    if (BytesContain(pRec + bestFnStart + 66, bestNameLen * 2, s.SearchBytesLower, s.SearchBytesUpper))
                    {
                        string n = System.Text.Encoding.Unicode.GetString(s.Buffer, nameByteOffset, bestNameLen * 2);
                        if (!n.StartsWith("$"))
                            s.MatchedFileRecords.TryAdd(recordIndex, new FileRecord { Name = n, ParentRef = bestParentRef, DataSize = dataSize, IsDir = isDir });
                    }
                }
            } // end for
        } // end fixed
    }

    // -------------------------------------------------------------------------
    // ReadRecordNameAndParent  - seeks directly to a record by number on disk
    // -------------------------------------------------------------------------
    private static bool ReadRecordNameAndParent(SafeFileHandle hVolume, long recordNumber,
        List<MftExtent> extents, uint bytesPerMftRecord, byte[] buf,
        out string name, out long parentRef)
    {
        name = null; parentRef = -1;
        long targetOffset = recordNumber * bytesPerMftRecord;
        long extentStart  = 0;
        bool found        = false;
        foreach (var ext in extents)
        {
            if (targetOffset >= extentStart && targetOffset < extentStart + ext.LengthBytes)
            {
                long dummy; uint br;
                if (!SetFilePointerEx(hVolume, ext.StartByte + (targetOffset - extentStart), out dummy, 0)) return false;
                if (!ReadFile(hVolume, buf, bytesPerMftRecord, out br, IntPtr.Zero) || br < bytesPerMftRecord) return false;
                found = true;
                break;
            }
            extentStart += ext.LengthBytes;
        }
        if (!found) return false;
        if (buf[0] != 0x46 || buf[1] != 0x49 || buf[2] != 0x4C || buf[3] != 0x45) return false;
        int pos    = BitConverter.ToUInt16(buf, 20);
        int recEnd = (int)bytesPerMftRecord;
        byte bestNs = 0xFF;
        while (pos + 4 <= recEnd)
        {
            uint attrType = BitConverter.ToUInt32(buf, pos);
            if (attrType == 0xFFFFFFFF || attrType == 0) break;
            uint attrLen = BitConverter.ToUInt32(buf, pos + 4);
            if (attrLen == 0 || pos + attrLen > recEnd) break;
            if (attrType == 0x30 && buf[pos + 8] == 0)
            {
                int  fnStart = pos + BitConverter.ToUInt16(buf, pos + 20);
                if (fnStart + 66 <= recEnd)
                {
                    long pRef  = BitConverter.ToInt64(buf, fnStart) & 0x0000FFFFFFFFFFFF;
                    byte nLen  = buf[fnStart + 64];
                    byte ns    = buf[fnStart + 65];
                    if (fnStart + 66 + nLen * 2 <= recEnd && nLen > 0)
                    {
                        if (name == null || ns == 0x01 || ns == 0x03 || (ns == 0x00 && bestNs == 0x02))
                        {
                            name = System.Text.Encoding.Unicode.GetString(buf, fnStart + 66, nLen * 2);
                            bestNs = ns; parentRef = pRef;
                        }
                    }
                }
            }
            pos += (int)attrLen;
        }
        return name != null;
    }

    // -------------------------------------------------------------------------
    // BuildPathOnDemand  - resolves path via targeted disk seeks + dir cache
    // -------------------------------------------------------------------------
    private static string BuildPathOnDemand(string matchedName, long initialParentRef, string driveLetter,
        SafeFileHandle hVolume, List<MftExtent> extents, uint bytesPerMftRecord,
        byte[] singleBuf, Dictionary<long, DirEntry> dirCache)
    {
        var  parts    = new List<string>();
        parts.Add(matchedName);
        long current  = initialParentRef;
        int  maxDepth = 64;
        while (current > 5 && maxDepth-- > 0)
        {
            if (dirCache.ContainsKey(current))
            {
                parts.Add(dirCache[current].Name);
                current = dirCache[current].ParentRef;
                continue;
            }
            string n; long p;
            if (!ReadRecordNameAndParent(hVolume, current, extents, bytesPerMftRecord, singleBuf, out n, out p)) break;
            dirCache[current] = new DirEntry { Name = n, ParentRef = p };
            parts.Add(n);
            if (p == current) break;
            current = p;
        }
        parts.Reverse();
        return driveLetter + ":\\" + string.Join("\\", parts);
    }

    // -------------------------------------------------------------------------
    // BuildPathFromDict  - resolves path from a pre-built dictionary (searchPath mode)
    // -------------------------------------------------------------------------
    private static string BuildPathFromDict(long recordIndex, ConcurrentDictionary<long, FileRecord> entries, string driveLetter)
    {
        var  parts    = new List<string>();
        long current  = recordIndex;
        int  maxDepth = 512;
        while (current >= 0 && maxDepth-- > 0)
        {
            FileRecord entry;
            if (!entries.TryGetValue(current, out entry)) break;
            parts.Add(entry.Name);
            long parent = entry.ParentRef;
            if (parent < 0 || parent == current || parent == 5) break;
            current = parent;
        }
        parts.Reverse();
        return driveLetter + ":\\" + string.Join("\\", parts);
    }

    // -------------------------------------------------------------------------
    // FormatSize
    // -------------------------------------------------------------------------
    private static string FormatSize(long bytes)
    {
        if (bytes >= 1073741824L) return (bytes / 1073741824.0).ToString("F2") + " GB";
        if (bytes >= 1048576L)    return (bytes / 1048576.0).ToString("F2")    + " MB";
        if (bytes >= 1024L)       return (bytes / 1024.0).ToString("F2")       + " KB";
        return bytes + " B";
    }

    // =========================================================================
    // Search
    // =========================================================================
    public static List<MftSearchResult> Search(string driveLetter, string searchTerm, bool caseSensitive, bool searchPath)
    {
        LastDiagnostics = new List<string>();
        var swTotal = Stopwatch.StartNew();
        var sw      = Stopwatch.StartNew();

        // Auto-detect logical CPU count, cap at 8 to avoid over-subscription
        int threadCount = Math.Min(Environment.ProcessorCount, 8);
        if (threadCount < 1) threadCount = 1;

        string volumePath = @"\\.\" + driveLetter + ":";
        var results            = new List<MftSearchResult>();
        var matchedFileRecords = new ConcurrentDictionary<long, FileRecord>();
        ConcurrentDictionary<long, FileRecord> allEntries = searchPath ? new ConcurrentDictionary<long, FileRecord>() : null;

        byte[] searchBytesLower = System.Text.Encoding.Unicode.GetBytes(caseSensitive ? searchTerm : searchTerm.ToLowerInvariant());
        byte[] searchBytesUpper = caseSensitive ? null : System.Text.Encoding.Unicode.GetBytes(searchTerm.ToUpperInvariant());

        using (SafeFileHandle hVolume = CreateFile(volumePath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
        {
            if (hVolume.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open volume " + volumePath + ". Ensure you are running as Administrator.");

            // --- NTFS volume data ---
            byte[]  ntfsData = new byte[128];
            GCHandle hData   = GCHandle.Alloc(ntfsData, GCHandleType.Pinned);
            uint    bytesReturned;
            try
            {
                if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA, IntPtr.Zero, 0,
                    hData.AddrOfPinnedObject(), (uint)ntfsData.Length, out bytesReturned, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to get NTFS volume data.");
            }
            finally { hData.Free(); }

            uint bytesPerCluster    = BitConverter.ToUInt32(ntfsData, 44);
            uint bytesPerMftRecord  = BitConverter.ToUInt32(ntfsData, 48);
            long mftValidDataLength = BitConverter.ToInt64(ntfsData, 56);
            long mftStartLcn        = BitConverter.ToInt64(ntfsData, 64);
            long mftStartByte       = mftStartLcn * bytesPerCluster;

            LastDiagnostics.Add(string.Format("[{0,7:F2}ms] Phase 1 - Volume open + NTFS data  | bytesPerMftRecord={1}  mftValidDataLength={2:N0}  threads={3}",
                sw.Elapsed.TotalMilliseconds, bytesPerMftRecord, mftValidDataLength, threadCount));
            sw.Restart();

            // --- MFT extents ---
            List<MftExtent> mftExtents = GetMftExtents(hVolume, mftStartByte, bytesPerMftRecord, bytesPerCluster);
            long totalMftBytes = 0;
            foreach (var ext in mftExtents) totalMftBytes += ext.LengthBytes;
            if (totalMftBytes > mftValidDataLength) totalMftBytes = mftValidDataLength;

            LastDiagnostics.Add(string.Format("[{0,7:F2}ms] Phase 2 - MFT extents parsed       | extents={1}  totalMftBytes={2:N0}",
                sw.Elapsed.TotalMilliseconds, mftExtents.Count, totalMftBytes));
            sw.Restart();

            // --- Main MFT scan (double-buffer ping-pong + Thread[] workers) ---
            //
            // Architecture:
            //   Reader (main thread): sequentially reads chunks from disk into
            //   the "fill" buffer. HDD sees one sequential stream — no seek thrashing.
            //
            //   Workers (Thread[]): N threads each process a private slice of
            //   the "process" buffer. Zero locking in the hot path.
            //
            //   Sync: after filling, main waits for previous workers to finish
            //   (Join), swaps buffers, then fires N new threads on the new chunk
            //   while it starts the next disk read. Disk I/O and CPU processing
            //   overlap across chunks.
            //
            int  recordsPerChunk     = 16384;
            uint chunkSize           = (uint)(recordsPerChunk * bytesPerMftRecord);

            // Two buffers: one being filled by reader, one being processed by workers
            byte[][] buffers         = new byte[2][] { new byte[chunkSize], new byte[chunkSize] };
            int      fillBuf         = 0;  // index of buffer currently being filled
            int      procBuf         = -1; // index of buffer currently being processed (-1 = none yet)

            Thread[]            workers      = null;
            ProcessChunkState[] workerStates = null;
            int   prevActualRecords          = 0;
            long  prevChunkBaseRecord        = 0;

            long mftBytesProcessed   = 0;
            int  extentIndex         = 0;
            long extentBytesConsumed = 0;
            int  totalRecordsScanned = 0;
            int  totalInUse          = 0;

            while (mftBytesProcessed < totalMftBytes && extentIndex < mftExtents.Count)
            {
                MftExtent cur = mftExtents[extentIndex];
                long extentRemaining = cur.LengthBytes - extentBytesConsumed;
                if (extentRemaining <= 0) { extentIndex++; extentBytesConsumed = 0; continue; }

                long globalRemaining = totalMftBytes - mftBytesProcessed;
                long toRead = Math.Min(chunkSize, Math.Min(extentRemaining, globalRemaining));
                toRead = (toRead / bytesPerMftRecord) * bytesPerMftRecord;
                if (toRead == 0) { extentIndex++; extentBytesConsumed = 0; continue; }

                // --- Disk read into fill buffer ---
                long dummy;
                if (!SetFilePointerEx(hVolume, cur.StartByte + extentBytesConsumed, out dummy, 0)) break;
                uint bytesRead;
                if (!ReadFile(hVolume, buffers[fillBuf], (uint)toRead, out bytesRead, IntPtr.Zero) || bytesRead == 0) break;

                int actualRecords    = (int)(bytesRead / bytesPerMftRecord);
                long chunkBaseRecord = mftBytesProcessed / bytesPerMftRecord;

                // --- Wait for previous workers to finish before we can swap ---
                if (workers != null)
                {
                    for (int t = 0; t < workers.Length; t++)
                        workers[t].Join();
                    for (int t = 0; t < workerStates.Length; t++)
                        totalInUse += workerStates[t].LocalInUse;
                    totalRecordsScanned += prevActualRecords;
                }

                // --- Launch workers on the just-filled buffer (now becomes procBuf after swap) ---
                procBuf = fillBuf;
                fillBuf = 1 - fillBuf;  // swap

                int slice    = actualRecords / threadCount;
                workers      = new Thread[threadCount];
                workerStates = new ProcessChunkState[threadCount];

                for (int t = 0; t < threadCount; t++)
                {
                    int start = t * slice;
                    int end   = (t == threadCount - 1) ? actualRecords : start + slice;

                    workerStates[t] = new ProcessChunkState
                    {
                        Buffer            = buffers[procBuf],
                        StartRecord       = start,
                        EndRecord         = end,
                        BytesPerMftRecord = (int)bytesPerMftRecord,
                        ChunkBaseRecord   = chunkBaseRecord,
                        SearchBytesLower  = searchBytesLower,
                        SearchBytesUpper  = searchBytesUpper,
                        SearchPath        = searchPath,
                        MatchedFileRecords = matchedFileRecords,
                        AllEntries        = allEntries,
                        LocalInUse        = 0
                    };

                    workers[t] = new Thread(ProcessChunk);
                    workers[t].IsBackground = true;
                    workers[t].Start(workerStates[t]);
                }

                prevActualRecords   = actualRecords;
                prevChunkBaseRecord = chunkBaseRecord;

                long consumed = (long)actualRecords * bytesPerMftRecord;
                extentBytesConsumed += consumed;
                mftBytesProcessed   += consumed;
            }

            // --- Wait for the last batch of workers ---
            if (workers != null)
            {
                for (int t = 0; t < workers.Length; t++)
                    workers[t].Join();
                for (int t = 0; t < workerStates.Length; t++)
                    totalInUse += workerStates[t].LocalInUse;
                totalRecordsScanned += prevActualRecords;
            }

            LastDiagnostics.Add(string.Format("[{0,7:F2}ms] Phase 3 - MFT scan complete        | recordsScanned={1:N0}  inUse={2:N0}  filenameMatches={3}",
                sw.Elapsed.TotalMilliseconds, totalRecordsScanned, totalInUse, matchedFileRecords.Count));
            sw.Restart();

            // --- SearchPath: full-path matching pass ---
            if (searchPath && allEntries != null)
            {
                string searchLower = caseSensitive ? searchTerm : searchTerm.ToLowerInvariant();
                foreach (var kvp in allEntries)
                {
                    if (matchedFileRecords.ContainsKey(kvp.Key)) continue;
                    if (kvp.Value.Name.StartsWith("$")) continue;
                    string fullPath  = BuildPathFromDict(kvp.Key, allEntries, driveLetter);
                    string pathCheck = caseSensitive ? fullPath : fullPath.ToLowerInvariant();
                    if (pathCheck.Contains(searchLower))
                        matchedFileRecords.TryAdd(kvp.Key, kvp.Value);
                }
                LastDiagnostics.Add(string.Format("[{0,7:F2}ms] Phase 3b - SearchPath matching    | totalMatches={1}",
                    sw.Elapsed.TotalMilliseconds, matchedFileRecords.Count));
                sw.Restart();
            }

            // --- Build results ---
            var      dirCache  = new Dictionary<long, DirEntry>();
            byte[]   singleBuf = new byte[bytesPerMftRecord];
            DateTime scanDate  = DateTime.Now;

            foreach (var kvp in matchedFileRecords)
            {
                var    rec      = kvp.Value;
                string fullPath = searchPath
                    ? BuildPathFromDict(kvp.Key, allEntries, driveLetter)
                    : BuildPathOnDemand(rec.Name, rec.ParentRef, driveLetter, hVolume, mftExtents, bytesPerMftRecord, singleBuf, dirCache);
                string ext = "";
                int dotIdx = rec.Name.LastIndexOf('.');
                if (dotIdx >= 0 && !rec.IsDir) ext = rec.Name.Substring(dotIdx);
                results.Add(new MftSearchResult
                {
                    FileName      = rec.Name,
                    FullPath      = fullPath,
                    FileSize      = rec.DataSize,
                    SizeFormatted = FormatSize(rec.DataSize),
                    SizeKB        = Math.Round(rec.DataSize / 1024.0, 2),
                    SizeMB        = Math.Round(rec.DataSize / 1048576.0, 2),
                    SizeGB        = Math.Round(rec.DataSize / 1073741824.0, 2),
                    IsDirectory   = rec.IsDir,
                    Type          = rec.IsDir ? "Directory" : "File",
                    Extension     = ext,
                    ScanDate      = scanDate
                });
            }

            LastDiagnostics.Add(string.Format("[{0,7:F2}ms] Phase 4 - Path resolution + build  | results={1}  dirCacheEntries={2}",
                sw.Elapsed.TotalMilliseconds, results.Count, dirCache.Count));
        }

        results.Sort((a, b) => string.Compare(a.FullPath, b.FullPath, StringComparison.OrdinalIgnoreCase));
        LastDiagnostics.Add(string.Format("[{0,7:F2}ms] TOTAL", swTotal.Elapsed.TotalMilliseconds));
        return results;
    }
}
'@

# Load C# type only once per session
if (-not ([System.Management.Automation.PSTypeName]'MftFileSearcher').Type) {
    $compilerParams = New-Object System.CodeDom.Compiler.CompilerParameters
    $compilerParams.CompilerOptions = "/unsafe"
    $compilerParams.ReferencedAssemblies.Add("System.dll")     | Out-Null
    $compilerParams.ReferencedAssemblies.Add("System.Core.dll") | Out-Null
    Add-Type -TypeDefinition $MftFileSearcherSource -CompilerParameters $compilerParams
}
$script:SessionCache = @{}

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
            $cp = New-Object System.CodeDom.Compiler.CompilerParameters
            $cp.CompilerOptions = "/unsafe"
            $cp.ReferencedAssemblies.Add("System.dll")      | Out-Null
            $cp.ReferencedAssemblies.Add("System.Core.dll") | Out-Null
            Add-Type -TypeDefinition $src -CompilerParameters $cp
            $results = [MftFileSearcher]::Search($drive, $term, $caseSens, $searchP)
            return @{ Results = $results; Diagnostics = [MftFileSearcher]::LastDiagnostics }
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
                    foreach ($line in [MftFileSearcher]::LastDiagnostics) { Write-Verbose $line }
                }
                else {
                    # Remote execution
                    Write-Verbose "Searching MFT on remote computer $computerLabel drive $DriveLetter`:..."
                    $sessionParams = @{
                        ComputerName = $target
                        ErrorAction  = 'Stop'
                    }
                    if ($Credential) { $sessionParams['Credential'] = $Credential }

                    $session = $script:SessionCache[$computerLabel]
if (-not $session -or $session.State -ne 'Opened') {
    $sessionParams = @{ ComputerName = $target; ErrorAction = 'Stop' }
    if ($Credential) { $sessionParams['Credential'] = $Credential }
    $session = New-PSSession @sessionParams
    $script:SessionCache[$computerLabel] = $session
}
$ret = Invoke-Command -Session $session -ScriptBlock $searchBlock -ArgumentList @(
    $MftFileSearcherSource, $DriveLetter, $SearchTerm, [bool]$CaseSensitive, [bool]$SearchPath
)
foreach ($line in $ret.Diagnostics) { Write-Verbose $line }
$results = $ret.Results
                }

                foreach ($r in $results) {
                    $r.ComputerName = $computerLabel

                    # Apply type filter
                    if ($Type -eq 'File'      -and $r.IsDirectory)  { continue }
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

function Disconnect-MftSession {
    param([string[]]$ComputerName)
    $keys = if ($ComputerName) { $ComputerName | ForEach-Object { $_.ToUpper() } } else { $script:SessionCache.Keys }
    foreach ($key in @($keys)) {
        if ($script:SessionCache[$key]) {
            Remove-PSSession $script:SessionCache[$key] -ErrorAction SilentlyContinue
            $script:SessionCache.Remove($key)
            Write-Verbose "Disconnected session for $key"
        }
    }
}

# Export
Export-ModuleMember -Function Search-MftFile, Disconnect-MftSession
