using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Foton.Win
{
    /// <summary>What an export of the change journal wrote.</summary>
    public sealed class UsnExport
    {
        public long Bytes { get; set; }
        public long Records { get; set; }
        public ulong JournalId { get; set; }
        public long FirstUsn { get; set; }
        public long NextUsn { get; set; }
        /// <summary>Start of the first exported batch: later than FirstUsn when the journal was larger than the cap.</summary>
        public long StartUsn { get; set; }
        public bool Capped { get; set; }
        public string? Error { get; set; }
        /// <summary>The destination stream failed; what it holds may end in a partly written record.</summary>
        public bool WriteFailed { get; set; }
    }

    /// <summary>
    /// The NTFS change journal ($Extend\$UsnJrnl:$J) read through FSCTL_READ_USN_JOURNAL, the interface fsutil uses.
    /// $J cannot be opened as a file, so this is the way to get its records without parsing the volume. The records are
    /// written unchanged, back to back, in their on-disk USN_RECORD layout, which MFTECmd reads like a copied $J (without
    /// the sparse leading zeros). Read-only: the volume handle is opened for reading. Needs an Administrator token.
    /// </summary>
    public static class UsnJournal
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct UsnJournalDataV0
        {
            public ulong UsnJournalId;
            public long FirstUsn;
            public long NextUsn;
            public long LowestValidUsn;
            public long MaxUsn;
            public ulong MaximumSize;
            public ulong AllocationDelta;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ReadUsnJournalDataV0
        {
            public long StartUsn;
            public uint ReasonMask;
            public uint ReturnOnlyOnClose;
            public ulong Timeout;
            public ulong BytesToWaitFor;
            public ulong UsnJournalId;
        }

        internal static int[] StructSizes() => new[] { Marshal.SizeOf(typeof(UsnJournalDataV0)), Marshal.SizeOf(typeof(ReadUsnJournalDataV0)) };

        const uint GenericRead = 0x80000000;
        const uint ShareReadWrite = 0x00000003;
        const uint OpenExisting = 3;
        const uint FsctlQueryUsnJournal = 0x000900F4;
        const uint FsctlReadUsnJournal = 0x000900BB;
        const int ErrorJournalEntryDeleted = 1181;
        internal const int BatchBytes = 65536;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr inBuffer, int inSize,
            out UsnJournalDataV0 outBuffer, int outSize, out int returned, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DeviceIoControl(SafeFileHandle device, uint code, ref ReadUsnJournalDataV0 inBuffer, int inSize,
            byte[] outBuffer, int outSize, out int returned, IntPtr overlapped);

        static readonly Regex DriveLetter = new Regex("^[A-Za-z]:$");

        /// <summary>
        /// Writes the journal of <paramref name="drive"/> ("C:") to <paramref name="destination"/>. When the journal holds
        /// more than <paramref name="maxBytes"/>, the newest records are kept: a first pass finds the earliest whole batch
        /// from which the rest fits, and the export runs from there to where that pass ended.
        /// Never throws for a host condition: an error is returned in UsnExport.Error with what was written so far.
        /// </summary>
        public static UsnExport Export(string drive, Stream destination, long maxBytes)
        {
            var result = new UsnExport();
            if (!DriveLetter.IsMatch(drive)) { result.Error = "Not a drive letter: " + drive; return result; }
            // The cap must hold at least one whole read batch, or not even the newest batch could be kept.
            if (maxBytes < BatchBytes) { result.Error = "The export cap must be at least " + BatchBytes + " bytes."; return result; }
            using (var volume = CreateFileW(@"\\.\" + drive, GenericRead, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero))
            {
                if (volume.IsInvalid) { result.Error = "Cannot open volume " + drive + " (error " + Marshal.GetLastWin32Error() + ")."; return result; }
                if (!DeviceIoControl(volume, FsctlQueryUsnJournal, IntPtr.Zero, 0, out var journal, Marshal.SizeOf(typeof(UsnJournalDataV0)), out _, IntPtr.Zero))
                {
                    result.Error = "No change journal on " + drive + " or it cannot be queried (error " + Marshal.GetLastWin32Error() + ").";
                    return result;
                }
                result.JournalId = journal.UsnJournalId;
                result.FirstUsn = journal.FirstUsn;
                result.NextUsn = journal.NextUsn;
                var buffer = new byte[BatchBytes];
                var request = new ReadUsnJournalDataV0 { StartUsn = journal.FirstUsn, ReasonMask = 0xFFFFFFFF, UsnJournalId = journal.UsnJournalId };
                int size = Marshal.SizeOf(typeof(ReadUsnJournalDataV0));
                int purges = 0;

                // A busy volume can purge the oldest records while they are read (ERROR_JOURNAL_ENTRY_DELETED): the new
                // first record of the same journal, or null when reading cannot continue.
                long? Purged(int error)
                {
                    if (error != ErrorJournalEntryDeleted || purges++ >= 8) return null;
                    if (!DeviceIoControl(volume, FsctlQueryUsnJournal, IntPtr.Zero, 0, out var now, Marshal.SizeOf(typeof(UsnJournalDataV0)), out _, IntPtr.Zero)) return null;
                    return now.UsnJournalId == journal.UsnJournalId && now.FirstUsn > request.StartUsn ? now.FirstUsn : (long?)null;
                }

                // Pass 1, only when the journal is larger than the cap: walk the batches without writing, then start at the
                // earliest batch from which the rest fits. FSCTL_READ_USN_JOURNAL accepts only a StartUsn on a record
                // boundary, and a batch's USN span can exceed its byte count, so the start cannot be computed from NextUsn.
                long stopAt = long.MaxValue;
                if (journal.NextUsn - journal.FirstUsn > maxBytes)
                {
                    var batches = new List<KeyValuePair<long, long>>();
                    while (true)
                    {
                        if (!DeviceIoControl(volume, FsctlReadUsnJournal, ref request, size, buffer, buffer.Length, out var returned, IntPtr.Zero))
                        {
                            var error = Marshal.GetLastWin32Error();
                            var first = Purged(error);
                            if (first == null) { result.Error = "Reading the change journal stopped (error " + error + ")."; return result; }
                            batches.RemoveAll(b => b.Key < first.Value);
                            request.StartUsn = first.Value;
                            continue;
                        }
                        if (returned <= 8) break;
                        var next = BitConverter.ToInt64(buffer, 0);
                        batches.Add(new KeyValuePair<long, long>(request.StartUsn, returned - 8));
                        if (next <= request.StartUsn) break;
                        request.StartUsn = next;
                    }
                    stopAt = request.StartUsn;
                    request.StartUsn = StartForCap(batches, maxBytes, stopAt);
                    result.Capped = batches.Count > 0 && request.StartUsn > batches[0].Key;
                }
                result.StartUsn = request.StartUsn;

                // Pass 2: write whole records from the start, up to where pass 1 ended (a snapshot of the journal at that
                // moment; records appended since are mostly the collector's own) or, uncapped, to the end.
                while (request.StartUsn < stopAt)
                {
                    if (!DeviceIoControl(volume, FsctlReadUsnJournal, ref request, size, buffer, buffer.Length, out var returned, IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        var first = Purged(error);
                        if (first == null) { result.Error = "Reading the change journal stopped (error " + error + ")."; break; }
                        if (result.Records == 0) result.StartUsn = first.Value;
                        else result.Error = (result.Error == null ? "" : result.Error + " ")
                            + "Records from USN " + request.StartUsn + " to " + first.Value + " were purged by the volume during the export; the export has a gap there.";
                        request.StartUsn = first.Value;
                        continue;
                    }
                    if (returned <= 8) break;
                    long bytes;
                    int records;
                    bool full, stopped;
                    try { bytes = WriteRecords(buffer, returned, destination, maxBytes - result.Bytes, out records, out full, out stopped, stopAt); }
                    catch (IOException ex)
                    {
                        result.Error = "Writing the change-journal export failed: " + ex.Message;
                        result.WriteFailed = true;
                        break;
                    }
                    result.Bytes += bytes;
                    result.Records += records;
                    if (full) { result.Capped = true; break; }
                    if (stopped) break;
                    if (bytes < returned - 8) { result.Error = "A malformed change-journal record ended the export; records before it were kept."; break; }
                    var nextUsn = BitConverter.ToInt64(buffer, 0);
                    if (nextUsn <= request.StartUsn) break;
                    request.StartUsn = nextUsn;
                }
            }
            return result;
        }

        /// <summary>
        /// The StartUsn of the earliest batch (start USN, record bytes) from which every later batch together fits in
        /// <paramref name="maxBytes"/>; <paramref name="end"/> when not even the newest batch fits.
        /// </summary>
        internal static long StartForCap(IReadOnlyList<KeyValuePair<long, long>> batches, long maxBytes, long end)
        {
            long total = 0, start = end;
            for (int i = batches.Count - 1; i >= 0; i--)
            {
                if (total + batches[i].Value > maxBytes) break;
                total += batches[i].Value;
                start = batches[i].Key;
            }
            return start;
        }

        /// <summary>
        /// Writes the USN records in one FSCTL_READ_USN_JOURNAL output (an 8-byte next-USN, then records) to
        /// <paramref name="destination"/>, up to <paramref name="budget"/> bytes and only whole records. A record whose
        /// length is zero, unaligned, shorter than a header, or past the data ends the batch: nothing past it is trusted.
        /// A record whose USN is <paramref name="stopUsn"/> or later is not written and sets <paramref name="stopped"/>.
        /// </summary>
        internal static long WriteRecords(byte[] buffer, int returned, Stream destination, long budget, out int records, out bool full,
            out bool stopped, long stopUsn = long.MaxValue)
        {
            records = 0;
            full = false;
            stopped = false;
            int offset = 8;
            long written = 0;
            while (offset + 8 <= returned)
            {
                var length = BitConverter.ToInt32(buffer, offset);
                if (!WellFormed(buffer, offset, length, returned)) break;
                if (RecordUsn(buffer, offset) >= stopUsn) { stopped = true; break; }
                if (written + length > budget) { full = true; break; }
                destination.Write(buffer, offset, length);
                written += length;
                records++;
                offset += length;
            }
            return written;
        }

        // Fixed header size, and where FileNameLength / FileNameOffset sit, per record version: USN_RECORD_V2 has 64-bit
        // file references (60-byte header), V3 128-bit ones (76 bytes). READ_USN_JOURNAL_DATA_V0 asks for V2; V3 appears
        // only on volumes with 128-bit file IDs. Anything else is not trusted.
        const int V2Header = 60, V3Header = 76;

        /// <summary>
        /// A whole V2 or V3 record: 8-byte aligned, inside the data, at least its version's header, and with its file name
        /// inside the record.
        /// </summary>
        internal static bool WellFormed(byte[] buffer, int offset, int length, int returned)
        {
            if (length % 8 != 0 || length < V2Header || length > returned - offset) return false;
            var major = BitConverter.ToUInt16(buffer, offset + 4);
            int header = major == 2 ? V2Header : major == 3 ? V3Header : 0;
            if (header == 0 || length < header) return false;
            int nameLength = BitConverter.ToUInt16(buffer, offset + header - 4);
            int nameOffset = BitConverter.ToUInt16(buffer, offset + header - 2);
            return nameOffset >= header && nameOffset + nameLength <= length;
        }

        /// <summary>The record's USN: offset 24 in USN_RECORD_V2 (after two 64-bit file references), 40 in V3 (two 128-bit ones).</summary>
        internal static long RecordUsn(byte[] buffer, int offset) =>
            BitConverter.ToInt64(buffer, offset + (BitConverter.ToUInt16(buffer, offset + 4) == 3 ? 40 : 24));
    }
}
