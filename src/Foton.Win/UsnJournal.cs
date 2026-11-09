using System;
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
        /// more than <paramref name="maxBytes"/>, the newest records are kept (older batches are read and skipped).
        /// Never throws for a host condition: an error is returned in UsnExport.Error with what was written so far.
        /// </summary>
        public static UsnExport Export(string drive, Stream destination, long maxBytes)
        {
            var result = new UsnExport();
            if (!DriveLetter.IsMatch(drive)) { result.Error = "Not a drive letter: " + drive; return result; }
            // Batches are skipped whole to keep the newest records, so the cap must hold at least one batch.
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
                // FSCTL_READ_USN_JOURNAL only accepts a StartUsn on a record boundary (error 87 otherwise), so a journal
                // larger than the cap is read from its first record and whole batches are skipped until what remains fits.
                // A batch spans at most BatchBytes of USN space, so every kept batch starts within maxBytes of NextUsn.
                long skipUntil = long.MinValue;
                if (journal.NextUsn - journal.FirstUsn > maxBytes) { skipUntil = journal.NextUsn - maxBytes + BatchBytes; result.Capped = true; }
                var request = new ReadUsnJournalDataV0 { StartUsn = journal.FirstUsn, ReasonMask = 0xFFFFFFFF, UsnJournalId = journal.UsnJournalId };
                result.StartUsn = journal.FirstUsn;
                int purges = 0;
                while (result.Bytes < maxBytes)
                {
                    if (!DeviceIoControl(volume, FsctlReadUsnJournal, ref request, Marshal.SizeOf(typeof(ReadUsnJournalDataV0)), buffer, buffer.Length, out var returned, IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        // A busy volume can purge the oldest records while they are being read: continue from the new first record.
                        if (error == ErrorJournalEntryDeleted && purges++ < 8
                            && DeviceIoControl(volume, FsctlQueryUsnJournal, IntPtr.Zero, 0, out var now, Marshal.SizeOf(typeof(UsnJournalDataV0)), out _, IntPtr.Zero)
                            && now.UsnJournalId == journal.UsnJournalId && now.FirstUsn > request.StartUsn)
                        {
                            request.StartUsn = now.FirstUsn;
                            result.StartUsn = Math.Max(result.StartUsn, now.FirstUsn);
                            continue;
                        }
                        result.Error = "Reading the change journal stopped (error " + error + ").";
                        break;
                    }
                    if (returned <= 8) break;
                    if (BitConverter.ToInt64(buffer, 0) <= skipUntil)
                    {
                        var skipTo = BitConverter.ToInt64(buffer, 0);
                        if (skipTo <= request.StartUsn) break;
                        request.StartUsn = skipTo;
                        result.StartUsn = skipTo;
                        continue;
                    }
                    long bytes;
                    int records;
                    bool full;
                    try { bytes = WriteRecords(buffer, returned, destination, maxBytes - result.Bytes, out records, out full); }
                    catch (IOException ex)
                    {
                        result.Error = "Writing the change-journal export failed: " + ex.Message;
                        result.WriteFailed = true;
                        break;
                    }
                    result.Bytes += bytes;
                    result.Records += records;
                    if (full) { result.Capped = true; break; }
                    if (bytes < returned - 8) { result.Error = "A malformed change-journal record ended the export; records before it were kept."; break; }
                    var next = BitConverter.ToInt64(buffer, 0);
                    if (next <= request.StartUsn) break;
                    request.StartUsn = next;
                }
            }
            return result;
        }

        /// <summary>
        /// Writes the USN records in one FSCTL_READ_USN_JOURNAL output (an 8-byte next-USN, then records) to
        /// <paramref name="destination"/>, up to <paramref name="budget"/> bytes and only whole records. A record whose
        /// length is zero, unaligned, shorter than a header, or past the data ends the batch: nothing past it is trusted.
        /// </summary>
        internal static long WriteRecords(byte[] buffer, int returned, Stream destination, long budget, out int records, out bool full)
        {
            records = 0;
            full = false;
            int offset = 8;
            long written = 0;
            while (offset + 4 <= returned)
            {
                var length = BitConverter.ToInt32(buffer, offset);
                if (length < 60 || length % 8 != 0 || length > returned - offset) break;
                if (written + length > budget) { full = true; break; }
                destination.Write(buffer, offset, length);
                written += length;
                records++;
                offset += length;
            }
            return written;
        }
    }
}
