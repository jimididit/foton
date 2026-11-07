using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Parse
{
    /// <summary>One DestList entry (ConvertFrom-FotonDestListBytes).</summary>
    public sealed class DestListEntry
    {
        public bool Supported { get; internal set; }
        public string Identity { get; internal set; } = "";
        public string Hostname { get; internal set; } = "";
        public string LastAccessUtc { get; internal set; } = "";
        public string PinStatus { get; internal set; } = "";
        public string EntryNumber { get; internal set; } = "";
        public string Note { get; internal set; } = "";
    }

    /// <summary>
    /// Jumplists copied off the host (ConvertFrom-FotonJumplist). Automatic destinations: DestList paths and
    /// FILETIME (versions 1-4) plus embedded LNK streams. Custom destinations: embedded LNKs found by the Shell
    /// Link CLSID. Unknown layouts emit unsupported rows instead of guessed times.
    /// </summary>
    public static class JumplistParser
    {
        static readonly byte[] ShellLinkClsid = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
        static readonly Regex HexName = new Regex("^[0-9a-fA-F]+$");

        public static List<ParseRecord> Parse(string path)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full)) throw new FileNotFoundException("Jumplist file not found: " + path, path);
            var bytes = File.ReadAllBytes(full);
            var sha = Hashing.Sha256Hex(bytes);
            ParseRecord Row(string format, bool supported, string identity, string note, string stream = "", string lastAccess = "", string pin = "", string host = "", string lnkPath = "")
            {
                var r = ParseRecord.For(full, bytes.Length, sha);
                r.Format = format;
                r.Supported = supported;
                r.Identity = identity;
                r.Note = note;
                r.Fields["StreamName"] = stream;
                r.Fields["Hostname"] = host;
                r.Fields["LastAccessUtc"] = lastAccess;
                r.Fields["PinStatus"] = pin;
                r.Fields["LocalBasePath"] = lnkPath;
                return r;
            }

            if (bytes.Length < 8)
                return new List<ParseRecord> { Row("Unsupported-TooSmall", false, "", "Shorter than a jumplist header. Paths were not guessed.") };

            var rows = new List<ParseRecord>();
            if (bytes[0] == 0xD0 && bytes[1] == 0xCF && bytes[2] == 0x11 && bytes[3] == 0xE0)
            {
                var streams = OleCompound.Streams(bytes);
                if (streams.Count == 0)
                    return new List<ParseRecord> { Row("AutomaticDestinations", false, "", "OLE compound header present but streams were not extracted. Use an OLE/jumplist tool; DestList times were not guessed.") };
                foreach (var st in streams)
                {
                    if (string.Equals(st.Name, "DestList", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var d in DestList(st.Data))
                            rows.Add(Row("DestList", d.Supported, d.Identity, d.Note, "DestList", d.LastAccessUtc, d.PinStatus, d.Hostname));
                    }
                    else if (HexName.IsMatch(st.Name))
                    {
                        var lnk = LnkParser.FromBytes(st.Data);
                        var note = lnk.Note.Length > 0 ? "Embedded LNK stream " + st.Name + ". " + lnk.Note : lnk.Note;
                        rows.Add(Row("JumplistLnk", lnk.Supported, lnk.LocalBasePath, note, st.Name, lnkPath: lnk.LocalBasePath));
                    }
                }
                if (rows.Count == 0)
                    rows.Add(Row("AutomaticDestinations", false, "", "OLE streams were present but none were DestList or hex-named LNK streams."));
                return rows;
            }

            int found = 0, i = 0;
            while (i <= bytes.Length - 20 && found < 40)
            {
                bool hit = true;
                for (int c = 0; c < 16; c++)
                    if (bytes[i + c] != ShellLinkClsid[c]) { hit = false; break; }
                if (!hit) { i++; continue; }
                int lnkStart = -1;
                if (i + 20 <= bytes.Length && BitConverter.ToUInt32(bytes, i + 16) == 0x4C) lnkStart = i + 16;
                else if (i >= 4 && BitConverter.ToUInt32(bytes, i - 4) == 0x4C) lnkStart = i - 4;
                if (lnkStart < 0) { i++; continue; }
                // An entry ends at the category footer or at the next entry (Shell Link CLSID + 0x4C header).
                // 1.38.x stopped only at the footer, so every LNK after the first in a category was skipped.
                int end = bytes.Length;
                for (int j = lnkStart + 4; j <= bytes.Length - 4; j++)
                {
                    if (bytes[j] == 0xAB && bytes[j + 1] == 0xFB && bytes[j + 2] == 0xBF && bytes[j + 3] == 0xBA) { end = j; break; }
                    if (j >= lnkStart + 0x4C && j + 20 <= bytes.Length && IsEntryStart(bytes, j)) { end = j; break; }
                }
                int len = end - lnkStart;
                if (len < 0x4C) { i++; continue; }
                var slice = new byte[len];
                Array.Copy(bytes, lnkStart, slice, 0, len);
                var lnk = LnkParser.FromBytes(slice);
                found++;
                var verNote = "Custom destinations embedded LNK (Shell Link CLSID). ";
                uint hv = BitConverter.ToUInt32(bytes, 0);
                if (hv != 2) verNote += $"File header version is {hv} (libyal documents 2); LNK still parsed when CLSID+HeaderSize matched. ";
                rows.Add(Row("CustomDestinations", lnk.Supported, lnk.LocalBasePath, verNote + lnk.Note, lnkPath: lnk.LocalBasePath));
                i = Math.Max(end, lnkStart + 1);
            }
            if (rows.Count == 0)
                rows.Add(Row("Unsupported-NotJumplist", false, "", "Not an OLE automatic destinations file and no Shell Link CLSID+LNK header was found. Paths were not guessed."));
            return rows;
        }

        /// <summary>Next entry: CLSID then a 0x4C LNK header, or (header-first layout) a 0x4C header then the CLSID.</summary>
        static bool IsEntryStart(byte[] b, int at) =>
            (Clsid(b, at) && BitConverter.ToUInt32(b, at + 16) == 0x4C) || (BitConverter.ToUInt32(b, at) == 0x4C && Clsid(b, at + 4));

        static bool Clsid(byte[] b, int at)
        {
            for (int c = 0; c < 16; c++)
                if (b[at + c] != ShellLinkClsid[c]) return false;
            return true;
        }

        /// <summary>DestList stream (libyal dtformats): versions 1 (Win7) and 2/3/4. FILETIME only at offset 100.</summary>
        public static List<DestListEntry> DestList(byte[]? b, int maxEntries = 200)
        {
            var rows = new List<DestListEntry>();
            if (b == null || b.Length == 0)
            {
                rows.Add(new DestListEntry { Note = "DestList stream is empty. Not proof the jumplist never had entries." });
                return rows;
            }
            if (b.Length < 32)
            {
                rows.Add(new DestListEntry { Note = "DestList shorter than the 32-byte header. Entries were not guessed." });
                return rows;
            }
            uint ver = BitConverter.ToUInt32(b, 0);
            uint count = BitConverter.ToUInt32(b, 4);
            if (ver < 1 || ver > 4)
            {
                rows.Add(new DestListEntry { Note = $"DestList format version {ver} is not 1, 2, 3, or 4. Paths and times were not guessed. Use a DestList-aware jumplist tool." });
                return rows;
            }
            long pos = 32;
            long n = Math.Min(count, (uint)maxEntries);
            int parsed = 0;
            int pathOff = ver == 1 ? 114 : 130;
            for (long e = 0; e < n; e++)
            {
                if (pos + pathOff > b.Length)
                {
                    rows.Add(new DestListEntry { Note = $"DestList truncated after {parsed} of {count} header entries (version {ver}). Remaining paths were not guessed." });
                    break;
                }
                var host = Encoding.ASCII.GetString(b, (int)pos + 72, 16).Trim('\0');
                uint entryNum = BitConverter.ToUInt32(b, (int)pos + 88);
                var lastUtc = Bin.FileTimeUtc(b, pos + 100);
                var pin = BitConverter.ToInt32(b, (int)pos + 108) == -1 ? "Unpinned" : "Pinned";
                int pathBytes = BitConverter.ToUInt16(b, (int)pos + pathOff - 2) * 2;
                if (pos + pathOff + pathBytes > b.Length)
                {
                    rows.Add(new DestListEntry
                    {
                        Hostname = host, LastAccessUtc = lastUtc, PinStatus = pin,
                        EntryNumber = entryNum.ToString(CultureInfo.InvariantCulture),
                        Note = "DestList path overruns the stream. This entry path was not guessed.",
                    });
                    break;
                }
                var path = pathBytes > 0 ? Encoding.Unicode.GetString(b, (int)pos + pathOff, pathBytes) : "";
                rows.Add(new DestListEntry
                {
                    Supported = path.Length > 0, Identity = path, Hostname = host, LastAccessUtc = lastUtc, PinStatus = pin,
                    EntryNumber = entryNum.ToString(CultureInfo.InvariantCulture),
                    Note = $"DestList v{ver} path. LastAccessUtc is the DestList FILETIME at offset 100, not the LNK timestamps.",
                });
                pos = pos + pathOff + pathBytes + (ver == 1 ? 0 : 4);
                parsed++;
            }
            return rows;
        }
    }
}
