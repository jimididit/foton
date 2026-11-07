using System;
using System.IO;
using System.Text;
using Foton.Core;

namespace Foton.Parse
{
    /// <summary>
    /// Prefetch (.pf) copied off the host (ConvertFrom-FotonPrefetch). Uncompressed SCCA v17/23/26/30: executable
    /// name from the header. Windows 10+ MAM-compressed files are recorded as such, never inflated or guessed.
    /// </summary>
    public static class PrefetchParser
    {
        public static ParseRecord Parse(string path)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full)) throw new FileNotFoundException("Prefetch file not found: " + path, path);
            var bytes = File.ReadAllBytes(full);
            var r = ParseRecord.For(full, bytes.Length, Hashing.Sha256Hex(bytes));
            r.Fields["ExecutableName"] = "";
            if (bytes.Length < 8)
            {
                r.Format = "Unsupported-TooSmall";
                r.Note = "File is shorter than a Prefetch header. Do not invent timestamps.";
                return r;
            }
            var magic = Encoding.ASCII.GetString(bytes, 0, 4);
            if (bytes[0] == 0x4D && bytes[1] == 0x41 && bytes[2] == 0x4D)
            {
                r.Format = "MAM-compressed";
                r.Note = "Win10+ Prefetch is compressed. This parser does not inflate MAM; use an offline decompressor then re-run. Absence of a parsed name is a format limit, not evidence the file is empty.";
                return r;
            }
            if (!string.Equals(magic, "SCCA", StringComparison.OrdinalIgnoreCase))
            {
                r.Format = "Unsupported-NotPrefetch";
                r.Note = "Header is not SCCA or MAM. Wrong fields would be worse than this record.";
                return r;
            }
            int version = BitConverter.ToInt32(bytes, 4);
            r.Fields["Version"] = version.ToString(System.Globalization.CultureInfo.InvariantCulture);
            r.Format = "SCCA";
            var name = "";
            if (bytes.Length >= 0x4C && (version == 17 || version == 23 || version == 26 || version == 30))
                name = Encoding.Unicode.GetString(bytes, 0x10, 60).Trim('\0');
            if (name.Length > 0)
            {
                r.Supported = true;
                r.Identity = name;
                r.Fields["ExecutableName"] = name;
                r.Note = "Name from uncompressed SCCA header. Run count and timestamps are not parsed in this version.";
            }
            else r.Note = $"SCCA version {version} name layout is not implemented. Recorded as unsupported rather than guessed.";
            return r;
        }
    }

    /// <summary>Shell Link (.lnk) LinkInfo LocalBasePath. Does not execute or resolve the shortcut.</summary>
    public static class LnkParser
    {
        public sealed class Result
        {
            public string Format { get; internal set; } = "Unknown";
            public bool Supported { get; internal set; }
            public string LocalBasePath { get; internal set; } = "";
            public string Note { get; internal set; } = "";
        }

        public static ParseRecord Parse(string path)
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full)) throw new FileNotFoundException("LNK file not found: " + path, path);
            var bytes = File.ReadAllBytes(full);
            var p = FromBytes(bytes);
            var r = ParseRecord.For(full, bytes.Length, Hashing.Sha256Hex(bytes));
            r.Format = p.Format;
            r.Supported = p.Supported;
            r.Identity = p.LocalBasePath;
            r.Note = p.Note;
            r.Fields["LocalBasePath"] = p.LocalBasePath;
            return r;
        }

        /// <summary>Get-FotonLnkParseFromBytes: LinkInfo ANSI LocalBasePath from a Shell Link buffer.</summary>
        public static Result FromBytes(byte[]? b)
        {
            var r = new Result();
            if (b == null || b.Length < 0x4C)
            {
                r.Format = "Unsupported-TooSmall";
                r.Note = "Shorter than a Shell Link header. Path not guessed.";
                return r;
            }
            if (BitConverter.ToUInt32(b, 0) != 0x4C)
            {
                r.Format = "Unsupported-NotLnk";
                r.Note = "HeaderSize is not 0x4C. Wrong fields would be worse than this record.";
                return r;
            }
            r.Format = "LNK";
            uint flags = BitConverter.ToUInt32(b, 20);
            long pos = 0x4C;
            if ((flags & 0x01) != 0)
            {
                if (pos + 2 > b.Length) return Stopped(r, "truncated IDList");
                pos = pos + 2 + BitConverter.ToUInt16(b, (int)pos);
            }
            if ((flags & 0x02) != 0)
            {
                if (pos + 20 > b.Length) return Stopped(r, "truncated LinkInfo");
                uint localOff = BitConverter.ToUInt32(b, (int)pos + 16);
                long at = pos + localOff;
                if (at >= b.Length || localOff == 0)
                {
                    r.Note = "LinkInfo present but LocalBasePath offset is empty or past EOF.";
                    return r;
                }
                int end = (int)at;
                while (end < b.Length && b[end] != 0) end++;
                r.LocalBasePath = Bin.Latin1(b, (int)at, end);
                if (r.LocalBasePath.Length > 0)
                {
                    r.Supported = true;
                    r.Note = "LocalBasePath from LinkInfo (ANSI). Arguments and timestamps are not parsed in this version.";
                }
                else r.Note = "LinkInfo contained no ANSI local path.";
                return r;
            }
            r.Note = "No LinkInfo block (flags). Network or IDList-only shortcuts are not expanded here.";
            return r;
        }

        static Result Stopped(Result r, string why)
        {
            r.Note = $"Parse stopped: {why}. Partial fields are not invented.";
            return r;
        }
    }
}
