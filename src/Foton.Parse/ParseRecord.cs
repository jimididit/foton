using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using Foton.Core;

namespace Foton.Parse
{
    /// <summary>
    /// One parser output row. Format names the layout that was read; Supported is false whenever a field
    /// would have to be guessed, and Note says why. Parser-specific fields live in Fields.
    /// </summary>
    public sealed class ParseRecord
    {
        public string SourcePath { get; set; } = "";
        public long SizeBytes { get; set; }
        public string SHA256 { get; set; } = "";
        public string Format { get; set; } = "Unknown";
        public bool Supported { get; set; }
        /// <summary>What the row is about (executable name, target path, event id|record id), or "".</summary>
        public string Identity { get; set; } = "";
        public string Note { get; set; } = "";
        public Dictionary<string, string> Fields { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string Field(string name) => Fields.TryGetValue(name, out var v) ? v : "";

        internal static ParseRecord For(string path, long size, string sha) => new ParseRecord { SourcePath = path, SizeBytes = size, SHA256 = sha };
    }

    /// <summary>Little-endian readers and FILETIME conversion over byte buffers. Out-of-range reads never guess.</summary>
    static class Bin
    {
        /// <summary>FILETIME at offset as "yyyy-MM-dd HH:mm:ss" UTC; "(not set)" when absent or zero, "(unparsed)" when invalid.</summary>
        public static string FileTimeUtc(byte[]? b, long offset)
        {
            if (b == null || offset < 0 || b.Length < offset + 8) return "(not set)";
            long ticks = BitConverter.ToInt64(b, (int)offset);
            if (ticks <= 0) return "(not set)";
            try { return DateTime.FromFileTimeUtc(ticks).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture); }
            catch (ArgumentOutOfRangeException) { return "(unparsed)"; }
        }

        public static bool Fits(byte[] b, long offset, int length) => offset >= 0 && offset + length <= b.Length;

        /// <summary>Bytes as Latin-1 characters, what PowerShell's [char]$byte produced.</summary>
        public static string Latin1(byte[] b, int start, int end)
        {
            var sb = new StringBuilder(end - start);
            for (int i = start; i < end; i++) sb.Append((char)b[i]);
            return sb.ToString();
        }

        public static string Sha256(string path)
        {
            try { return Hashing.Sha256Hex(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return "HASH_ERROR"; }
        }
    }
}
