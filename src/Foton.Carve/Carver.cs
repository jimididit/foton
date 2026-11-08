using System;
using System.Collections.Generic;
using System.IO;
using Foton.Core;

namespace Foton.Carve
{
    /// <summary>One signature hit. Tier 3: no path, no timestamp, and not evidence the file existed or ran.</summary>
    public sealed class CarveHit
    {
        public string SourcePath { get; set; } = "";
        public long Offset { get; set; }
        /// <summary>MZ, or PE when e_lfanew points at "PE\0\0" inside the scanned bytes.</summary>
        public string Kind { get; set; } = "";
        /// <summary>SHA-256 of up to 64 bytes from the hit, for matching against collected executables.</summary>
        public string WindowSha256 { get; set; } = "";
        public string Note { get; set; } = "";
    }

    public sealed class CarveRun
    {
        public List<CarveHit> Hits { get; } = new List<CarveHit>();
        public long BytesScanned { get; set; }
    }

    /// <summary>
    /// MZ/PE signature scan of a capped blob (Invoke-FotonCarve): an image fragment, an unallocated dump, or a sample
    /// already copied to the workstation. Not NTFS carving: no filenames, no MAC times, no FILE records. Caps keep a huge
    /// blob from hanging the analyst box. To add a signature, add a recognizer beside the MZ check and give its hits
    /// their own Kind.
    /// </summary>
    public static class Carver
    {
        public const int DefaultMaxBytes = 8 * 1024 * 1024;
        public const int DefaultMaxHits = 50;
        const int WindowBytes = 64;

        public const string HitNote = "Signature hit only. No path or timestamp. Tier 3 until a collected file hash or Prefetch/LNK name corroborates it.";

        public static CarveRun Scan(string path, int maxBytes = DefaultMaxBytes, int maxHits = DefaultMaxHits)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("Carve input not found: " + path, path);
            if (maxBytes < 0 || maxHits < 0) throw new ArgumentOutOfRangeException(maxBytes < 0 ? nameof(maxBytes) : nameof(maxHits), "Caps must not be negative.");
            var full = Path.GetFullPath(path);
            byte[] buf;
            int len;
            using (var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                buf = new byte[(int)Math.Min(fs.Length, maxBytes)];
                len = 0;
                int n;
                while (len < buf.Length && (n = fs.Read(buf, len, buf.Length - len)) > 0) len += n;
            }

            var run = new CarveRun { BytesScanned = len };
            for (int i = 0; i < len - 1 && run.Hits.Count < maxHits; i++)
            {
                if (buf[i] != 0x4D || buf[i + 1] != 0x5A) continue;
                var kind = "MZ";
                if (i + 0x40 <= len)
                {
                    long peAt = i + (long)BitConverter.ToInt32(buf, i + 0x3C);
                    if (peAt >= i && peAt + 4 <= len
                        && buf[peAt] == 0x50 && buf[peAt + 1] == 0x45 && buf[peAt + 2] == 0 && buf[peAt + 3] == 0)
                        kind = "PE";
                }
                var window = new byte[Math.Min(WindowBytes, len - i)];
                Array.Copy(buf, i, window, 0, window.Length);
                run.Hits.Add(new CarveHit { SourcePath = full, Offset = i, Kind = kind, WindowSha256 = Hashing.Sha256Hex(window), Note = HitNote });
            }
            return run;
        }
    }
}
