using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Foton.Core;

namespace Foton.Package
{
    /// <summary>
    /// Extracts a package ZIP, refusing any entry that would land outside the destination (zip-slip:
    /// "..\" segments, rooted or drive-qualified names). A case ZIP is untrusted input: it came off a
    /// possibly compromised host.
    /// </summary>
    public static class SafeZip
    {
        public static void Extract(string zipPath, string destination) => Extract(zipPath, destination, null);

        /// <summary>
        /// As Extract, skipping entries whose stored path (forward slashes) starts with one of <paramref name="skipPrefixes"/>.
        /// Every entry is still checked for an unsafe path first.
        /// </summary>
        public static void Extract(string zipPath, string destination, IReadOnlyCollection<string>? skipPrefixes) =>
            Extract(zipPath, destination, skipPrefixes, null);

        /// <summary>
        /// As Extract; when <paramref name="tooLong"/> is given, an entry whose extracted path would reach the Windows
        /// 260-character limit is listed there (stored name) and not written, instead of failing the whole extraction.
        /// <paramref name="finalDestination"/> is where the folder ends up when it is renamed after extraction: lengths are
        /// measured there, so nothing extracted becomes unreachable after the rename.
        /// </summary>
        public static void Extract(string zipPath, string destination, IReadOnlyCollection<string>? skipPrefixes, List<string>? tooLong,
            string? finalDestination = null)
        {
            var root = Path.GetFullPath(destination).TrimEnd('\\') + "\\";
            var measureRoot = finalDestination == null ? root : Path.GetFullPath(finalDestination).TrimEnd('\\') + "\\";
            Directory.CreateDirectory(root);
            using (var zip = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    var name = entry.FullName.Replace('/', '\\');
                    if (name.Length == 0) continue;
                    if (Path.IsPathRooted(name) || name.IndexOf(':') >= 0)
                        throw new InvalidDataException("Unsafe ZIP entry (rooted path): " + entry.FullName);
                    // Skipped entries are never written, so they skip the containment check (and any over-long path).
                    var stored = entry.FullName.Replace('\\', '/');
                    if (skipPrefixes != null && skipPrefixes.Any(p => stored.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
                    // Built lexically: GetFullPath throws for a path of 260 characters or more under net462, and the
                    // tool root's rule files are that long. A ".." segment is refused outright, so the result stays inside root.
                    var target = Contained(root, name, entry.FullName);
                    if (target == null) continue;
                    var measured = measureRoot + target.Substring(root.Length);
                    var parent = target.Substring(0, target.LastIndexOf('\\'));
                    if (tooLong != null && (Math.Max(target.Length, measured.Length) > 259 || measured.Substring(0, measured.LastIndexOf('\\')).Length > 247 || parent.Length > 247))
                    {
                        tooLong.Add(entry.FullName);
                        continue;
                    }
                    if (name.EndsWith("\\", StringComparison.Ordinal)) { Directory.CreateDirectory(LongPath.For(target)); continue; }
                    Directory.CreateDirectory(LongPath.For(parent));
                    entry.ExtractToFile(LongPath.For(target), overwrite: false);
                }
            }
        }

        /// <summary>
        /// The full path an entry lands on, built from its segments without touching the file system. Empty and "."
        /// segments are dropped; a ".." segment is refused (the entry would leave the folder). Returns null for an entry
        /// that names the folder itself. Root ends with a backslash.
        /// </summary>
        static string? Contained(string root, string name, string stored)
        {
            var target = root.TrimEnd('\\');
            var any = false;
            foreach (var seg in name.Split('\\'))
            {
                if (seg.Length == 0 || seg == ".") continue;
                if (seg == "..") throw new InvalidDataException("Unsafe ZIP entry (outside the extraction folder): " + stored);
                target += "\\" + seg;
                any = true;
            }
            return any ? target : null;
        }
    }
}
