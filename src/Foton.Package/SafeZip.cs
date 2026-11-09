using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

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
        /// </summary>
        public static void Extract(string zipPath, string destination, IReadOnlyCollection<string>? skipPrefixes, List<string>? tooLong)
        {
            var root = Path.GetFullPath(destination).TrimEnd('\\') + "\\";
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
                    var target = Path.GetFullPath(Path.Combine(root, name));
                    if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Unsafe ZIP entry (outside the extraction folder): " + entry.FullName);
                    if (tooLong != null && (target.Length > 259 || Path.GetDirectoryName(target)!.Length > 247))
                    {
                        tooLong.Add(entry.FullName);
                        continue;
                    }
                    if (name.EndsWith("\\", StringComparison.Ordinal)) { Directory.CreateDirectory(target); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    entry.ExtractToFile(target, overwrite: false);
                }
            }
        }
    }
}
