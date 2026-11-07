using System;
using System.IO;
using System.IO.Compression;

namespace Foton.Package
{
    /// <summary>
    /// Extracts a package ZIP, refusing any entry that would land outside the destination (zip-slip:
    /// "..\" segments, rooted or drive-qualified names). A case ZIP is untrusted input: it came off a
    /// possibly compromised host.
    /// </summary>
    public static class SafeZip
    {
        public static void Extract(string zipPath, string destination)
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
                    var target = Path.GetFullPath(Path.Combine(root, name));
                    if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Unsafe ZIP entry (outside the extraction folder): " + entry.FullName);
                    if (name.EndsWith("\\", StringComparison.Ordinal)) { Directory.CreateDirectory(target); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    entry.ExtractToFile(target, overwrite: false);
                }
            }
        }
    }
}
