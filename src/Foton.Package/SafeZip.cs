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
        /// A skipped entry is never written, so its ".." steps, device names, and length are not checked; a rooted or
        /// drive-qualified name still refuses the archive, and every other entry is checked before anything is written.
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
            // Full, not GetFullPath: a destination of 260 characters or more throws in GetFullPath, and the prefix is added at the call.
            var root = LongPath.Full(destination).TrimEnd('\\') + "\\";
            var measureRoot = finalDestination == null ? root : LongPath.Full(finalDestination).TrimEnd('\\') + "\\";
            // The archive path can be past 260 characters too (a deep local copy); the open takes the prefixed form.
            using (var zip = ZipFile.OpenRead(LongPath.For(LongPath.Full(zipPath))))
            {
                // Two passes. The first checks every entry and plans what to write; the second writes. A refused archive
                // therefore writes nothing, instead of leaving the entries that came before the unsafe one.
                var plan = new List<Planned>();
                var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in zip.Entries)
                {
                    var name = entry.FullName.Replace('/', '\\');
                    if (name.Length == 0) continue;
                    // A rooted or drive-qualified name refuses the archive even when the entry would be skipped.
                    if (Path.IsPathRooted(name) || name.IndexOf(':') >= 0)
                        throw new InvalidDataException("Unsafe ZIP entry (rooted path): " + entry.FullName);
                    // Skipped entries are never written, so they skip the containment check (and any over-long path).
                    var stored = entry.FullName.Replace('\\', '/');
                    if (skipPrefixes != null && skipPrefixes.Any(p => stored.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
                    // Built lexically: GetFullPath throws for a path of 260 characters or more under net462, and the
                    // tool root's rule files are that long. A ".." step above root is refused, so the result stays inside root.
                    var target = Contained(root, name, entry.FullName);
                    if (target == null) continue;
                    var measured = measureRoot + target.Substring(root.Length);
                    var parent = target.Substring(0, target.LastIndexOf('\\'));
                    if (tooLong != null && (Math.Max(target.Length, measured.Length) > 259 || measured.Substring(0, measured.LastIndexOf('\\')).Length > 247 || parent.Length > 247))
                    {
                        tooLong.Add(entry.FullName);
                        continue;
                    }
                    var isFolder = name.EndsWith("\\", StringComparison.Ordinal);
                    // Two entries for one file (or a\b and a\.\b) would fail on the second write, after the first was already
                    // on disk. Refused here instead, with nothing written.
                    if (!isFolder && !files.Add(target)) throw new InvalidDataException("Unsafe ZIP entry (two entries for one file): " + entry.FullName);
                    plan.Add(new Planned { Entry = entry, Target = target, Parent = parent, IsFolder = isFolder });
                }
                // The destination is created only now, so a refused archive leaves no folder behind either.
                Directory.CreateDirectory(LongPath.For(root));
                foreach (var p in plan)
                {
                    if (p.IsFolder) { Directory.CreateDirectory(LongPath.For(p.Target)); continue; }
                    Directory.CreateDirectory(LongPath.For(p.Parent));
                    p.Entry.ExtractToFile(LongPath.For(p.Target), overwrite: false);
                }
            }
        }

        /// <summary>One entry that passed the checks, with where it goes.</summary>
        sealed class Planned
        {
            public ZipArchiveEntry Entry = null!;
            public string Target = "";
            public string Parent = "";
            public bool IsFolder;
        }

        static readonly HashSet<string> DeviceNames = new HashSet<string>(new[]
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        }, StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The full path an entry lands on, built from its segments without touching the file system. Empty and "."
        /// segments are dropped. A ".." segment steps back one segment, so a\..\b lands on b, as it does on disk; a step
        /// above the folder is refused (the entry would leave it). Returns null for an entry that names the folder itself.
        /// Root ends with a backslash.
        /// </summary>
        static string? Contained(string root, string name, string stored)
        {
            var parts = new List<string>();
            foreach (var seg in name.Split('\\'))
            {
                if (seg.Length == 0 || seg == ".") continue;
                if (seg == "..")
                {
                    if (parts.Count == 0) throw new InvalidDataException("Unsafe ZIP entry (outside the extraction folder): " + stored);
                    parts.RemoveAt(parts.Count - 1);
                    continue;
                }
                // Windows maps CON, NUL, COM1 and the like to devices even with an extension (nul.txt is the null device), so such a
                // segment would write to a device instead of a file. Trailing spaces are ignored by Windows, so they are trimmed too.
                if (DeviceNames.Contains(seg.Split('.')[0].TrimEnd(' ')))
                    throw new InvalidDataException("Unsafe ZIP entry (Windows device name): " + stored);
                // Windows drops trailing dots and spaces from a name, so a segment that is only dots and spaces ("...", ".. ")
                // names the folder or a parent. It is refused rather than guessed at. A name with other characters (".. x") is a
                // plain name and is allowed.
                if (seg.Trim('.', ' ').Length == 0) throw new InvalidDataException("Unsafe ZIP entry (outside the extraction folder): " + stored);
                parts.Add(seg);
            }
            return parts.Count == 0 ? null : root.TrimEnd('\\') + "\\" + string.Join("\\", parts);
        }
    }
}
