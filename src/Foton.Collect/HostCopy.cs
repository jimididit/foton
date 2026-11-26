using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect
{
    /// <summary>One file a task copied (or tried to copy) into the package. Status is a fact about the attempt.</summary>
    public sealed class CopyRow : ICopyRow
    {
        public string SourcePath { get; set; } = "";
        public string DestRelative { get; set; } = "";
        public long SizeBytes { get; set; }
        public string SHA256 { get; set; } = "";
        public string Status { get; set; } = "";
        public string Note { get; set; } = "";
    }

    /// <summary>A file to copy and where it goes under the task's destination directory.</summary>
    public sealed class CopyItem
    {
        public CopyItem(string sourcePath, string destRelative) { SourcePath = sourcePath; DestRelative = destRelative; }
        public string SourcePath { get; }
        public string DestRelative { get; }
    }

    /// <summary>
    /// Copies live host files into the package (Copy-FotonHostFile and its capped / family / list variants, and
    /// Save-FotonRegistryHive). Sources are opened read-only with FileShare.ReadWrite; the only writes are the
    /// destination files. A source path that is not plainly local is recorded and never opened. Caps keep a busy host
    /// from filling the output volume; the inventory CSVs still list what was not copied.
    /// </summary>
    public static class HostCopy
    {
        const string MissingNote = "Source leaf not found. Visibility gap, not proof it never existed on the host.";
        const string NonLocalNote = "Non-local source refused. Collect does not follow remote paths (NTLM / network footprint).";

        // SRUDB.dat and similar ESE/WAL files can be briefly exclusive-locked by the host writer. A few short
        // retries avoid a one-off CopyError that leaves SrumECmd with NoInput on an otherwise healthy package.
        const int CopyAttempts = 5;

        /// <summary>
        /// Caps the total time a single collection call spends waiting on held locks. Each file still gets its own
        /// retry budget until the call's total reaches the cap; after that, further locked files get one attempt. A
        /// directory full of held files therefore costs about the cap in total, not one budget per file, and a brief
        /// lock on a later file is still retried while the cap has room.
        /// </summary>
        internal sealed class LockGate
        {
            public const int DefaultCapMs = 5000;

            public LockGate(int capMs = DefaultCapMs) { CapMs = capMs; }

            public int CapMs { get; }
            public int SleptMs { get; private set; }

            /// <summary>Reserves a wait; false when it would take the call past its cap.</summary>
            public bool TryReserve(int ms)
            {
                if (SleptMs + ms > CapMs) return false;
                SleptMs += ms;
                return true;
            }
        }

        /// <summary>Copy-FotonHostFile: Copied / Missing / CopyError, with size and SHA-256 of the copy.</summary>
        public static CopyRow CopyFile(string source, string destination, bool skipHashing) =>
            CopyFile(source, destination, skipHashing, null, null);

        /// <summary>
        /// The copy with its lock gate and an optional hook that runs before each attempt (tests use it to release a
        /// lock at a chosen attempt, so the retry is exercised without timing).
        /// </summary>
        internal static CopyRow CopyFile(string source, string destination, bool skipHashing, LockGate? gate, Action<int>? beforeAttempt)
        {
            var row = new CopyRow { SourcePath = source, Status = "CopyError" };
            if (string.IsNullOrWhiteSpace(source) || !Hashing.IsLocalPath(source) || !LeafExists(source))
            {
                row.Status = "Missing";
                row.Note = "Source leaf not found. Visibility gap, not proof the artifact never existed on the host.";
                return row;
            }
            if (Hashing.IsCloudPlaceholder(source))
            {
                row.Status = "SkippedCloudPlaceholder";
                row.Note = "Cloud-only placeholder (for example OneDrive Files On-Demand). Not copied: reading it would download it to the host.";
                return row;
            }
            Exception? last = null;
            for (int attempt = 1; ; attempt++)
            {
                beforeAttempt?.Invoke(attempt);
                try
                {
                    var dir = Path.GetDirectoryName(destination);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    using (var src = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var dst = File.Create(destination))
                        src.CopyTo(dst);
                    row.SizeBytes = new FileInfo(destination).Length;
                    row.SHA256 = Hashing.SafeHash(destination, skipHashing);
                    row.Status = "Copied";
                    row.Note = attempt == 1
                        ? "Copied with FileShare.ReadWrite. Do not parse the live path."
                        : F("Copied with FileShare.ReadWrite after {0} attempts (transient lock). Do not parse the live path.", attempt);
                    return row;
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException || ex is ArgumentException || ex is System.Security.SecurityException)
                {
                    last = ex;
                    try { if (File.Exists(destination)) File.Delete(destination); } catch (Exception) { }
                    // Only a sharing or lock violation is worth waiting for. Access denied, not found, and bad
                    // arguments are permanent for this run: record them at once instead of sleeping the budget.
                    if (!IsTransientLock(ex) || attempt >= CopyAttempts)
                        break;
                    // Per-file budget: 100+200+300+400 ms (about 1 s). Under a gate, the call's total wait is also capped.
                    var wait = 100 * attempt;
                    if (gate != null && !gate.TryReserve(wait))
                        break;
                    System.Threading.Thread.Sleep(wait);
                }
            }
            row.Status = "CopyError";
            // The loop leaves only through the catch above, so a failure always has an exception to report.
            row.Note = last!.Message;
            return row;
        }

        // Win32 ERROR_SHARING_VIOLATION (32) and ERROR_LOCK_VIOLATION (33) as HRESULTs in the FACILITY_WIN32 range
        // (0x8007xxxx). Matching the low word alone would also retry unrelated HRESULTs that end in 0x20 or 0x21.
        internal static bool IsTransientLock(Exception ex)
        {
            if (!(ex is IOException) || (ex.HResult & unchecked((int)0xFFFF0000)) != unchecked((int)0x80070000)) return false;
            var code = ex.HResult & 0xFFFF;
            return code == 32 || code == 33;
        }

        static bool LeafExists(string path)
        {
            try { return File.Exists(path); }
            catch (Exception) { return false; }
        }

        static long LengthOf(string path)
        {
            try { return new FileInfo(path).Length; }
            catch (Exception) { return 0; }
        }

        static DateTime WriteTimeOf(string path)
        {
            try { return File.GetLastWriteTimeUtc(path); }
            catch (Exception) { return DateTime.MinValue; }
        }

        static string Rel(string packageRelativeDirectory, string leaf) =>
            string.IsNullOrEmpty(packageRelativeDirectory) ? leaf : Path.Combine(packageRelativeDirectory, leaf);

        /// <summary>Copy-FotonCappedHostFiles: newest-first files matching a filter in one directory (Prefetch).</summary>
        public static List<CopyRow> CappedDirectory(string sourceDirectory, string filter, string destinationDirectory, string packageRelativeDirectory,
            bool skipHashing, int maxFiles = 1024, long maxTotalBytes = 83886080,
            string missingNote = "Source directory not found. Prefetch is often disabled or the token cannot see it.")
        {
            var rows = new List<CopyRow>();
            if (!Hashing.IsLocalPath(sourceDirectory) || !Directory.Exists(sourceDirectory))
            {
                rows.Add(new CopyRow { SourcePath = sourceDirectory, Status = "Missing", Note = missingNote });
                return rows;
            }
            FileInfo[] files;
            try { files = new DirectoryInfo(sourceDirectory).GetFiles(filter).OrderByDescending(f => f.LastWriteTimeUtc).ToArray(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { files = new FileInfo[0]; }
            if (files.Length == 0)
            {
                rows.Add(new CopyRow { SourcePath = sourceDirectory, Status = "NoData", Note = "Directory existed but no files matched the filter." });
                return rows;
            }
            int copied = 0;
            long used = 0;
            var gate = new LockGate();
            foreach (var f in files)
            {
                string? skip = copied >= maxFiles ? $"Capped at MaxFiles={maxFiles}. Prefer the listing CSV for names not copied."
                    : used + f.Length > maxTotalBytes ? $"Capped at MaxTotalBytes={maxTotalBytes}. Prefer the listing CSV for names not copied." : null;
                if (skip != null)
                {
                    rows.Add(new CopyRow { SourcePath = f.FullName, SizeBytes = f.Length, Status = "CappedSkip", Note = skip });
                    continue;
                }
                var copy = CopyFile(f.FullName, Path.Combine(destinationDirectory, f.Name), skipHashing, gate, null);
                copy.DestRelative = Rel(packageRelativeDirectory, f.Name);
                rows.Add(copy);
                if (copy.Status == "Copied") { copied++; used += copy.SizeBytes; }
            }
            return rows;
        }

        /// <summary>
        /// Copy-FotonHostFileFamily: a primary file plus same-directory sidecars whose names start with its name
        /// (hive .LOG1/.LOG2/.regtrans-ms, ESE logs), primary first, within a byte budget.
        /// </summary>
        public static List<CopyRow> Family(string sourcePath, string destinationDirectory, string packageRelativeDirectory, bool skipHashing, long maxTotalBytes = 104857600)
        {
            var rows = new List<CopyRow>();
            if (!Hashing.IsLocalPath(sourcePath) || !LeafExists(sourcePath))
            {
                rows.Add(new CopyRow { SourcePath = sourcePath, Status = "Missing", Note = "Primary file not found. Visibility gap, not proof it was never present." });
                return rows;
            }
            var leaf = Path.GetFileName(sourcePath).ToLowerInvariant();
            FileInfo[] family;
            try
            {
                family = new DirectoryInfo(Path.GetDirectoryName(sourcePath)!).GetFiles()
                    .Where(f => f.Name.ToLowerInvariant().StartsWith(leaf, StringComparison.Ordinal))
                    .OrderBy(f => f.Name.ToLowerInvariant() == leaf ? 0 : 1).ThenBy(f => f.Name, StringComparer.InvariantCultureIgnoreCase).ToArray();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { family = new FileInfo[0]; }
            long budget = maxTotalBytes;
            var gate = new LockGate();
            foreach (var f in family)
            {
                if (f.Length > budget)
                {
                    rows.Add(new CopyRow { SourcePath = f.FullName, SizeBytes = f.Length, Status = "CappedSkip", Note = "File exceeds remaining copy budget. Full file remains on the host; this package is a capped copy." });
                    continue;
                }
                var copy = CopyFile(f.FullName, Path.Combine(destinationDirectory, f.Name), skipHashing, gate, null);
                copy.DestRelative = Rel(packageRelativeDirectory, f.Name);
                rows.Add(copy);
                if (copy.Status == "Copied") budget -= copy.SizeBytes;
            }
            return rows;
        }

        static readonly Regex DotDot = new Regex(@"(^|[\\/])\.\.([\\/]|$)");

        /// <summary>
        /// Copy-FotonCappedHostFileList: an explicit list, newest first, within count and byte caps. DestRelative may
        /// hold subfolders; one that would leave the destination directory is refused.
        /// </summary>
        public static List<CopyRow> CappedList(IEnumerable<CopyItem> items, string destinationDirectory, string packageRelativeDirectory, bool skipHashing,
            int maxFiles = 400, long maxTotalBytes = 83886080)
        {
            var rows = new List<CopyRow>();
            var list = items.ToList();
            if (list.Count == 0)
            {
                rows.Add(new CopyRow { Status = "NoData", Note = "No source paths were queued. Visibility gap, not proof the artifact class was empty." });
                return rows;
            }
            var sorted = list.OrderByDescending(i => Hashing.IsLocalPath(i.SourcePath) && LeafExists(i.SourcePath) ? WriteTimeOf(i.SourcePath) : DateTime.MinValue).ToList();
            var rootFull = Path.GetFullPath(destinationDirectory).TrimEnd('\\');
            int copied = 0;
            long used = 0;
            var gate = new LockGate();
            foreach (var it in sorted)
            {
                var src = it.SourcePath;
                var relLeaf = it.DestRelative.Length > 0 ? it.DestRelative : SafeFileName(src);
                if (src.Length > 0 && !Hashing.IsLocalPath(src))
                {
                    rows.Add(new CopyRow { SourcePath = src, DestRelative = relLeaf, Status = "SkippedUnc", Note = NonLocalNote });
                    continue;
                }
                if (DotDot.IsMatch(relLeaf))
                {
                    rows.Add(new CopyRow { SourcePath = src, DestRelative = relLeaf, Status = "CopyError", Note = "DestRelative contained .. segments; refused to prevent package-directory escape." });
                    continue;
                }
                if (src.Length == 0 || !LeafExists(src))
                {
                    rows.Add(new CopyRow { SourcePath = src, DestRelative = relLeaf, Status = "Missing", Note = MissingNote });
                    continue;
                }
                var len = LengthOf(src);
                string? skip = copied >= maxFiles ? $"Capped at MaxFiles={maxFiles}. Inventory CSVs still list names that were not copied."
                    : used + len > maxTotalBytes ? $"Capped at MaxTotalBytes={maxTotalBytes}. Inventory CSVs still list names that were not copied." : null;
                if (skip != null)
                {
                    rows.Add(new CopyRow { SourcePath = src, DestRelative = relLeaf, SizeBytes = len, Status = "CappedSkip", Note = skip });
                    continue;
                }
                var fitted = FitLeaf(rootFull, packageRelativeDirectory, relLeaf);
                string destFull;
                try { destFull = Path.GetFullPath(Path.Combine(destinationDirectory, fitted)); }
                catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException) { destFull = ""; }
                if (destFull.Length == 0 || !destFull.StartsWith(rootFull + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    rows.Add(new CopyRow { SourcePath = src, DestRelative = relLeaf, SizeBytes = len, Status = "CopyError", Note = "Resolved destination left DestinationDirectory; copy refused." });
                    continue;
                }
                var copy = CopyFile(src, destFull, skipHashing, gate, null);
                copy.DestRelative = Rel(packageRelativeDirectory, fitted);
                if (copy.Status == "Copied" && !string.Equals(fitted, relLeaf, StringComparison.Ordinal))
                    copy.Note += F(" Name shortened to keep the path inside the package under {0} characters (Windows tools and ZIP extraction fail on longer paths); SourcePath holds the original name.", MaxPackagePath);
                rows.Add(copy);
                if (copy.Status == "Copied") { copied++; used += copy.SizeBytes; }
            }
            return rows;
        }

        // Windows APIs on .NET Framework refuse paths of 260+ characters. A package is also extracted elsewhere
        // (beside the ZIP as <name>-extracted\<case>, or wherever the analyst extracts it), so the path inside the case
        // folder keeps room for that root too.
        internal const int MaxPackagePath = 160;
        const int MaxFullPath = 259;

        static string F(string format, params object[] args) => string.Format(System.Globalization.CultureInfo.InvariantCulture, format, args);

        /// <summary>
        /// The leaf of <paramref name="relLeaf"/>, shortened when the copy's path inside the package or on disk would be
        /// too long: a stem prefix, "~", eight hex digits of the original leaf's SHA-256, and the original extension.
        /// Unchanged when it fits, or when even a shortened leaf cannot (the copy then fails and is recorded).
        /// </summary>
        internal static string FitLeaf(string destinationRoot, string packageRelativeDirectory, string relLeaf)
        {
            var inPackage = Rel(packageRelativeDirectory, relLeaf).Length;
            var onDisk = destinationRoot.Length + 1 + relLeaf.Length;
            var over = Math.Max(inPackage - MaxPackagePath, onDisk - MaxFullPath);
            if (over <= 0) return relLeaf;
            var cut = relLeaf.LastIndexOfAny(new[] { '\\', '/' });
            var dir = cut >= 0 ? relLeaf.Substring(0, cut + 1) : "";
            var leaf = relLeaf.Substring(cut + 1);
            var ext = Path.GetExtension(leaf);
            if (ext.Length > 16) ext = "";
            var stem = leaf.Substring(0, leaf.Length - ext.Length);
            string tag;
            using (var sha = System.Security.Cryptography.SHA256.Create())
                tag = "~" + BitConverter.ToString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(leaf)), 0, 4).Replace("-", "");
            var keep = leaf.Length - over - tag.Length - ext.Length;
            if (keep < 1 || keep >= stem.Length) return relLeaf;
            return dir + stem.Substring(0, keep).TrimEnd(' ', '.') + tag + ext;
        }

        static string SafeFileName(string path)
        {
            try { return Path.GetFileName(path); }
            catch (ArgumentException) { return ""; }
        }

        /// <summary>
        /// Save-FotonRegistryHive: reg save of a loaded hive (the kernel holds loaded hive files exclusively, so a file
        /// copy fails). Needs an Administrator token; callers run it only in elevated tasks.
        /// </summary>
        public static CopyRow SaveHive(string registryPath, string destination, string packageRelativePath, bool skipHashing)
        {
            var row = new CopyRow { SourcePath = registryPath, DestRelative = packageRelativePath, Status = "SaveError" };
            if (registryPath.IndexOf('"') >= 0 || destination.IndexOf('"') >= 0)
            {
                row.DestRelative = "";
                row.Note = "Refused: a quote in the key or destination would change the reg.exe arguments.";
                return row;
            }
            try
            {
                var dir = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var output = Exec.System32("reg.exe", $"save \"{registryPath}\" \"{destination}\" /y", out var code, 600000);
                if (code != 0 || !File.Exists(destination))
                {
                    row.DestRelative = "";
                    row.Note = $"reg save exit {code}: {output.Trim()}";
                    try { if (File.Exists(destination)) File.Delete(destination); } catch (Exception) { }
                    return row;
                }
                row.SizeBytes = new FileInfo(destination).Length;
                row.SHA256 = Hashing.SafeHash(destination, skipHashing);
                row.Status = "Saved";
                row.Note = "Exported with reg save (consistent image of the loaded hive; no transaction logs needed).";
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                row.DestRelative = "";
                row.Note = ex.Message;
            }
            return row;
        }

        static readonly Regex Unsafe = new Regex(@"[\\/:*?""<>|]");

        /// <summary>Get-FotonSafePathSegment: a user name usable as one folder name ("." and ".." are not folder names).</summary>
        public static string SafeSegment(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "unknown";
            var s = Unsafe.Replace(name, "_").Trim();
            return s.Length == 0 ? "unknown" : s.Trim('.').Length == 0 ? new string('_', s.Length) : s;
        }

        static readonly Regex SidForm = new Regex(@"^S-1-\d+(-\d+)+$");

        /// <summary>A profile SID that is safe to pass to reg.exe (ProfileList key names are host data).</summary>
        public static bool IsSid(string sid) => SidForm.IsMatch(sid);
    }
}
