using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Foton.Core;

namespace Foton.Tools
{
    /// <summary>
    /// tools.json under the Foton tool root (Get-FotonToolRoot / Save-FotonToolManifestEntry): every pinned install
    /// and registered folder, so compose finds tools without PATH changes. Same file and shape as 1.38.x, so either
    /// version reads the other's registrations. Rows are kept as maps, so fields this version does not know survive
    /// a rewrite.
    /// </summary>
    public static class ToolManifest
    {
        public const string FileName = "tools.json";

        /// <summary>%LOCALAPPDATA%\Foton\tools unless overridden. Not PATH, not inside a case.</summary>
        public static string Root(string? toolRoot)
        {
            // LongPath.Full, not GetFullPath: a tool root of 260 characters or more is valid (install and compose work under it).
            if (!string.IsNullOrWhiteSpace(toolRoot)) return LongPath.Full(toolRoot!.Trim());
            var baseDir = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(baseDir))
                baseDir = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? "", "AppData", "Local");
            return LongPath.Full(Path.Combine(baseDir, "Foton", "tools"));
        }

        public static string PathOf(string? toolRoot) => Path.Combine(Root(toolRoot), FileName);

        /// <summary>Every row; empty when the file is missing or unreadable.</summary>
        public static IReadOnlyList<Dictionary<string, object?>> List(string? toolRoot)
        {
            var path = PathOf(toolRoot);
            if (!File.Exists(LongPath.For(path))) return new Dictionary<string, object?>[0];
            return TryRead(path) ?? new Dictionary<string, object?>[0];
        }

        /// <summary>The rows in the file at path; null when it cannot be read or parsed (never "no rows").</summary>
        static IReadOnlyList<Dictionary<string, object?>>? TryRead(string path)
        {
            try
            {
                var doc = Json.Parse(File.ReadAllText(LongPath.For(path), Encoding.UTF8));
                // A file with no Installed list is not one this version (or 1.38.x) wrote; refuse it rather than read it as empty.
                if (!(doc is IDictionary d) || !d.Contains("Installed")) return null;
                return Rows(doc);
            }
            // Broad on purpose: the serializer and the file read can throw several types, and a lookup of "what is installed"
            // must report the file as unreadable, not fail the caller.
            catch (Exception)
            {
                return null;
            }
        }

        public static Dictionary<string, object?>? Find(string name, string? toolRoot)
        {
            var want = name.Trim();
            return List(toolRoot).FirstOrDefault(r => string.Equals(Get(r, "Name"), want, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Upserts one row by Name and rewrites the file. Returns the manifest path.</summary>
        public static string Save(string? toolRoot, Dictionary<string, object?> entry)
        {
            var root = Root(toolRoot);
            Directory.CreateDirectory(LongPath.For(root));
            // Read, change, and swap happen under one lock, so two installs or registrations cannot each read the old rows and
            // overwrite the other's. The swap is atomic; the lock covers the read-modify-write.
            using (AcquireLock(root))
                return SaveLocked(root, entry);
        }

        /// <summary>
        /// An exclusive handle on tools.json.lock beside the manifest, waiting up to 30 seconds. The lock is the file, not a
        /// name derived from the folder text, so every spelling of the folder (8.3 names, junctions, subst drives, other
        /// sessions) contends on the same lock. DeleteOnClose removes it, including when a process dies holding it.
        /// </summary>
        static FileStream AcquireLock(string root)
        {
            var lockPath = LongPath.For(Path.Combine(root, FileName + ".lock"));
            var started = DateTime.UtcNow;
            while (true)
            {
                try { return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    // A holder gives a sharing violation; a lock being deleted gives access denied for a moment. Real access
                    // denial (a read-only folder) is reported after a second rather than after the full wait.
                    var waited = DateTime.UtcNow - started;
                    if (waited > TimeSpan.FromSeconds(30) || (ex is UnauthorizedAccessException && waited > TimeSpan.FromSeconds(1)))
                    {
                    // Access denied that does not clear in a second is a permissions problem, not a busy lock; say so.
                    if (ex is UnauthorizedAccessException)
                        throw new IOException("Foton cannot take the write lock for the tool manifest under " + root + " (access denied). Check that the tool folder is writable.", ex);
                    throw new IOException("Another Foton process is writing the tool manifest under " + root + ". Try again in a moment.", ex);
                    }
                    Thread.Sleep(25);
                }
            }
        }

        static string SaveLocked(string root, Dictionary<string, object?> entry)
        {
            var path = Path.Combine(root, FileName);
            // A manifest that exists but cannot be read is not "no rows": rewriting it would drop every other registration.
            var existing = File.Exists(LongPath.For(path)) ? TryRead(path) : new Dictionary<string, object?>[0];
            if (existing == null)
                throw new InvalidDataException("The tool manifest at " + path + " exists but cannot be read, so it was not overwritten. Move or repair the file, then try again.");
            var rows = existing.Where(r => !string.Equals(Get(r, "Name"), Get(entry, "Name"), StringComparison.OrdinalIgnoreCase)).ToList();
            rows.Add(entry);
            var doc = new Dictionary<string, object?>
            {
                ["ToolRoot"] = root,
                ["UpdatedUtc"] = FotonTime.Format(DateTime.UtcNow),
                ["Installed"] = rows,
            };
            // Written beside the file and then swapped in, so a crash mid-write leaves the old manifest, never a half-written one.
            var temp = LongPath.For(path + ".tmp-" + Guid.NewGuid().ToString("N"));
            try
            {
                TextFile.Write(temp, Json.Indented(doc));
                // A process outside the lock (another Foton version, a hand edit) can create or remove tools.json between the
                // check and the swap. Replace needs the file to exist and Move needs it not to, so try again with the other.
                for (int attempt = 0; ; attempt++)
                {
                    try
                    {
                        if (File.Exists(LongPath.For(path))) File.Replace(temp, LongPath.For(path), null);
                        else File.Move(temp, LongPath.For(path));
                        break;
                    }
                    catch (IOException) when (attempt < 2) { Thread.Sleep(20); }
                }
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
            return path;
        }

        /// <summary>A field as text; "" when absent.</summary>
        public static string Get(IDictionary<string, object?> row, string key) =>
            row.TryGetValue(key, out var v) && v != null ? Csv.FormatValue(v) : "";

        static IReadOnlyList<Dictionary<string, object?>> Rows(object? doc)
        {
            var installed = doc is IDictionary d && d.Contains("Installed") ? d["Installed"] : null;
            var items = installed is IDictionary one ? new object[] { one } : (installed as IEnumerable)?.Cast<object?>() ?? Enumerable.Empty<object?>();
            return items.OfType<IDictionary>().Select(r =>
            {
                var row = new Dictionary<string, object?>();
                foreach (DictionaryEntry kv in r) row[Convert.ToString(kv.Key, System.Globalization.CultureInfo.InvariantCulture) ?? ""] = kv.Value;
                return row;
            }).ToList();
        }
    }
}
