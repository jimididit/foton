using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Package;

namespace Foton.Tools
{
    public sealed class ToolListRow
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        /// <summary>
        /// Rule set the tool runs with (Hayabusa / Chainsaw), as recorded in tools.json. For a catalog tool that is not
        /// installed, a generic note that the pinned release bundles rules, marked "(on install)". No version is shown there:
        /// the rule set is only known once the archive is downloaded, and Install records what it actually finds.
        /// Empty when the tool has no rules.
        /// </summary>
        public string RulesVersion { get; set; } = "";
        /// <summary>Installed (pinned, hash-verified), Registered (existing install, observed hash), or Catalog (not installed).</summary>
        public string Source { get; set; } = "";
        /// <summary>The executable compose will run, or the download URL for a catalog tool not yet installed.</summary>
        public string Location { get; set; } = "";
        public bool Verified { get; set; }
        public string License { get; set; } = "";
        public string ExpectedSha256 { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    /// <summary>
    /// Installs a catalog-pinned release into the Foton tool root (Install-FotonTool). Workstation setup only: never
    /// runs during compose or analyze, never changes PATH, and refuses an archive whose SHA-256 differs from the pin.
    /// </summary>
    public static class ToolInstaller
    {
        /// <summary>Pinned catalog tools (installed or not) and registered installs, one row each.</summary>
        public static IReadOnlyList<ToolListRow> List(string? toolRoot, string? catalogPath = null)
        {
            var catalog = ToolCatalog.Load(catalogPath);
            var installed = ToolManifest.List(toolRoot);
            var rows = new List<ToolListRow>();
            foreach (var entry in catalog)
            {
                var have = installed.FirstOrDefault(r => string.Equals(ToolManifest.Get(r, "Name"), entry.Name, StringComparison.OrdinalIgnoreCase));
                // A catalog tool can also be registered from an existing folder; only an explicit pinned install is verified.
                bool verified = have != null && IsVerified(have);
                rows.Add(new ToolListRow
                {
                    Name = entry.Name,
                    Version = have != null ? ToolManifest.Get(have, "Version") : entry.Version,
                    RulesVersion = have != null ? InstalledRules(have)
                        // Not installed: nothing is recorded yet, and no version is invented. Say only that the pinned release
                        // bundles rules; Install records the rule set it actually finds (a rules folder, or its git commit).
                        : entry.RulesRelativePath.Length > 0 ? "bundled with release (on install)" : "",
                    Source = have == null ? "Catalog" : verified ? "Installed" : "Registered",
                    Location = have != null ? ToolManifest.Get(have, "ExecutablePath") : entry.DownloadUrl,
                    Verified = verified,
                    License = entry.License,
                    ExpectedSha256 = entry.ExpectedSha256,
                    Notes = have != null && !verified ? Observed(have) : entry.Notes,
                });
            }
            // Installs whose catalog entry is gone keep the verification they were recorded with: a pinned install stays Installed.
            foreach (var have in installed
                .Where(r => !catalog.Any(c => string.Equals(c.Name, ToolManifest.Get(r, "Name"), StringComparison.OrdinalIgnoreCase)))
                .OrderBy(r => ToolManifest.Get(r, "Name"), StringComparer.OrdinalIgnoreCase))
            {
                var verified = IsVerified(have);
                rows.Add(new ToolListRow
                {
                    Name = ToolManifest.Get(have, "Name"),
                    Version = ToolManifest.Get(have, "Version"),
                    RulesVersion = InstalledRules(have),
                    Source = verified ? "Installed" : "Registered",
                    Verified = verified,
                    Location = ToolManifest.Get(have, "ExecutablePath"),
                    Notes = verified ? "Pinned install; no longer in the catalog." : Observed(have),
                });
            }
            return rows;
        }

        /// <summary>A pinned, hash-checked install. Install writes no Verified key and records the archive hash it matched
        /// against the pin; Register writes Verified = False and an empty ArchiveSha256. So a row is verified only when it
        /// has no Verified key AND a non-empty ArchiveSha256. Any other shape (a damaged or hand-edited row, including an
        /// edited Verified = True with no hash) is unverified. Get alone cannot tell absent from empty, so the key is checked directly.</summary>
        static bool IsVerified(Dictionary<string, object?> row) =>
            !row.ContainsKey("Verified") && ToolManifest.Get(row, "ArchiveSha256").Length > 0;

        static string Observed(Dictionary<string, object?> row)
        {
            var sha = ToolManifest.Get(row, "ObservedSha256");
            return $"Registered existing install; observed SHA-256 {(sha.Length > 0 ? sha : "not recorded")}, not verified against upstream.";
        }

        /// <summary>Moves an existing file or folder aside to a timestamped .replaced- name and records it for rollback.
        /// Returns the kept name, or null when nothing was there. Kept, not deleted, so local edits stay recoverable.</summary>
        static string? MoveAside(string target, List<Moved> moved)
        {
            var isFolder = Directory.Exists(LongPath.For(target));
            if (!isFolder && !File.Exists(LongPath.For(target))) return null;
            var kept = target + ".replaced-" + FotonTime.Stamp(DateTime.UtcNow) + "Z";
            for (int n = 2; Directory.Exists(LongPath.For(kept)) || File.Exists(LongPath.For(kept)); n++) kept = target + ".replaced-" + FotonTime.Stamp(DateTime.UtcNow) + "Z-" + n;
            if (isFolder) Directory.Move(LongPath.For(target), LongPath.For(kept)); else File.Move(LongPath.For(target), LongPath.For(kept));
            moved.Add(new Moved { Original = target, Kept = kept, IsFolder = isFolder });
            return kept;
        }

        /// <summary>An earlier file or folder moved aside during an install swap, recorded so a failed swap can put it back.</summary>
        sealed class Moved
        {
            public string Original = "";
            public string Kept = "";
            public bool IsFolder;
        }

        /// <summary>Undoes a failed swap: removes what was written, then puts the earlier copies back. A failure here is
        /// logged and does not replace the original error, which the caller rethrows.</summary>
        static void RollBack(List<Moved> moved, List<string> copied, Action<string> log)
        {
            foreach (var written in copied)
            {
                try { if (Directory.Exists(LongPath.For(written))) DeleteTree(written); else if (File.Exists(LongPath.For(written))) File.Delete(LongPath.For(written)); }
                catch (Exception ex) when (IsFileFailure(ex))
                { TryLog(log, $"Could not remove the partial copy {written}: {ex.Message}"); }
            }
            for (int i = moved.Count - 1; i >= 0; i--)
            {
                var m = moved[i];
                try { if (m.IsFolder) Directory.Move(LongPath.For(m.Kept), LongPath.For(m.Original)); else File.Move(LongPath.For(m.Kept), LongPath.For(m.Original)); }
                catch (Exception ex) when (IsFileFailure(ex))
                { TryLog(log, $"Could not restore {m.Original}; the earlier copy is at {m.Kept}: {ex.Message}"); }
            }
        }

        static bool IsFileFailure(Exception ex) =>
            ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException || ex is ArgumentException;

        /// <summary>
        /// Writes a rollback note. The log is install.log, which can fail for the same reason the install did (disk full,
        /// locked file); that must not replace the error the caller is about to rethrow.
        /// </summary>
        static void TryLog(Action<string> log, string message)
        {
            try { log(message); }
            catch (Exception ex) when (IsFileFailure(ex)) { }
        }

        /// <summary>The rule set recorded at install. A manifest with no RulesVersion key predates the field, so it says
        /// "not recorded" rather than reading as "no rules". A key that is present but empty means the install found none.</summary>
        static string InstalledRules(Dictionary<string, object?> have) =>
            have.ContainsKey("RulesVersion") ? ToolManifest.Get(have, "RulesVersion") : "not recorded";

        /// <summary>Where a pinned release unpacks: tool root\name\version.</summary>
        public static string Destination(CatalogTool entry, string? toolRoot) =>
            Path.Combine(ToolManifest.Root(toolRoot), entry.Name.ToLowerInvariant(), entry.Version);

        /// <summary>
        /// Downloads (or takes a local archive), verifies the catalog SHA-256, unpacks, and writes the tools.json row.
        /// Every step is appended to install.log in the tool root.
        /// </summary>
        public static Dictionary<string, object?> Install(CatalogTool entry, string? archivePath, string? toolRoot, StatusLog log)
        {
            // Support folders are deleted and replaced beside the tool, so each must be one plain folder name other than
            // the version folder; checked before anything is downloaded, extracted, or deleted. The rules folder is one of
            // them even when SupportFolders leave it out, so it is checked here too (a nested path would otherwise fail later).
            var folders = entry.SupportFolders.Count > 0 ? entry.SupportFolders.ToList() : new List<string> { "config", "rules" };
            if (entry.RulesRelativePath.Length > 0 && !folders.Contains(entry.RulesRelativePath, StringComparer.OrdinalIgnoreCase))
                folders.Add(entry.RulesRelativePath);
            foreach (var leaf in folders)
                if (!SupportFolderName.IsMatch(leaf ?? "") || string.Equals(leaf, entry.Version, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Catalog support folder must be one plain folder name other than the version: '" + leaf + "'");
            var root = ToolManifest.Root(toolRoot);
            Directory.CreateDirectory(LongPath.For(root));
            var logPath = Path.Combine(root, "install.log");
            void Log(string msg)
            {
                TextFile.AppendLine(LongPath.For(logPath), FotonTime.Format(DateTime.UtcNow) + " UTC  " + msg);
                log.Write(msg, StatusLevel.Info);
            }

            string? download = null;
            try
            {
                string zip;
                if (archivePath != null)
                {
                    if (!File.Exists(LongPath.For(LongPath.Full(archivePath)))) throw new FileNotFoundException("Archive not found: " + archivePath, archivePath);
                    zip = LongPath.Full(archivePath);
                    Log("Using local archive " + zip);
                }
                else
                {
                    zip = download = Path.Combine(Path.GetTempPath(), "foton-tool-" + Guid.NewGuid().ToString("N") + ".zip");
                    Log("Downloading " + entry.DownloadUrl);
                    Download(entry.DownloadUrl, zip);
                }

                var hash = Hashing.Sha256Hex(zip).ToUpperInvariant();
                var expect = entry.ExpectedSha256.ToUpperInvariant();
                Log("Archive SHA-256 " + hash);
                if (hash != expect)
                    throw new InvalidDataException($"SHA-256 mismatch for {entry.AssetName}. Expected {expect}, got {hash}. Refusing to install.");
                Log("Hash matches catalog pin.");

                var destVer = Destination(entry, root);
                // Every swap below is one transaction. An earlier install of this same version, the earlier executable, and the
                // earlier support folders are each moved aside before their replacement is written. If any step fails, all of
                // them are put back, so a failed reinstall leaves the tool as it was. tools.json is written last.
                var moved = new List<Moved>();
                var copied = new List<string>();
                var notes = new List<string>();
                string exe = "", stable = "", stableDir = "", exeDir = "";
                try
                {
                    MoveAside(destVer, moved);
                    copied.Add(destVer);
                    SafeZip.Extract(zip, destVer, entry.SkipArchivePrefixes);
                    Log("Expanded to " + destVer);

                    exe = entry.ExecutableNames.Select(n => FileSearch.Find(destVer, n, int.MaxValue).FirstOrDefault()).FirstOrDefault(f => f != null)
                        ?? throw new InvalidDataException($"Archive extracted but no executable named {string.Join("/", entry.ExecutableNames)} was found under {destVer}.");

                    // A stable copy at tool root\name\<exe> with its support folders beside it (catalog SupportFolders;
                    // config\ and rules\ when the entry names none), so the path in tools.json does not change shape between
                    // releases that nest the binary differently. Folders from an earlier version are replaced: rules are
                    // part of the pinned release.
                    // Parent and leaf are cut from the string, not Path.GetDirectoryName: the version folder can be past 260
                    // characters under net462 and the path APIs here reject that.
                    stableDir = Parent(destVer);
                    stable = Path.Combine(stableDir, Leaf(exe));
                    exeDir = Parent(exe);

                    var exeKept = MoveAside(stable, moved);
                    copied.Add(stable);
                    File.Copy(LongPath.For(exe), LongPath.For(stable), true);
                    if (exeKept != null) notes.Add($"Kept the earlier executable as {Path.GetFileName(exeKept)}.");

                    foreach (var leaf in folders)
                    {
                        // leaf passed SupportFolderName and is not the version, so dst is one folder directly under stableDir.
                        var src = Path.Combine(exeDir, leaf!);
                        var dst = Path.Combine(stableDir, leaf!);
                        // A file where the release ships a folder would be skipped silently; refuse it instead.
                        if (File.Exists(LongPath.For(src))) throw new InvalidDataException($"The pinned release ships '{leaf}' as a file, not a folder.");

                        // An earlier version's folder, or a stray file in the way, is moved aside even when this release has no
                        // such folder, so a stale rules\ is never used (or recorded). Kept, not deleted: local edits stay recoverable.
                        var kept = MoveAside(dst, moved);
                        var srcExists = Directory.Exists(LongPath.For(src));
                        if (srcExists)
                        {
                            copied.Add(dst);
                            CopyDirectory(src, dst);
                        }
                        if (kept != null)
                            notes.Add(srcExists
                                ? $"Moved the existing {leaf} to {Path.GetFileName(kept)} and installed the pinned release's copy."
                                : $"The pinned release has no {leaf} folder beside its executable; moved the earlier {leaf} to {Path.GetFileName(kept)} so it is not used with this version.");
                    }
                }
                catch
                {
                    RollBack(moved, copied, Log);
                    throw;
                }
                // The swap is done. A log line that cannot be written (a locked or full disk) must not undo or abort an install
                // that has no record yet, so these are best effort; the run's own log still shows them.
                foreach (var note in notes) TryLog(Log, note);
                exe = stable;

                // Empty unless the pinned release actually brought a rules folder: a tool with none records no rule set.
                var rulesVersion = "";
                var rulesPath = "";
                if (entry.RulesRelativePath.Length > 0)
                {
                    var rp = Path.Combine(stableDir, entry.RulesRelativePath);
                    if (Directory.Exists(LongPath.For(rp)) || File.Exists(LongPath.For(rp)))
                    {
                        rulesPath = rp;
                        // Not a rule-set identifier: with no git history, it only says the rules came with this release.
                        rulesVersion = GitRulesVersion(rp) ?? "bundled with release " + entry.Version;
                    }
                }

                var record = new Dictionary<string, object?>
                {
                    ["Name"] = entry.Name,
                    ["Version"] = entry.Version,
                    ["SourceUrl"] = archivePath != null ? zip : entry.DownloadUrl,
                    ["ArchiveSha256"] = hash,
                    ["InstallDateUtc"] = FotonTime.Format(DateTime.UtcNow),
                    ["InstallPath"] = destVer,
                    ["ExecutablePath"] = exe,
                    ["RulesPath"] = rulesPath,
                    ["RulesVersion"] = rulesVersion,
                    ["License"] = entry.License,
                };
                // tools.json is rewritten in place, so a failed write can leave it short. The earlier bytes are kept and put back,
                // and the swap is undone, so a failed save leaves the tool and its record as they were.
                var manifestPath = ToolManifest.PathOf(root);
                var manifestExisted = File.Exists(LongPath.For(manifestPath));
                byte[]? priorManifest = null;
                try
                {
                    // The read is inside the try too: if it fails, the swap is still undone below.
                    if (manifestExisted) priorManifest = File.ReadAllBytes(LongPath.For(manifestPath));
                    var written = ToolManifest.Save(root, record);
                    // Saved. If this line cannot be logged the install is still recorded, so it is not rolled back.
                    TryLog(Log, "Wrote manifest " + written);
                }
                catch
                {
                    try
                    {
                        // Restore only what was read. A failed read leaves tools.json as it was, since Save never ran.
                        if (!manifestExisted) { if (File.Exists(LongPath.For(manifestPath))) File.Delete(LongPath.For(manifestPath)); }
                        else if (priorManifest != null) File.WriteAllBytes(LongPath.For(manifestPath), priorManifest);
                    }
                    catch (Exception ex) when (IsFileFailure(ex))
                    { TryLog(Log, $"Could not restore {manifestPath}: {ex.Message}"); }
                    RollBack(moved, copied, Log);
                    throw;
                }
                TryLog(Log, $"Installed {entry.Name} {entry.Version} -> {exe}");
                return record;
            }
            finally
            {
                if (download != null) try { File.Delete(download); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
        }

        static readonly Regex SupportFolderName = new Regex(@"^[A-Za-z0-9_-][A-Za-z0-9._-]*$");

        static void Download(string url, string path)
        {
            if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Catalog download URL is not HTTPS: " + url);
            // .NET Framework 4.6.2 defaults can exclude TLS 1.2, which GitHub requires.
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            using (var client = new HttpClient { Timeout = TimeSpan.FromMinutes(10) })
            using (var response = client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult())
            {
                response.EnsureSuccessStatusCode();
                using (var fs = File.Create(path))
                    response.Content.CopyToAsync(fs).GetAwaiter().GetResult();
            }
        }

        /// <summary>The first 12 characters of the rules commit when the release ships a .git folder; null otherwise.</summary>
        static string? GitRulesVersion(string rulesDir)
        {
            try
            {
                var head = LongPath.For(Path.Combine(rulesDir, ".git", "HEAD"));
                if (!File.Exists(head)) return null;
                var h = (File.ReadLines(head).FirstOrDefault() ?? "").Trim();
                var m = Regex.Match(h, @"ref:\s*refs/heads/(.+)$");
                string commit;
                if (m.Success)
                {
                    // The ref is joined under .git\refs\heads. A rooted or drive value would make Path.Combine return that path itself,
                    // so only plain relative names (letters, digits, . _ - and /) are read.
                    var branch = m.Groups[1].Value;
                    // No leading or doubled slash either: a leading slash makes the segment rooted, and Path.Combine would drop the folder.
                    if (branch.Contains("..") || !Regex.IsMatch(branch, @"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")) return null;
                    var refPath = LongPath.For(Path.Combine(rulesDir, ".git", "refs", "heads", branch));
                    if (!File.Exists(refPath)) return null;
                    commit = (File.ReadLines(refPath).FirstOrDefault() ?? "").Trim();
                }
                else commit = h;
                // Only a hash counts. HEAD can also point at a tag or a remote ref ("ref: refs/tags/..."), and its text is not a
                // commit; a detached HEAD holds the hash itself.
                return Regex.IsMatch(commit, "^[0-9a-fA-F]{12,}$") ? commit.Substring(0, 12) : null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) { return null; }
        }

        static void CopyDirectory(string src, string dst)
        {
            // Names come back prefixed from a prefixed folder; they are turned back to the normal form before they are
            // joined with dst, so the destination is built from the same plain strings as everything else.
            Directory.CreateDirectory(LongPath.For(dst));
            foreach (var found in Directory.GetFiles(LongPath.For(src)))
            {
                var f = LongPath.Plain(found);
                File.Copy(LongPath.For(f), LongPath.For(Path.Combine(dst, Leaf(f))), true);
            }
            foreach (var found in Directory.GetDirectories(LongPath.For(src)))
            {
                var d = LongPath.Plain(found);
                CopyDirectory(d, Path.Combine(dst, Leaf(d)));
            }
        }

        /// <summary>
        /// Recursive delete that works past 260 characters. On net462, Directory.Delete(path, true) rebuilds child names
        /// without the prefix and fails on a deep tree, so the walk is done here with the prefix on every call. Links
        /// (junctions, symlinks) are removed as links and never followed, so nothing outside the tree is touched.
        /// </summary>
        static void DeleteTree(string path)
        {
            // The top of the tree can itself be a link (a junction put where the folder was): remove the link, not its target.
            if ((File.GetAttributes(LongPath.For(path)) & FileAttributes.ReparsePoint) != 0)
            {
                Directory.Delete(LongPath.For(path));
                return;
            }
            // Every call takes LongPath.For on the name it is given. A short folder can list children past 260
            // characters (the threshold is on the folder's own length), so each child is prefixed by its own length.
            foreach (var file in Directory.GetFiles(LongPath.For(path)))
            {
                File.SetAttributes(LongPath.For(file), FileAttributes.Normal);
                File.Delete(LongPath.For(file));
            }
            foreach (var dir in Directory.GetDirectories(LongPath.For(path)))
            {
                if ((File.GetAttributes(LongPath.For(dir)) & FileAttributes.ReparsePoint) != 0) Directory.Delete(LongPath.For(dir));
                else DeleteTree(dir);
            }
            Directory.Delete(LongPath.For(path));
        }

        /// <summary>The text after the last backslash. A substring, not Path.GetFileName, so it works on any length.</summary>
        static string Leaf(string path) => path.Substring(path.LastIndexOf('\\') + 1);

        /// <summary>The text before the last backslash. A substring, not Path.GetDirectoryName, so it works on any length.</summary>
        static string Parent(string path) => LongPath.ParentOf(path);
    }
}
