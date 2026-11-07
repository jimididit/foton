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
                // A catalog tool can also be registered from an existing folder; only a pinned install is verified.
                bool registered = have != null && ToolManifest.Get(have, "Verified") == "False";
                rows.Add(new ToolListRow
                {
                    Name = entry.Name,
                    Version = have != null ? ToolManifest.Get(have, "Version") : entry.Version,
                    Source = have == null ? "Catalog" : registered ? "Registered" : "Installed",
                    Location = have != null ? ToolManifest.Get(have, "ExecutablePath") : entry.DownloadUrl,
                    Verified = have != null && !registered,
                    License = entry.License,
                    ExpectedSha256 = entry.ExpectedSha256,
                    Notes = registered ? Observed(have!) : entry.Notes,
                });
            }
            foreach (var have in installed
                .Where(r => !catalog.Any(c => string.Equals(c.Name, ToolManifest.Get(r, "Name"), StringComparison.OrdinalIgnoreCase)))
                .OrderBy(r => ToolManifest.Get(r, "Name"), StringComparer.OrdinalIgnoreCase))
                rows.Add(new ToolListRow
                {
                    Name = ToolManifest.Get(have, "Name"),
                    Version = ToolManifest.Get(have, "Version"),
                    Source = "Registered",
                    Location = ToolManifest.Get(have, "ExecutablePath"),
                    Notes = Observed(have),
                });
            return rows;
        }

        static string Observed(Dictionary<string, object?> row) =>
            $"Registered existing install; observed SHA-256 {ToolManifest.Get(row, "ObservedSha256")}, not verified against upstream.";

        /// <summary>Where a pinned release unpacks: tool root\name\version.</summary>
        public static string Destination(CatalogTool entry, string? toolRoot) =>
            Path.Combine(ToolManifest.Root(toolRoot), entry.Name.ToLowerInvariant(), entry.Version);

        /// <summary>
        /// Downloads (or takes a local archive), verifies the catalog SHA-256, unpacks, and writes the tools.json row.
        /// Every step is appended to install.log in the tool root.
        /// </summary>
        public static Dictionary<string, object?> Install(CatalogTool entry, string? archivePath, string? toolRoot, StatusLog log)
        {
            var root = ToolManifest.Root(toolRoot);
            Directory.CreateDirectory(root);
            var logPath = Path.Combine(root, "install.log");
            void Log(string msg)
            {
                TextFile.AppendLine(logPath, FotonTime.Format(DateTime.UtcNow) + " UTC  " + msg);
                log.Write(msg, StatusLevel.Info);
            }

            string? download = null;
            try
            {
                string zip;
                if (archivePath != null)
                {
                    if (!File.Exists(archivePath)) throw new FileNotFoundException("Archive not found: " + archivePath, archivePath);
                    zip = Path.GetFullPath(archivePath);
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
                if (Directory.Exists(destVer)) Directory.Delete(destVer, true);
                SafeZip.Extract(zip, destVer);
                Log("Expanded to " + destVer);

                var exe = entry.ExecutableNames.Select(n => FileSearch.Find(destVer, n, int.MaxValue).FirstOrDefault()).FirstOrDefault(f => f != null)
                    ?? throw new InvalidDataException($"Archive extracted but no executable named {string.Join("/", entry.ExecutableNames)} was found under {destVer}.");

                // A stable copy at tool root\name\<exe> with config\ and rules\ beside it, so the path in tools.json
                // does not change shape between releases that nest the binary differently.
                var stableDir = Path.GetDirectoryName(destVer)!;
                var stable = Path.Combine(stableDir, Path.GetFileName(exe));
                File.Copy(exe, stable, true);
                var exeDir = Path.GetDirectoryName(exe)!;
                foreach (var leaf in new[] { "config", "rules" })
                {
                    var src = Path.Combine(exeDir, leaf);
                    var dst = Path.Combine(stableDir, leaf);
                    if (Directory.Exists(src) && !Directory.Exists(dst) && !File.Exists(dst)) CopyDirectory(src, dst);
                }
                exe = stable;

                var rulesVersion = "bundled-" + entry.Version;
                var rulesPath = "";
                if (entry.RulesRelativePath.Length > 0)
                {
                    var rp = Path.Combine(stableDir, entry.RulesRelativePath);
                    if (Directory.Exists(rp) || File.Exists(rp))
                    {
                        rulesPath = Path.GetFullPath(rp);
                        rulesVersion = GitRulesVersion(rp) ?? rulesVersion;
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
                Log("Wrote manifest " + ToolManifest.Save(root, record));
                Log($"Installed {entry.Name} {entry.Version} -> {exe}");
                return record;
            }
            finally
            {
                if (download != null) try { File.Delete(download); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
        }

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
                var head = Path.Combine(rulesDir, ".git", "HEAD");
                if (!File.Exists(head)) return null;
                var h = (File.ReadLines(head).FirstOrDefault() ?? "").Trim();
                var m = Regex.Match(h, @"ref:\s*refs/heads/(.+)$");
                string commit;
                if (m.Success)
                {
                    if (m.Groups[1].Value.Contains("..")) return null;
                    var refPath = Path.Combine(rulesDir, ".git", "refs", "heads", m.Groups[1].Value);
                    if (!File.Exists(refPath)) return null;
                    commit = (File.ReadLines(refPath).FirstOrDefault() ?? "").Trim();
                }
                else commit = h;
                return commit.Length >= 12 ? commit.Substring(0, 12) : null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) { return null; }
        }

        static void CopyDirectory(string src, string dst)
        {
            Directory.CreateDirectory(dst);
            foreach (var f in Directory.GetFiles(src)) File.Copy(f, Path.Combine(dst, Path.GetFileName(f)), true);
            foreach (var d in Directory.GetDirectories(src)) CopyDirectory(d, Path.Combine(dst, Path.GetFileName(d)));
        }
    }
}
