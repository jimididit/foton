using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools.Update
{
    public enum UpdateState
    {
        /// <summary>No stable release is newer than the running one.</summary>
        UpToDate,
        /// <summary>A newer release whose statement verifies against a pinned key.</summary>
        Available,
        /// <summary>Newer releases exist, but none carries the owner's signature yet: nothing to install.</summary>
        NotYetSigned,
        /// <summary>The check could not finish, or a newer release failed a check; nothing to install.</summary>
        Failed,
    }

    public sealed class UpdateCheckResult
    {
        public UpdateState State { get; set; }
        public string CurrentVersion { get; set; } = "";
        /// <summary>What happened, in one or two sentences for the analyst.</summary>
        public string Message { get; set; } = "";
        /// <summary>The release page (Available, NotYetSigned, and a failed release).</summary>
        public string ReleaseUrl { get; set; } = "";
        public ReleaseStatement? Statement { get; set; }
        public ReleaseKey? SignedBy { get; set; }
        public string ZipUrl { get; set; } = "";
        /// <summary>A release newer than the available one that is published but not signed yet; empty when none.</summary>
        public string PendingVersion { get; set; } = "";
    }

    /// <summary>
    /// Finds the newest stable release newer than the running one whose foton-release.json is signed by a pinned key.
    /// Never installs anything; downgrades are impossible (only newer versions are considered) and any release that fails
    /// a check stops the search with the reason, rather than quietly falling back to another.
    /// </summary>
    public static class UpdateCheck
    {
        public const string Repository = "jimididit/foton";
        public const string ReleasesApi = "https://api.github.com/repos/" + Repository + "/releases?per_page=30";
        public const string StatementName = "foton-release.json";
        public const string SignatureName = "foton-release.json.sig";
        public const long MaxListBytes = 1024 * 1024;

        public static UpdateCheckResult Run(IUpdateSource source, string currentVersion, DateTime utcNow, IEnumerable<ReleaseKey> keys)
        {
            var result = new UpdateCheckResult { CurrentVersion = currentVersion };
            List<GitHubRelease> newer;
            try
            {
                newer = GitHubRelease.ParseList(source.Get(ReleasesApi, MaxListBytes))
                    .Where(r => !r.Draft && !r.Prerelease && r.Version.Length > 0 && IsNewer(r.Version, currentVersion))
                    .OrderByDescending(r => System.Version.Parse(r.Version)).ToList();
            }
            catch (Exception ex) when (ex is IOException || ex is InvalidDataException)
            {
                return Fail(result, "Could not check for updates: " + ex.Message);
            }
            if (newer.Count == 0)
            {
                result.State = UpdateState.UpToDate;
                result.Message = "No release newer than Foton " + currentVersion + " is published.";
                return result;
            }

            var keyList = keys.ToList();
            foreach (var release in newer)
            {
                var statementUrl = release.Asset(StatementName);
                var signatureUrl = release.Asset(SignatureName);
                if (statementUrl == null || signatureUrl == null)
                {
                    if (result.PendingVersion.Length == 0) { result.PendingVersion = release.Version; result.ReleaseUrl = release.HtmlUrl; }
                    continue;
                }
                result.ReleaseUrl = release.HtmlUrl;
                try
                {
                    var statementBytes = source.Get(statementUrl, ReleaseStatement.MaxBytes);
                    var signature = source.Get(signatureUrl, ReleaseSignature.MaxSignatureFileBytes);
                    var key = ReleaseSignature.Verify(statementBytes, signature, keyList);
                    if (key == null)
                        return Fail(result, $"Foton {release.Version} is not trusted: its {SignatureName} does not verify against the pinned Foton release keys. Nothing will be installed.");
                    var statement = ReleaseStatement.Parse(statementBytes);
                    if (statement.Version != release.Version)
                        return Fail(result, $"Foton {release.Version} is not trusted: its signed statement is for version {statement.Version}. Nothing will be installed.");
                    if (statement.Released > utcNow.Date.AddDays(1))
                        return Fail(result, $"Foton {release.Version} is not trusted: its signed release date {statement.ReleasedText} is in the future. Nothing will be installed.");
                    var zipUrl = release.Asset(statement.ZipName);
                    if (zipUrl == null)
                        return Fail(result, $"Foton {release.Version} has no {statement.ZipName} to download. Nothing will be installed.");
                    result.State = UpdateState.Available;
                    result.Statement = statement;
                    result.SignedBy = key;
                    result.ZipUrl = zipUrl;
                    result.Message = $"Foton {statement.Version} (released {statement.ReleasedText}) is available; signed by the Foton release key ({key.Role}, fingerprint {key.Fingerprint}).";
                    return result;
                }
                catch (Exception ex) when (ex is IOException || ex is InvalidDataException)
                {
                    return Fail(result, $"Could not check Foton {release.Version}: {ex.Message}");
                }
            }
            result.State = UpdateState.NotYetSigned;
            result.Message = $"Foton {result.PendingVersion} is published but not signed yet; nothing to install until its signature is attached.";
            return result;
        }

        static UpdateCheckResult Fail(UpdateCheckResult result, string message)
        {
            result.State = UpdateState.Failed;
            result.Message = message;
            return result;
        }

        /// <summary>
        /// True when candidate (X.Y.Z) is later than the running version. A prerelease (3.3.0-beta.1) is older than its
        /// release (3.3.0); an unreadable running version (a local build) treats every release as newer.
        /// </summary>
        public static bool IsNewer(string candidate, string current)
        {
            if (!System.Version.TryParse(candidate, out var c)) return false;
            int dash = current.IndexOf('-');
            var core = dash < 0 ? current : current.Substring(0, dash);
            if (!System.Version.TryParse(core, out var cur) || cur.Build < 0) return true;
            int cmp = c.CompareTo(cur);
            return cmp > 0 || (cmp == 0 && dash >= 0);
        }
    }

    /// <summary>One entry of GitHub's release list, with only what the updater reads.</summary>
    sealed class GitHubRelease
    {
        static readonly Regex StableTag = new Regex(@"^v(\d{1,4}\.\d{1,4}\.\d{1,4})\z", RegexOptions.CultureInvariant);

        public string Tag { get; private set; } = "";
        /// <summary>X.Y.Z from a vX.Y.Z tag; empty for any other tag.</summary>
        public string Version { get; private set; } = "";
        public bool Draft { get; private set; }
        public bool Prerelease { get; private set; }
        public string HtmlUrl { get; private set; } = "";
        readonly Dictionary<string, string> _assets = new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// The download address of an asset of this release, or null. Only addresses under this repository's own release
        /// downloads for this tag count, whatever the list says.
        /// </summary>
        public string? Asset(string name) => _assets.TryGetValue(name, out var url) ? url : null;

        public static List<GitHubRelease> ParseList(byte[] bytes)
        {
            object? parsed;
            try { parsed = Json.Parse(Encoding.UTF8.GetString(bytes)); }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException) { throw new InvalidDataException("GitHub's release list is not JSON."); }
            if (!(parsed is IEnumerable list) || parsed is string || parsed is IDictionary) throw new InvalidDataException("GitHub's release list is not a JSON array.");
            var releases = new List<GitHubRelease>();
            foreach (var item in list)
            {
                if (!(item is IDictionary<string, object> r)) continue;
                var tag = r.TryGetValue("tag_name", out var t) ? t as string ?? "" : "";
                var m = StableTag.Match(tag);
                var release = new GitHubRelease
                {
                    Tag = tag,
                    Version = m.Success ? m.Groups[1].Value : "",
                    Draft = r.TryGetValue("draft", out var d) && d is bool db && db,
                    Prerelease = r.TryGetValue("prerelease", out var p) && p is bool pb && pb,
                    HtmlUrl = r.TryGetValue("html_url", out var h) && h is string hs && hs.StartsWith("https://github.com/" + UpdateCheck.Repository + "/releases/", StringComparison.Ordinal) ? hs : "",
                };
                var prefix = "https://github.com/" + UpdateCheck.Repository + "/releases/download/" + tag + "/";
                if (r.TryGetValue("assets", out var a) && a is IEnumerable assets && !(a is string))
                    foreach (var asset in assets)
                    {
                        if (!(asset is IDictionary<string, object> ad)) continue;
                        var name = ad.TryGetValue("name", out var n) ? n as string ?? "" : "";
                        var url = ad.TryGetValue("browser_download_url", out var u) ? u as string ?? "" : "";
                        if (name.Length > 0 && url == prefix + name && !release._assets.ContainsKey(name)) release._assets[name] = url;
                    }
                releases.Add(release);
            }
            return releases;
        }
    }
}
