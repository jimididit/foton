using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools
{
    /// <summary>
    /// A folder to carry to an endpoint (foton bundle, the console's bundle builders): the collector, for a collection
    /// the profile if any, the command to run, and the SHA-256 of each. The collector comes from the program building
    /// the bundle (EmbeddedCollectors), so it is the one released with that program; it is checked to be the right
    /// collector of the same Foton version before it is written. Workstation setup only: nothing here runs a collector
    /// or touches a case package or a live host.
    /// </summary>
    public sealed class DeploymentBundle
    {
        public const string ProfileFileName = "profile.json";
        public const string ReadmeFileName = "RUN.txt";
        public const string SumsFileName = "SHA256SUMS.txt";
        const long MaxExeBytes = 64L * 1024 * 1024;

        public string Folder { get; private set; } = "";
        public CollectorKind Kind { get; private set; }
        public string CollectorVersion { get; private set; } = "";
        public string CollectorSha256 { get; private set; } = "";
        /// <summary>The command RUN.txt gives, to run from the bundle folder on the endpoint.</summary>
        public string RunCommand { get; private set; } = "";

        static string Command(CollectorKind kind, bool profile, bool loadUserHives) =>
            kind == CollectorKind.Collect
                ? $".\\{EmbeddedCollectors.FileName(kind)}{(profile ? $" -Profile .\\{ProfileFileName}" : "")} -CaseNumber CASE-0001 -Examiner NAME"
                : $".\\{EmbeddedCollectors.FileName(kind)}{(loadUserHives ? " -LoadUserHives" : "")}";

        /// <summary>
        /// Builds Foton_Bundle_&lt;profile&gt;_&lt;UTC&gt;Z (collect) or Foton_BaselineBundle_&lt;UTC&gt;Z (baseline) under
        /// <paramref name="parentFolder"/>. <paramref name="profile"/> is for a collection only (null collects every
        /// category with the collector's defaults); <paramref name="loadUserHives"/> for a baseline only.
        /// </summary>
        public static DeploymentBundle Build(CollectorKind kind, byte[] collector, CollectionProfile? profile, bool loadUserHives, string parentFolder, DateTime utcNow)
        {
            if (kind == CollectorKind.Baseline && profile != null) throw new ArgumentException("A baseline bundle takes no collection profile.");
            if (kind == CollectorKind.Collect && loadUserHives) throw new ArgumentException("-LoadUserHives here is a baseline option; a collection sets it in its profile.");
            if (collector.Length > MaxExeBytes) throw new InvalidDataException("Too large to be " + EmbeddedCollectors.FileName(kind));
            var name = EmbeddedCollectors.FileName(kind);
            var sha = Hashing.Sha256Hex(collector).ToLowerInvariant();
            var stamp = utcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
            var leaf = kind == CollectorKind.Collect ? $"Foton_Bundle_{SafeName(profile?.Name ?? "All_categories")}_{stamp}" : $"Foton_BaselineBundle_{stamp}";
            var folder = Path.Combine(Path.GetFullPath(parentFolder), leaf);
            if (Directory.Exists(folder) || File.Exists(folder)) throw new IOException("Already exists: " + folder);
            Directory.CreateDirectory(folder);
            try
            {
                var exePath = Path.Combine(folder, name);
                File.WriteAllBytes(exePath, collector);
                // Its own version resource says what it is: the right collector, and the same Foton as this program.
                var v = FileVersionInfo.GetVersionInfo(exePath);
                var version = CheckCollector(kind, v.OriginalFilename, v.FileVersion);
                var sums = new StringBuilder($"{sha}  {name}\r\n");
                string? profileSha = null;
                if (profile != null)
                {
                    File.WriteAllBytes(Path.Combine(folder, ProfileFileName), profile.Bytes);
                    profileSha = profile.Sha256.ToLowerInvariant();
                    sums.Append($"{profileSha}  {ProfileFileName}\r\n");
                }
                TextFile.Write(Path.Combine(folder, ReadmeFileName), Readme(kind, profile, profileSha, loadUserHives, version, sha, utcNow));
                File.WriteAllText(Path.Combine(folder, SumsFileName), sums.ToString(), new UTF8Encoding(false));
                return new DeploymentBundle { Folder = folder, Kind = kind, CollectorVersion = Show(version), CollectorSha256 = sha, RunCommand = Command(kind, profile != null, loadUserHives) };
            }
            catch
            {
                try { Directory.Delete(folder, true); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                throw;
            }
        }

        /// <summary>
        /// The collector's version when its version resource names the expected collector and the same version as this
        /// Foton (the two are built and released together); otherwise InvalidDataException naming why.
        /// </summary>
        internal static Version CheckCollector(CollectorKind kind, string? originalFilename, string? fileVersion)
        {
            var expected = EmbeddedCollectors.FileName(kind);
            if (!string.Equals(originalFilename, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"This is not {expected} (its version resource names '{originalFilename}').");
            if (!Version.TryParse(fileVersion ?? "", out var version))
                throw new InvalidDataException($"{expected} has no readable version ('{fileVersion}').");
            var mine = FotonVersion.Product.Split('-', '+')[0];
            if (!Version.TryParse(mine, out var own) || Full(version) != Full(own))
                throw new InvalidDataException($"{expected} {Show(version)} is not the collector released with Foton {FotonVersion.Product}.");
            return version;
        }

        /// <summary>A version as major.minor.build, or as many parts as it has.</summary>
        public static string Show(Version v) => v.ToString(v.Build >= 0 ? 3 : 2);

        /// <summary>Missing parts as 0 and the revision ignored, so 3.0.0.0 equals 3.0.0.</summary>
        static Version Full(Version v) => new Version(v.Major, v.Minor, Math.Max(v.Build, 0));

        /// <summary>A name as a file or folder name part: letters, digits, '.', '-', '_' only.</summary>
        public static string SafeName(string name)
        {
            var safe = Regex.Replace(name ?? "", @"[^A-Za-z0-9._-]+", "_").Trim('_', '.');
            if (safe.Length > 40) safe = safe.Substring(0, 40).TrimEnd('_', '.');
            return safe.Length == 0 ? "profile" : safe;
        }

        static string Readme(CollectorKind kind, CollectionProfile? p, string? profileSha, bool loadUserHives, Version version, string sha, DateTime utcNow)
        {
            var name = EmbeddedCollectors.FileName(kind);
            var lines = new System.Collections.Generic.List<string?>
            {
                kind == CollectorKind.Collect ? "Foton collection bundle" : "Foton baseline bundle",
                $"Built {FotonTime.Format(utcNow)} UTC by Foton {FotonVersion.Product}",
                "",
            };
            if (kind == CollectorKind.Collect)
            {
                if (p == null) lines.Add("Profile: none (every category, the collector's defaults)");
                else
                {
                    var options = p.Options.Count == 0 ? "(none)" : string.Join(", ", p.Options.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                        .Select(kv => kv.Key + "=" + Convert.ToString(kv.Value, CultureInfo.InvariantCulture)!.ToLowerInvariant()));
                    lines.Add("Profile: " + TextFile.OneLine(p.Name));
                    lines.Add(p.Description.Length > 0 ? "  " + TextFile.OneLine(p.Description) : null);
                    lines.Add($"  Categories:   {string.Join(", ", p.Categories)} ({p.Categories.Count} of {CollectionProfile.AllCategories.Count})");
                    lines.Add("  ExcludeTasks: " + (p.ExcludeTasks.Count == 0 ? "(none)" : string.Join(", ", p.ExcludeTasks)));
                    lines.Add("  Options:      " + options);
                    lines.Add($"  {ProfileFileName} SHA-256 {profileSha}");
                }
                lines.Add("");
            }
            lines.Add($"{name} {Show(version)} SHA-256 {sha}");
            lines.Add($"  The {name} released with Foton {FotonVersion.Product}, written by the program that built this bundle. It matches");
            lines.Add($"  {name} in that release's SHA256SUMS.txt.");
            lines.Add("");
            if (kind == CollectorKind.Collect)
            {
                lines.Add("On the endpoint, from this folder (an elevated prompt collects the most; a standard user is supported):");
                lines.Add("  " + Command(kind, p != null, false));
                lines.Add(p != null ? "A switch given on the command line wins over the same option in the profile." : null);
                lines.Add("The case package is written to C:\\Foton\\Cases (or -OutputPath <folder>). Bring it to the workstation and open it in foton-console.exe.");
            }
            else
            {
                lines.Add("On the machine to baseline, from this folder (an elevated prompt captures the most; a standard user is supported):");
                lines.Add("  " + Command(kind, false, loadUserHives));
                lines.Add(loadUserHives ? "-LoadUserHives also reads the registry of users who are not signed in (loaded and unloaded again)." : null);
                lines.Add("The baseline is written to C:\\Foton\\Baselines (or -OutputPath <folder>). Compare two baselines with foton compare or the console's Compare tab.");
            }
            lines.Add("");
            lines.Add("Before running, check the files:");
            lines.Add($"  Get-FileHash .\\{name}{(p != null ? $", .\\{ProfileFileName}" : "")} -Algorithm SHA256");
            lines.Add($"and compare with {SumsFileName} in this folder (carried separately if the channel is untrusted).");
            lines.Add("");
            return string.Join("\r\n", lines.Where(l => l != null));
        }
    }
}
