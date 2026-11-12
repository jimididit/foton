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
    /// A folder to carry to an endpoint: foton-collect.exe, the collection profile, the command to run, and the SHA-256 of
    /// each. Workstation setup only; nothing here touches a case package or a live host. The executable is hashed and
    /// copied from the same bytes, and checked against the release's SHA256SUMS.txt when one sits beside it.
    /// </summary>
    public sealed class DeploymentBundle
    {
        public const string ProfileFileName = "profile.json";
        public const string ReadmeFileName = "RUN.txt";
        public const string SumsFileName = "SHA256SUMS.txt";
        const string CollectFileName = "foton-collect.exe";
        const long MaxExeBytes = 64L * 1024 * 1024;
        const long MaxSumsBytes = 64 * 1024;
        /// <summary>The first foton-collect that reads -Profile.</summary>
        static readonly Version ProfileSupport = new Version(2, 8, 0);

        public string Folder { get; private set; } = "";
        public string CollectVersion { get; private set; } = "";
        public string CollectSha256 { get; private set; } = "";
        /// <summary>True when a SHA256SUMS.txt beside the source listed this executable with the same hash.</summary>
        public bool CollectVerified { get; private set; }

        /// <summary>
        /// Builds Foton_Bundle_&lt;profile&gt;_&lt;UTC&gt; under <paramref name="parentFolder"/>. Refuses a file that is not
        /// foton-collect 2.8.0 or later, and one that differs from the SHA256SUMS.txt beside it.
        /// </summary>
        public static DeploymentBundle Build(string collectExe, CollectionProfile profile, string parentFolder, DateTime utcNow)
        {
            var info = new FileInfo(collectExe);
            if (!info.Exists) throw new FileNotFoundException("Not found: " + collectExe, collectExe);
            if (info.Length > MaxExeBytes) throw new InvalidDataException("This file is too large to be foton-collect.exe: " + collectExe);
            var v = FileVersionInfo.GetVersionInfo(info.FullName);
            var version = CheckCollect(v.OriginalFilename, v.FileVersion);

            var bytes = File.ReadAllBytes(info.FullName);
            var sha = Hashing.Sha256Hex(bytes).ToLowerInvariant();
            var verified = Verify(Path.Combine(info.DirectoryName!, SumsFileName), info.Name, sha);

            var folder = Path.Combine(Path.GetFullPath(parentFolder), $"Foton_Bundle_{SafeName(profile.Name)}_{utcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}Z");
            if (Directory.Exists(folder) || File.Exists(folder)) throw new IOException("Already exists: " + folder);
            Directory.CreateDirectory(folder);
            try
            {
                File.WriteAllBytes(Path.Combine(folder, CollectFileName), bytes);
                File.WriteAllBytes(Path.Combine(folder, ProfileFileName), profile.Bytes);
                var profileSha = profile.Sha256.ToLowerInvariant();
                TextFile.Write(Path.Combine(folder, ReadmeFileName), Readme(profile, profileSha, version, sha, verified, utcNow));
                File.WriteAllText(Path.Combine(folder, SumsFileName),
                    $"{sha}  {CollectFileName}\r\n{profileSha}  {ProfileFileName}\r\n", new UTF8Encoding(false));
            }
            catch
            {
                try { Directory.Delete(folder, true); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                throw;
            }
            return new DeploymentBundle { Folder = folder, CollectVersion = Show(version), CollectSha256 = sha, CollectVerified = verified };
        }

        /// <summary>The executable's version when it is foton-collect 2.8.0 or later; otherwise InvalidDataException naming why.</summary>
        internal static Version CheckCollect(string? originalFilename, string? fileVersion)
        {
            if (Version.TryParse(fileVersion ?? "", out var v) && v < ProfileSupport
                && string.Equals(originalFilename, CollectFileName, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"foton-collect {Show(v)} does not read collection profiles; use {Show(ProfileSupport)} or later.");
            return CheckExecutable(CollectFileName, ProfileSupport, originalFilename, fileVersion);
        }

        /// <summary>A version as major.minor.build, or as many parts as it has (a version resource can hold "2.9").</summary>
        public static string Show(Version v) => v.ToString(v.Build >= 0 ? 3 : 2);

        /// <summary>
        /// The executable's version when its version resource names <paramref name="expected"/> and it is at least
        /// <paramref name="minimum"/>; otherwise InvalidDataException naming why.
        /// </summary>
        internal static Version CheckExecutable(string expected, Version minimum, string? originalFilename, string? fileVersion)
        {
            if (!string.Equals(originalFilename, expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"This is not {expected} (its version resource names '{originalFilename}').");
            if (!Version.TryParse(fileVersion ?? "", out var version))
                throw new InvalidDataException($"{expected} has no readable version ('{fileVersion}').");
            if (version < minimum)
                throw new InvalidDataException($"{expected} {Show(version)} is too old for the console; use {Show(minimum)} or later.");
            return version;
        }

        /// <summary>
        /// False when there is no SHA256SUMS.txt; true when it lists the file with this hash. A list that leaves the file
        /// out, or gives another hash, is refused: the executable is not the one released with that list.
        /// </summary>
        internal static bool Verify(string sumsPath, string fileName, string sha256)
        {
            var sums = new FileInfo(sumsPath);
            if (!sums.Exists) return false;
            if (sums.Length > MaxSumsBytes) throw new InvalidDataException("SHA256SUMS.txt beside foton-collect.exe is too large to be a release list.");
            foreach (var line in File.ReadAllLines(sums.FullName))
            {
                var m = Regex.Match(line, @"^([0-9a-fA-F]{64}) [ *](.+)$");
                if (!m.Success || !string.Equals(m.Groups[2].Value.Trim(), fileName, StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(m.Groups[1].Value, sha256, StringComparison.OrdinalIgnoreCase)) return true;
                throw new InvalidDataException($"{fileName} does not match SHA256SUMS.txt beside it (listed {m.Groups[1].Value.ToLowerInvariant()}, file is {sha256}). It is not the released file.");
            }
            throw new InvalidDataException($"SHA256SUMS.txt beside {fileName} does not list it, so the file cannot be checked against the release.");
        }

        /// <summary>The profile name as a file or folder name part: letters, digits, '.', '-', '_' only.</summary>
        public static string SafeName(string name)
        {
            var safe = Regex.Replace(name ?? "", @"[^A-Za-z0-9._-]+", "_").Trim('_', '.');
            if (safe.Length > 40) safe = safe.Substring(0, 40).TrimEnd('_', '.');
            return safe.Length == 0 ? "profile" : safe;
        }

        static string Readme(CollectionProfile p, string profileSha, Version version, string sha, bool verified, DateTime utcNow)
        {
            var nl = "\r\n";
            var options = p.Options.Count == 0 ? "(none)" : string.Join(", ", p.Options.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => kv.Key + "=" + Convert.ToString(kv.Value, CultureInfo.InvariantCulture)!.ToLowerInvariant()));
            return string.Join(nl, new[]
            {
                "Foton collection bundle",
                $"Built {FotonTime.Format(utcNow)} UTC by Foton {FotonVersion.Product}",
                "",
                "Profile: " + TextFile.OneLine(p.Name),
                p.Description.Length > 0 ? "  " + TextFile.OneLine(p.Description) : null,
                $"  Categories:   {string.Join(", ", p.Categories)} ({p.Categories.Count} of {CollectionProfile.AllCategories.Count})",
                "  ExcludeTasks: " + (p.ExcludeTasks.Count == 0 ? "(none)" : string.Join(", ", p.ExcludeTasks)),
                "  Options:      " + options,
                $"  {ProfileFileName} SHA-256 {profileSha}",
                "",
                $"{CollectFileName} {Show(version)} SHA-256 {sha}",
                verified
                    ? "  Matches SHA256SUMS.txt from the folder it was copied from."
                    : "  NOT verified: there was no SHA256SUMS.txt beside the source. Compare this hash with the release's SHA256SUMS.txt before use.",
                "",
                "On the endpoint, from this folder (an elevated prompt collects the most; a standard user is supported):",
                $"  .\\{CollectFileName} -Profile .\\{ProfileFileName} -CaseNumber CASE-0001 -Examiner NAME",
                "",
                "A switch given on the command line wins over the same option in the profile. Before running, check both files:",
                $"  Get-FileHash .\\{CollectFileName}, .\\{ProfileFileName} -Algorithm SHA256",
                $"and compare with {SumsFileName} in this folder (carried separately if the channel is untrusted).",
                "",
            }.Where(l => l != null));
        }
    }
}
