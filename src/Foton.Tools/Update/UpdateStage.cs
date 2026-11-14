using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Package;

namespace Foton.Tools.Update
{
    /// <summary>
    /// Downloads a signed release's ZIP into the updates folder and proves every file against the signed statement
    /// before anything is installed. Any failure deletes the staging folder and names the check that failed.
    /// </summary>
    public static class UpdateStage
    {
        public const long MaxZipBytes = 64L * 1024 * 1024;
        public const long MaxEntryBytes = 64L * 1024 * 1024;

        /// <summary>The release ZIP's files besides the executables the statement lists.</summary>
        public static readonly IReadOnlyList<string> CompanionFiles = new[] { "LICENSE.txt", "README.txt", "SHA256SUMS.txt" };

        /// <summary>%LOCALAPPDATA%\Foton\updates: staging and update.log. Not beside the running executables.</summary>
        public static string Root()
        {
            var baseDir = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(baseDir))
                baseDir = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? "", "AppData", "Local");
            return Path.GetFullPath(Path.Combine(baseDir, "Foton", "updates"));
        }

        static readonly Regex ReleaseVersion = new Regex(@"^\d{1,4}\.\d{1,4}\.\d{1,4}\z", RegexOptions.CultureInvariant);

        /// <summary>updatesRoot\version, for an X.Y.Z version only: the one folder Stage and Clean may delete.</summary>
        static string WorkFolder(string updatesRoot, string version)
        {
            if (!ReleaseVersion.IsMatch(version)) throw new InvalidDataException("Not a release version: '" + TextFile.OneLine(version) + "'.");
            var root = Path.GetFullPath(updatesRoot).TrimEnd('\\') + "\\";
            var work = Path.GetFullPath(root + version);
            if (!work.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("The staging folder resolves outside " + root);
            return work;
        }

        /// <summary>Removes a version's staging folder (after an install, or to discard a download); a failure to delete is ignored.</summary>
        public static void Clean(string updatesRoot, string version)
        {
            var work = WorkFolder(updatesRoot, version);
            try { if (Directory.Exists(work)) Directory.Delete(work, true); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
        }

        /// <summary>Downloads and verifies; returns the folder holding the verified files (updatesRoot\version\Foton-version).</summary>
        public static string Stage(ReleaseStatement statement, string zipUrl, IUpdateSource source, string updatesRoot, StatusLog log)
        {
            var work = WorkFolder(updatesRoot, statement.Version);
            if (Directory.Exists(work)) Directory.Delete(work, true);
            Directory.CreateDirectory(work);
            try
            {
                var zip = Path.Combine(work, statement.ZipName);
                log.Write("Downloading " + zipUrl);
                using (var fs = new FileStream(zip, FileMode.CreateNew, FileAccess.Write))
                    source.Fetch(zipUrl, fs, MaxZipBytes);
                return Verify(statement, zip, Path.Combine(work, "Foton-" + statement.Version), log);
            }
            catch
            {
                try { Directory.Delete(work, true); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                throw;
            }
        }

        /// <summary>
        /// Checks a downloaded ZIP against the statement and extracts it to dest: the ZIP's SHA-256, only the expected
        /// files at its root, each executable's SHA-256, and each executable's version resource. dest must not exist yet.
        /// Deletes the ZIP after.
        /// </summary>
        public static string Verify(ReleaseStatement statement, string zip, string dest, StatusLog log)
        {
            var zipSha = Hashing.Sha256Hex(zip).ToLowerInvariant();
            log.Write($"{statement.ZipName} SHA-256 {zipSha}");
            if (zipSha != statement.ZipSha256)
                throw new InvalidDataException($"{statement.ZipName} does not match the signed SHA-256 (expected {statement.ZipSha256}, got {zipSha}).");

            var allowed = new HashSet<string>(statement.Files.Keys.Concat(CompanionFiles), StringComparer.Ordinal);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (var archive = ZipFile.OpenRead(zip))
                foreach (var entry in archive.Entries)
                {
                    var name = entry.FullName;
                    if (name.IndexOf('/') >= 0 || name.IndexOf('\\') >= 0 || !allowed.Contains(name))
                        throw new InvalidDataException($"{statement.ZipName} holds an unexpected entry '{TextFile.OneLine(name)}'.");
                    if (!seen.Add(name)) throw new InvalidDataException($"{statement.ZipName} holds {name} twice.");
                    if (entry.Length > MaxEntryBytes) throw new InvalidDataException($"{name} in {statement.ZipName} is over the {MaxEntryBytes}-byte limit.");
                }
            var missing = statement.Files.Keys.FirstOrDefault(f => !seen.Contains(f));
            if (missing != null) throw new InvalidDataException($"{statement.ZipName} does not hold {missing}.");

            if (Directory.Exists(dest) || File.Exists(dest)) throw new IOException(dest + " already exists; release files are extracted only into a new folder.");
            SafeZip.Extract(zip, dest);
            foreach (var pair in statement.Files.OrderBy(p => p.Key, StringComparer.Ordinal))
            {
                var path = Path.Combine(dest, pair.Key);
                var sha = Hashing.Sha256Hex(path).ToLowerInvariant();
                if (sha != pair.Value) throw new InvalidDataException($"{pair.Key} does not match the signed SHA-256 (expected {pair.Value}, got {sha}).");
                var info = FileVersionInfo.GetVersionInfo(path);
                var version = $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}";
                if (version != statement.Version) throw new InvalidDataException($"{pair.Key} carries version {version}, not the signed {statement.Version}.");
                log.Write($"{pair.Key} {version} SHA-256 {sha} matches the signed statement.", StatusLevel.Good);
            }
            File.Delete(zip);
            return dest;
        }
    }

    /// <summary>
    /// Installs verified files side by side: a new Foton-version folder, never over the running executables. The old
    /// folder stays, so a case can be re-run with the version that produced it.
    /// </summary>
    public static class UpdateInstall
    {
        /// <summary>A Scoop install updates through Scoop (it checks its own hash and keeps its own versions).</summary>
        public static bool IsScoop(string exeDir) =>
            (Path.GetFullPath(exeDir).TrimEnd('\\') + "\\").IndexOf(@"\scoop\apps\", StringComparison.OrdinalIgnoreCase) >= 0;

        /// <summary>Foton-version beside the folder the running executable is in (inside it when that is a drive root).</summary>
        public static string DefaultTarget(string exeDir, string version)
        {
            var full = Path.GetFullPath(exeDir).TrimEnd('\\');
            var parent = Path.GetDirectoryName(full);
            return Path.Combine(string.IsNullOrEmpty(parent) ? full + "\\" : parent, "Foton-" + version);
        }

        /// <summary>
        /// Copies the staged files to target through a temporary sibling folder, checks the executables again there, then
        /// renames it into place. A target that already holds this release is reported as installed; any other existing
        /// target is refused. The staging folder is removed afterwards.
        /// </summary>
        public static string Install(string staged, string target, ReleaseStatement statement, StatusLog log)
        {
            target = Path.GetFullPath(target).TrimEnd('\\');
            if (File.Exists(target)) throw new IOException(target + " is a file; choose another folder.");
            if (Directory.Exists(target))
            {
                if (!Matches(target, statement)) throw new IOException(target + " already exists and does not hold this release; choose another folder.");
                log.Write($"Foton {statement.Version} is already installed in {target}.", StatusLevel.Good);
                return target;
            }
            var partial = target + ".partial-" + Guid.NewGuid().ToString("N");
            Directory.CreateDirectory(partial);
            try
            {
                foreach (var file in Directory.GetFiles(staged))
                    File.Copy(file, Path.Combine(partial, Path.GetFileName(file)));
                if (!Matches(partial, statement)) throw new InvalidDataException("The copied executables no longer match the signed statement; nothing installed.");
                Directory.Move(partial, target);
            }
            catch
            {
                try { Directory.Delete(partial, true); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                throw;
            }
            log.Write($"Installed Foton {statement.Version} in {target}.", StatusLevel.Good);
            return target;
        }

        static bool Matches(string folder, ReleaseStatement statement) =>
            statement.Files.All(p =>
            {
                var path = Path.Combine(folder, p.Key);
                return File.Exists(path) && Hashing.Sha256Hex(path).ToLowerInvariant() == p.Value;
            });
    }
}
