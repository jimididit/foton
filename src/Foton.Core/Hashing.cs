using System;
using System.IO;
using System.Security.Cryptography;

namespace Foton.Core
{
    /// <summary>SHA-256 as uppercase hex (the format hashes.csv and every hash column use).</summary>
    public static class Hashing
    {
        public const long SafeHashLimitBytes = 200L * 1024 * 1024;

        public static string Sha256Hex(string path)
        {
            using (var sha = SHA256.Create())
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                return ToHex(sha.ComputeHash(fs));
        }

        public static string Sha256Hex(byte[] data)
        {
            using (var sha = SHA256.Create()) return ToHex(sha.ComputeHash(data));
        }

        public static string ToHex(byte[] hash) => BitConverter.ToString(hash).Replace("-", "");

        /// <summary>
        /// The hash, or a sentinel recording why there is none: NotHashed (hashing was skipped),
        /// "" (no path), SkippedRemotePath (a UNC path, never opened), FileNotFound, SkippedTooLarge
        /// (over 200 MB), HashError. Sentinels are facts about the attempt, never hash values; do not
        /// match them as IOCs.
        /// </summary>
        public static string SafeHash(string? path, bool skipHashing)
        {
            if (skipHashing) return "NotHashed";
            if (string.IsNullOrWhiteSpace(path)) return "";
            if (IsRemotePath(path!)) return "SkippedRemotePath";
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return "FileNotFound";
                if (fi.Length > SafeHashLimitBytes) return "SkippedTooLarge";
                return Sha256Hex(fi.FullName);
            }
            catch (Exception) { return "HashError"; }
        }

        /// <summary>
        /// A UNC or remote device path (\\server\share, \\?\UNC\..., \??\UNC\...). Paths read from the host (driver,
        /// service, and task image paths) are attacker-controlled; opening a UNC one makes the collector connect over SMB
        /// and offer the examiner's credentials, so such paths are recorded but never opened. \\?\C:\ and \\.\C:\ are local.
        /// </summary>
        public static bool IsRemotePath(string path)
        {
            var p = path.Trim().Trim('"');
            if (p.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
            if (!p.StartsWith(@"\\", StringComparison.Ordinal) && !p.StartsWith("//", StringComparison.Ordinal)) return false;
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"\\.\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
            // \\?\C:\... and \\.\C:\... are local; anything else after \\ names a server.
            return !(p.Length >= 7 && (p[2] == '?' || p[2] == '.') && (p[3] == '\\' || p[3] == '/') && char.IsLetter(p[4]) && p[5] == ':');
        }
    }
}
