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
        /// "" (no path), SkippedNonLocalPath (not a local file path, never opened), FileNotFound,
        /// SkippedTooLarge (over 200 MB), HashError. Sentinels are facts about the attempt, never hash
        /// values; do not match them as IOCs.
        /// </summary>
        public static string SafeHash(string? path, bool skipHashing)
        {
            if (skipHashing) return "NotHashed";
            if (string.IsNullOrWhiteSpace(path)) return "";
            if (!IsLocalPath(path!)) return "SkippedNonLocalPath";
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
        /// True only for a plainly local file path: a drive path (C:\..., optionally behind \\?\, \\.\, or \??\), a volume
        /// GUID path, or a root-relative or relative path. Paths read from the host (driver, service, task, profile) are
        /// attacker-controlled; a UNC path, a GLOBALROOT/Mup device path, or a raw device could make the collector connect
        /// over SMB and offer the examiner's credentials, or read a device. Anything not plainly local is recorded but
        /// never opened.
        /// </summary>
        public static bool IsLocalPath(string path)
        {
            var p = path.Trim().Trim('"').Replace('/', '\\');
            if (!p.StartsWith(@"\\", StringComparison.Ordinal) && !p.StartsWith(@"\??\", StringComparison.Ordinal)) return true;
            var rest = p.StartsWith(@"\??\", StringComparison.Ordinal) ? p.Substring(4)
                : p.Length >= 4 && (p[2] == '?' || p[2] == '.') && p[3] == '\\' ? p.Substring(4) : null;
            if (rest == null) return false;
            if (rest.Length >= 3 && char.IsLetter(rest[0]) && rest[1] == ':' && rest[2] == '\\') return true;
            return rest.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase) && rest.IndexOf('}') > 0;
        }
    }
}
