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
        /// "" (no path), FileNotFound, SkippedTooLarge (over 200 MB), HashError. Sentinels are facts
        /// about the attempt, never hash values; do not match them as IOCs.
        /// </summary>
        public static string SafeHash(string? path, bool skipHashing)
        {
            if (skipHashing) return "NotHashed";
            if (string.IsNullOrWhiteSpace(path)) return "";
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return "FileNotFound";
                if (fi.Length > SafeHashLimitBytes) return "SkippedTooLarge";
                return Sha256Hex(fi.FullName);
            }
            catch (Exception) { return "HashError"; }
        }
    }
}
