using System;
using System.IO;

namespace Foton.Core
{
    /// <summary>
    /// Long-path support for the file operations under a tool root (the pinned release unpacks several hundred rule files
    /// deep under %LOCALAPPDATA%). .NET Framework 4.x (net462) rejects a full path of 260 characters or more with
    /// PathTooLongException, and Directory/File checks answer "not found" for it, so a long Sigma rule would be skipped
    /// or its folder reported missing. foton.exe does not opt in to long paths in a manifest, so the \\?\ prefix is added
    /// here, only at the call that touches the disk. Paths that are returned, logged, or written to tools.json stay in
    /// the normal form, so the prefix never reaches a record. Use For() at I/O, Full() where GetFullPath would throw, and
    /// Plain() on names a prefixed call returns.
    /// </summary>
    public static class LongPath
    {
        const string Prefix = @"\\?\";
        const string UncPrefix = @"\\?\UNC\";

        // Short paths are passed through untouched, so every path that worked before still goes down the same call.
        const int Threshold = 240;

        /// <summary>
        /// The form to pass to a file-system call. A full path of 240 characters or more gets the prefix (\\?\ for a drive
        /// path, \\?\UNC\ for a share); anything shorter, relative, or already prefixed is returned unchanged. Pass a full path.
        /// </summary>
        public static string For(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length < Threshold || path.StartsWith(Prefix, StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return UncPrefix + path.Substring(2);
            if (path.Length < 3 || path[1] != ':' || path[2] != '\\') return path;
            return Prefix + path;
        }

        /// <summary>The normal form of a path a prefixed call returned (for example a file found under a prefixed folder).</summary>
        public static string Plain(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (path.StartsWith(UncPrefix, StringComparison.Ordinal)) return @"\\" + path.Substring(UncPrefix.Length);
            return path.StartsWith(Prefix, StringComparison.Ordinal) ? path.Substring(Prefix.Length) : path;
        }

        /// <summary>
        /// GetFullPath for a path that is already absolute and normalized (a recorded install path, for example). GetFullPath
        /// throws on 260 characters or more under net462, so a path that long is returned as it is.
        /// </summary>
        public static string Full(string path) => path.Length < Threshold ? Path.GetFullPath(path) : path;
    }
}
