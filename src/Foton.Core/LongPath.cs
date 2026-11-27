using System;

namespace Foton.Core
{
    /// <summary>
    /// Long-path support for the file operations under a tool root (the pinned release unpacks several hundred rule files
    /// deep under %LOCALAPPDATA%). .NET Framework 4.x (net462) rejects a full path of 260 characters or more with
    /// PathTooLongException, and Directory/File checks answer "not found" for it, so a long Sigma rule would be skipped
    /// or its folder reported missing. foton.exe does not opt in to long paths in a manifest, so the \\?\ prefix is added
    /// here, only at the call that touches the disk. Paths that are returned, logged, or written to tools.json stay in
    /// the normal form, so the prefix never reaches a record. Use For() at I/O and Plain() on names a prefixed call returns.
    /// </summary>
    public static class LongPath
    {
        const string Prefix = @"\\?\";

        // Short paths are passed through untouched, so every path that worked before still goes down the same call.
        const int Threshold = 240;

        /// <summary>
        /// The form to pass to a file-system call. A full local path (drive letter) of 240 characters or more gets the
        /// \\?\ prefix; anything else (short, relative, UNC) is returned unchanged. Pass a full path (GetFullPath first).
        /// </summary>
        public static string For(string path)
        {
            if (path.Length < Threshold || path.StartsWith(Prefix, StringComparison.Ordinal)) return path;
            if (path.Length < 3 || path[1] != ':' || path[2] != '\\') return path;
            return Prefix + path;
        }

        /// <summary>The normal form of a path a prefixed call returned (for example a file found under a prefixed folder).</summary>
        public static string Plain(string path) =>
            path.StartsWith(Prefix, StringComparison.Ordinal) && !path.StartsWith(Prefix + "UNC", StringComparison.Ordinal)
                ? path.Substring(Prefix.Length)
                : path;
    }
}
