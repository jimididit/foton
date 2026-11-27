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
            if (string.IsNullOrEmpty(path) || path.Length < Threshold) return path;
            // Windows reads / as \, but the prefixed form does not normalize, so a C:/... path would be sent as is.
            if (path.IndexOf('/') >= 0) path = path.Replace('/', '\\');
            if (path.StartsWith(Prefix, StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return UncPrefix + path.Substring(2);
            // Length is already 240 or more here, so only the drive form needs checking.
            if (path[1] != ':' || path[2] != '\\') return path;
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
        /// GetFullPath for a path that may be long. GetFullPath throws on 260 characters or more under net462, so a long
        /// path is made absolute here: a relative one joins the current folder, and a drive path has its . and .. segments
        /// removed lexically (no disk access, so it works on a folder that is not there). Other long forms (UNC) are
        /// returned joined but not normalized.
        /// </summary>
        public static string Full(string path)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            // Absolute first: GetFullPath on a relative name joins the working folder itself, and that throws for a short
            // name too when the folder is long (about 250 characters or more).
            var absolute = Path.IsPathRooted(path) ? path : Path.Combine(Directory.GetCurrentDirectory(), path);
            if (absolute.Length < Threshold) return Path.GetFullPath(absolute);
            if (absolute.StartsWith(Prefix, StringComparison.Ordinal)) return absolute;
            absolute = absolute.Replace('/', '\\');
            if (absolute.StartsWith(@"\\", StringComparison.Ordinal))
            {
                // \\server\share\rest: the share is the root, and . and .. are resolved in the rest only.
                var segs = absolute.Substring(2).Split('\\');
                if (segs.Length < 2) return absolute;
                return Normalize(@"\\" + segs[0] + "\\" + segs[1] + "\\", string.Join("\\", segs, 2, segs.Length - 2));
            }
            if (absolute[1] != ':' || absolute[2] != '\\') return absolute;
            return Normalize(absolute.Substring(0, 3), absolute.Substring(3));
        }

        /// <summary>
        /// The folder a path lies in, cut at its last backslash without touching the disk. A drive root keeps its
        /// backslash: the parent of C:\tool.exe is C:\, not the drive-relative C:. Empty when there is no backslash.
        /// </summary>
        public static string ParentOf(string path)
        {
            var cut = path.LastIndexOf('\\');
            if (cut < 0) return "";
            if (cut == 2 && path[1] == ':') return path.Substring(0, 3);
            return path.Substring(0, cut);
        }

        // Resolves . and .. in the segments of rest under root (which ends with a backslash). A .. above root stops at root,
        // as Windows does, so the result stays under root.
        static string Normalize(string root, string rest)
        {
            var parts = new System.Collections.Generic.List<string>();
            foreach (var seg in rest.Split('\\'))
            {
                if (seg.Length == 0 || seg == ".") continue;
                if (seg == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); continue; }
                parts.Add(seg);
            }
            return root + string.Join("\\", parts);
        }
    }
}
