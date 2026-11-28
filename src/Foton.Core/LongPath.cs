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
        const string DevicePrefix = @"\\.\";

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
            // A device path (\\.\C:\...) names the same drive; it is not a share, so it maps to the drive form.
            if (path.StartsWith(DevicePrefix, StringComparison.Ordinal)) return Prefix + path.Substring(DevicePrefix.Length);
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
        /// removed lexically (no disk access, so it works on a folder that is not there). A UNC path is normalized the same
        /// way below its share; a bare share is returned as given. Forms that are neither drive nor UNC are returned joined.
        /// </summary>
        public static string Full(string path)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            // Absolute first: GetFullPath on a relative name joins the working folder itself, and that throws for a short
            // name too when the folder is long (about 250 characters or more).
            var absolute = Path.IsPathRooted(path) ? path : Path.Combine(Directory.GetCurrentDirectory(), path);
            // A prefixed path does not normalize on disk, so its . and .. are resolved here, from the normal form.
            if (absolute.StartsWith(Prefix, StringComparison.Ordinal)) absolute = Plain(absolute);
            // GetFullPath for a path that names its drive and folder. \folder and C:folder depend on the current folder, and
            // GetFullPath throws for them when that folder is long, so they go through the lexical path below even when short.
            if (absolute.Length < Threshold && !DependsOnCurrentFolder(absolute)) return Path.GetFullPath(absolute);
            var original = absolute = absolute.Replace('/', '\\');
            // \folder\tool names the current drive but is not drive-qualified; give it the drive so the prefix can go on later.
            if (absolute[0] == '\\' && !absolute.StartsWith(@"\\", StringComparison.Ordinal))
                absolute = Path.GetPathRoot(Directory.GetCurrentDirectory()).TrimEnd('\\') + absolute;
            if (absolute.StartsWith(@"\\", StringComparison.Ordinal))
            {
                // \\server\share\rest: the share is the root, and . and .. are resolved in the rest only.
                var segs = absolute.Substring(2).Split('\\');
                if (segs.Length < 2) return absolute;
                var share = @"\\" + segs[0] + "\\" + segs[1];
                var tail = string.Join("\\", segs, 2, segs.Length - 2);
                // A bare share keeps its form (no trailing backslash added); only a path under the share gets one.
                return tail.Length == 0 ? share : KeepTrailingBackslash(original, Normalize(share + "\\", tail));
            }
            // C:folder\tool is relative to the current folder of drive C, which Windows keeps per drive in the =C: variable
            // (the root when the variable is not set). Resolve it there, so the prefix can go on.
            if (absolute.Length >= 2 && absolute[1] == ':' && (absolute.Length < 3 || absolute[2] != '\\'))
            {
                var drive = absolute.Substring(0, 2);
                // On the current drive the process folder is the answer; for another drive, Windows keeps it in =X:.
                var cwd = Directory.GetCurrentDirectory();
                var driveCwd = cwd.StartsWith(drive, StringComparison.OrdinalIgnoreCase) ? cwd : Environment.GetEnvironmentVariable("=" + drive);
                if (string.IsNullOrEmpty(driveCwd)) driveCwd = drive + "\\";
                absolute = driveCwd.TrimEnd('\\') + "\\" + absolute.Substring(2);
                original = absolute;
            }
            if (absolute.Length < 3 || absolute[1] != ':' || absolute[2] != '\\') return absolute;
            return KeepTrailingBackslash(original, Normalize(absolute.Substring(0, 3), absolute.Substring(3)));
        }

        /// <summary>True for \folder (the current drive) and C:folder (the current folder of drive C): they need the current folder to resolve.</summary>
        static bool DependsOnCurrentFolder(string path)
        {
            if (path.Length > 0 && (path[0] == '\\' || path[0] == '/'))
                return path.Length < 2 || (path[1] != '\\' && path[1] != '/');   // \\server is a share, not the current drive
            return path.Length >= 2 && path[1] == ':' && (path.Length < 3 || (path[2] != '\\' && path[2] != '/'));
        }

        /// <summary>GetFullPath keeps a trailing backslash; the lexical form does too, so a long folder path reads like a short one.</summary>
        static string KeepTrailingBackslash(string original, string result) =>
            original.EndsWith("\\", StringComparison.Ordinal) && !result.EndsWith("\\", StringComparison.Ordinal) ? result + "\\" : result;

        /// <summary>
        /// The folder a path lies in, cut at its last backslash without touching the disk. A drive root keeps its
        /// backslash: the parent of C:\tool.exe is C:\, not the drive-relative C:. Empty when there is no backslash.
        /// </summary>
        public static string ParentOf(string path)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            // Windows reads / as \ in a normal path, so C:/tools/x.exe has the folder C:\tools, not none.
            path = path.Replace('/', '\\');
            // A prefixed share works on its normal form: \\?\UNC\server\share\x lies in \\?\UNC\server\share, and the share has no parent.
            if (path.StartsWith(UncPrefix, StringComparison.Ordinal))
            {
                var uncParent = ParentOf(@"\\" + path.Substring(UncPrefix.Length));
                return uncParent.Length == 0 ? "" : UncPrefix + uncParent.Substring(2);
            }
            // A device path (\\.\C:\tool.exe) keeps its prefix; its folder is worked out from the drive form.
            if (path.StartsWith(DevicePrefix, StringComparison.Ordinal))
            {
                var deviceParent = ParentOf(path.Substring(DevicePrefix.Length));
                return deviceParent.Length == 0 ? "" : DevicePrefix + deviceParent;
            }
            var cut = path.LastIndexOf('\\');
            if (cut < 0) return "";
            // A drive root keeps its backslash, prefixed or not: \\?\C:\tool.exe lies in \\?\C:\, not \\?\C:.
            var at = path.StartsWith(Prefix, StringComparison.Ordinal) ? Prefix.Length : 0;
            if (cut == at + 2 && path.Length > at + 1 && path[at + 1] == ':') return path.Substring(0, at + 3);
            if (path.StartsWith(@"\\", StringComparison.Ordinal))
            {
                // \\server\share has no folder above it: its last backslash is the one after the server, not a parent.
                var server = path.IndexOf('\\', 2);
                if (server < 0 || path.IndexOf('\\', server + 1) < 0) return "";
            }
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
