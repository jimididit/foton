using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect
{
    /// <summary>
    /// Local OneDrive and Teams presence (Get-FotonOneDriveTeamsRows). Inventory only: registry account fields, sync
    /// roots without walking the cloud tree, and a capped log listing. Databases, cookies, and tokens are never copied
    /// or read; nothing calls Graph.
    /// </summary>
    static class CloudClients
    {
        static readonly string[] MachineRoots = { @"HKLM:\SOFTWARE\Microsoft\OneDrive", @"HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive" };
        static readonly Regex LogExtension = new Regex(@"\.(log|txt|aodl)$", RegexOptions.IgnoreCase);

        static Dictionary<string, object?> Row(string kind, string scope, string user, string identity, string path, bool exists, string email,
            string detail, string note, object? sizeBytes = null, string modifiedUtc = "") => new Dictionary<string, object?>
        {
            ["Kind"] = kind, ["Scope"] = scope, ["User"] = user, ["Identity"] = identity, ["Path"] = path, ["Exists"] = exists,
            ["SizeBytes"] = sizeBytes ?? "", ["ModifiedUtc"] = modifiedUtc, ["Email"] = email, ["Detail"] = detail, ["Note"] = note,
        };

        public static List<Dictionary<string, object?>> Rows(List<UserProfile> profiles, List<UserHive> hives)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var mr in MachineRoots.Where(Reg.Exists))
            {
                var loc = CloudJoin.V(mr, "CurrentVersionPath");
                if (loc.Length == 0) loc = CloudJoin.V(mr, "InstallLocation");
                rows.Add(Row("OneDriveMachine", "Machine", "N/A", mr, loc, HostInfo.Accessible(loc), "", CloudJoin.V(mr, "Version"),
                    "HKLM OneDrive install path/version. Not a sync inventory."));
            }

            foreach (var hive in hives)
            {
                var user = hive.UserName.Length > 0 ? hive.UserName : hive.Sid;
                var acctRoot = Reg.Join(hive.Root, @"Software\Microsoft\OneDrive\Accounts");
                foreach (var leaf in Reg.SubKeyNames(acctRoot))
                {
                    var key = Reg.Join(acctRoot, leaf);
                    var folder = CloudJoin.V(key, "UserFolder");
                    var email = CloudJoin.V(key, "UserEmail");
                    var cid = CloudJoin.V(key, "cid");
                    var endpoint = CloudJoin.V(key, "ServiceEndpointUri");
                    var id = cid.Length > 0 ? cid : leaf;
                    rows.Add(Row("OneDriveAccount", "User", user, id, folder, HostInfo.Accessible(folder), email,
                        endpoint.Length > 0 ? leaf + "; Endpoint=" + endpoint : leaf,
                        "OneDrive Accounts subkey. Endpoint is cached config, not a live tenant call. Token values are omitted."));
                    if (folder.Length > 0)
                        rows.AddRange(Folder("OneDriveFolder", "User", user, id, folder, email, "Sync root only. Children at depth 0. Cloud contents are not walked or copied.", false));
                }
            }

            foreach (var p in profiles.Where(p => p.Exists && p.ProfilePath.Length > 0))
            {
                var user = p.UserName;
                var root = p.ProfilePath;
                foreach (var d in Directories(root).Where(d => d.Name.StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase)).Take(8))
                {
                    if (rows.Any(r => (string)r["Kind"]! == "OneDriveFolder" && string.Equals((string)r["Path"]!, d.FullName, StringComparison.OrdinalIgnoreCase))) continue;
                    rows.AddRange(Folder("OneDriveFolder", "User", user, d.Name, d.FullName, "", "Profile-root folder named OneDrive*. Not a full cloud listing.", false));
                }

                rows.AddRange(Logs("OneDriveLog", user, Path.Combine(root, @"AppData\Local\Microsoft\OneDrive\logs"), 2, 20));

                var teamsClassic = Path.Combine(root, @"AppData\Roaming\Microsoft\Teams");
                rows.AddRange(Folder("TeamsClassic", "User", user, "TeamsClassic", teamsClassic, "", "Classic Teams appdata. Cookies/IndexedDB are not copied.", true));
                var classicLog = Path.Combine(teamsClassic, "logs.txt");
                if (HostInfo.Accessible(classicLog))
                {
                    try
                    {
                        var f = new FileInfo(classicLog);
                        rows.Add(Row("TeamsLog", "User", user, f.Name, f.FullName, true, "", "", "Classic Teams logs.txt name/size/mtime only. Contents not read.",
                            f.Length, FotonTime.Format(f.LastWriteTimeUtc)));
                    }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }

                rows.AddRange(Folder("TeamsLocal", "User", user, "TeamsLocal", Path.Combine(root, @"AppData\Local\Microsoft\Teams"), "",
                    "Local Microsoft\\Teams folder (new or leftover client). Not copied.", true));

                var pkgRoot = Path.Combine(root, @"AppData\Local\Packages");
                if (HostInfo.Accessible(pkgRoot))
                    foreach (var d in Directories(pkgRoot).Where(d => d.Name.StartsWith("MSTeams_", StringComparison.OrdinalIgnoreCase) || d.Name.StartsWith("MicrosoftTeams_", StringComparison.OrdinalIgnoreCase)).Take(4))
                        rows.AddRange(Folder("TeamsStore", "User", user, d.Name, d.FullName, "", "Store/MSIX Teams package folder. Databases inside are not copied or parsed.", false));
            }

            return rows.OrderBy(r => (string)r["Kind"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["User"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["Identity"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["Path"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }

        static IEnumerable<DirectoryInfo> Directories(string path)
        {
            if (!HostInfo.Accessible(path)) return new DirectoryInfo[0];
            try { return new DirectoryInfo(path).GetDirectories(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new DirectoryInfo[0]; }
        }

        /// <summary>Get-FotonCloudClientFolderRow: existence, write time, and the number of direct children.</summary>
        static IEnumerable<Dictionary<string, object?>> Folder(string kind, string scope, string user, string identity, string path, string email, string note, bool onlyIfExists)
        {
            var exists = HostInfo.Accessible(path);
            if (onlyIfExists && !exists) yield break;
            string mtime = "", detail = "";
            if (exists)
            {
                try
                {
                    mtime = FotonTime.Format(Directory.Exists(path) ? Directory.GetLastWriteTimeUtc(path) : File.GetLastWriteTimeUtc(path));
                    int n = 0;
                    try { if (Directory.Exists(path)) n = Directory.EnumerateFileSystemEntries(path).Count(); }
                    catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                    detail = "RootChildCount=" + n;
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
            yield return Row(kind, scope, user, identity, path, exists, email, detail, note, null, mtime);
        }

        /// <summary>Get-FotonCloudClientLogRows: newest log/txt/aodl names, sizes, and times; contents are never read.</summary>
        static IEnumerable<Dictionary<string, object?>> Logs(string kind, string user, string directory, int depth, int maxFiles)
        {
            if (!HostInfo.Accessible(directory)) return new Dictionary<string, object?>[0];
            return FileWalk.Files(directory, depth).Where(f => LogExtension.IsMatch(f.Extension)).OrderByDescending(f => f.LastWriteTimeUtc).Take(maxFiles)
                .Select(f => Row(kind, "User", user, f.Name, f.FullName, true, "", "", "Log name/size/mtime only. Contents are not read or copied.",
                    f.Length, FotonTime.Format(f.LastWriteTimeUtc))).ToList();
        }
    }

    /// <summary>Get-ChildItem -Recurse -File -Force -Depth n: a directory's files, then each subdirectory in turn.</summary>
    static class FileWalk
    {
        /// <summary>
        /// Files at most <paramref name="depth"/> levels below root. Unreadable directories are skipped (SilentlyContinue).
        /// Reparse-point directories (junctions, symlinks) are not followed: they can loop or lead off the volume.
        /// </summary>
        public static IEnumerable<FileInfo> Files(string root, int depth)
        {
            var stack = new Stack<KeyValuePair<DirectoryInfo, int>>();
            stack.Push(new KeyValuePair<DirectoryInfo, int>(new DirectoryInfo(root), depth));
            while (stack.Count > 0)
            {
                var item = stack.Pop();
                FileSystemInfo[] entries;
                try { entries = item.Key.GetFileSystemInfos(); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException) { continue; }
                foreach (var f in entries.OfType<FileInfo>()) yield return f;
                if (item.Value <= 0) continue;
                var subdirs = entries.OfType<DirectoryInfo>().Where(d => (d.Attributes & FileAttributes.ReparsePoint) == 0).ToList();
                for (int i = subdirs.Count - 1; i >= 0; i--) stack.Push(new KeyValuePair<DirectoryInfo, int>(subdirs[i], item.Value - 1));
            }
        }
    }
}
