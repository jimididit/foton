using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>Installed software, drivers, browser extensions, and AppX packages (Invoke-FotonSoftwareCollection).</summary>
    public static class SoftwareCollection
    {
        const string Cat = "Software", Cimv2 = @"root\cimv2";

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting installed software, drivers, and browser extensions", StatusLevel.Step);
            Task(s, Cat, "installed_software", "Installed programs from all registry views", TaskFormat.Csv, () => InstalledSoftware(s));
            Task(s, Cat, "drivers", "Kernel and file system drivers with signature state", TaskFormat.Csv, () => Drivers(s));
            Task(s, Cat, "browser_extensions", "Chromium-family extension folders and Firefox profile add-ons", TaskFormat.Csv, () => BrowserExtensions(s));
            Task(s, Cat, "remote_access_tool_indicators", "Presence of common remote access / tunneling tooling", TaskFormat.Csv, () => RemoteAccessIndicators(s));
            // -AllUsers needs elevation; standard-user coverage is this token's packages only.
            Task(s, Cat, "appx_packages", "Installed Store/AppX packages", TaskFormat.Csv, () => Appx.Packages(s.IsElevated));

            if (!s.Options.Deep) return;
            Task(s, Cat, "pnp_devices", "Deep: Win32_PnPEntity inventory (Name, DeviceID, class, service). No binary copy.", TaskFormat.Csv, () =>
                Wmi.Query(Cimv2, "SELECT Name, DeviceID, Manufacturer, Status, PNPClass, Service FROM Win32_PnPEntity").Select(d => new Dictionary<string, object?>
                {
                    ["Name"] = Raw(d, "Name"), ["DeviceID"] = Raw(d, "DeviceID"), ["Manufacturer"] = Raw(d, "Manufacturer"),
                    ["Status"] = Raw(d, "Status"), ["PNPClass"] = Raw(d, "PNPClass"), ["Service"] = Raw(d, "Service"),
                }).OrderBy(r => r["DeviceID"] as string ?? "", StringComparer.InvariantCultureIgnoreCase).ToList());
            Task(s, Cat, "driverstore_inventory", "Deep: DriverStore\\FileRepository inventory. SHA-256 for .sys/.inf/.cat only. No full tree copy into the package.", TaskFormat.Csv,
                () => DriverStore(s));
        }

        static readonly string[] UninstallValues = { "DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation", "UninstallString" };

        static object InstalledSoftware(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            void Read(string root, string scope, string user)
            {
                foreach (var name in Reg.SubKeyNames(root))
                {
                    var key = Reg.Join(root, name);
                    var display = BaselineDocument.PsString(Reg.Value(key, "DisplayName"));
                    if (display.Length == 0) continue;
                    var row = new Dictionary<string, object?> { ["Scope"] = scope, ["User"] = user };
                    foreach (var v in UninstallValues) row[v] = BaselineDocument.PsString(Reg.Value(key, v));
                    rows.Add(row);
                }
            }
            Read(@"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Machine", "");
            Read(@"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Machine", "");
            foreach (var h in HostInfo.HiveRoots(s.IsElevated))
                Read(Reg.Join(h.Root, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"), "User", h.UserName);
            return rows.OrderBy(r => (string)r["DisplayName"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }

        static object Drivers(FotonSession s) =>
            Wmi.Query(Cimv2, "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_SystemDriver").Select(d =>
            {
                var path = Wmi.Str(d, "PathName");
                if (path.Length > 0) path = Environment.ExpandEnvironmentVariables(path.Trim('"'));
                // WMI reports some drivers as \??\C:\...; 1.38.x could not open those and recorded FileNotFound.
                var file = Authenticode.Openable(path);
                var sig = Authenticode.Check(file);
                return new Dictionary<string, object?>
                {
                    ["Name"] = Raw(d, "Name"), ["DisplayName"] = Raw(d, "DisplayName"), ["State"] = Raw(d, "State"), ["StartMode"] = Raw(d, "StartMode"),
                    ["PathName"] = path, ["SignatureStatus"] = sig.Status, ["Signer"] = sig.Signer, ["SHA256"] = Hashing.SafeHash(file, s.Options.SkipHashing),
                };
            }).OrderBy(r => r["Name"] as string ?? "", StringComparer.InvariantCultureIgnoreCase).ToList();

        static readonly string[][] Chromium =
        {
            new[] { "Chrome", @"AppData\Local\Google\Chrome\User Data" },
            new[] { "Edge", @"AppData\Local\Microsoft\Edge\User Data" },
            new[] { "Brave", @"AppData\Local\BraveSoftware\Brave-Browser\User Data" },
        };

        static object BrowserExtensions(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            Dictionary<string, object?> Row(string user, string browser, string profile, string id, string name, string version, string perms, DateTime created) =>
                new Dictionary<string, object?>
                {
                    ["User"] = user, ["Browser"] = browser, ["BrowserProfile"] = profile, ["ExtensionId"] = id, ["Name"] = name,
                    ["Version"] = version, ["Permissions"] = perms, ["InstalledUtc"] = FotonTime.Format(created),
                };
            foreach (var p in HostInfo.Profiles(s.IsElevated).Where(p => p.Exists))
            {
                foreach (var b in Chromium)
                {
                    var userData = Path.Combine(p.ProfilePath, b[1]);
                    foreach (var profile in Dirs(userData))
                        foreach (var ext in Dirs(Path.Combine(profile, "Extensions")))
                        {
                            string name = "", version = "", perms = "";
                            var manifest = FirstManifest(ext);
                            if (manifest != null && Read(manifest) is IDictionary m)
                            {
                                name = Str(m, "name");
                                version = Str(m, "version");
                                if (m.Contains("permissions") && m["permissions"] is IEnumerable list && !(m["permissions"] is string))
                                    perms = string.Join(", ", list.Cast<object?>().Select(x => x is string str ? str : Json.Compact(x)));
                            }
                            rows.Add(Row(p.UserName, b[0], Path.GetFileName(profile), Path.GetFileName(ext), name, version, perms, Created(ext)));
                        }
                }
                foreach (var ff in Dirs(Path.Combine(p.ProfilePath, @"AppData\Roaming\Mozilla\Firefox\Profiles")))
                {
                    var extDir = Path.Combine(ff, "extensions");
                    if (!Directory.Exists(extDir)) continue;
                    foreach (var x in Entries(extDir))
                        rows.Add(Row(p.UserName, "Firefox", Path.GetFileName(ff), Path.GetFileName(x), "", "", "", Created(x)));
                }
            }
            return rows;
        }

        static IEnumerable<string> Dirs(string path)
        {
            try { return Directory.Exists(path) ? Directory.GetDirectories(path) : new string[0]; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new string[0]; }
        }

        static IEnumerable<string> Entries(string path)
        {
            try { return Directory.GetFileSystemEntries(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new string[0]; }
        }

        /// <summary>The first manifest.json under an extension folder (version subfolders), in Get-ChildItem -Recurse order.</summary>
        static string? FirstManifest(string dir)
        {
            var pending = new Stack<string>();
            pending.Push(dir);
            while (pending.Count > 0)
            {
                var d = pending.Pop();
                string[] files, subs;
                try { files = Directory.GetFiles(d, "manifest.json"); subs = Directory.GetDirectories(d); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                if (files.Length > 0) return files[0];
                // Extension folders are user-writable: a junction there could loop or point outside the profile.
                for (int i = subs.Length - 1; i >= 0; i--) if (!Reparse(subs[i])) pending.Push(subs[i]);
            }
            return null;
        }

        static bool Reparse(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return true; }
        }

        /// <summary>Every file under a folder; a subfolder that cannot be read is skipped, never the whole walk. Junctions are not followed.</summary>
        static IEnumerable<FileInfo> Files(string root)
        {
            var pending = new Stack<DirectoryInfo>();
            pending.Push(new DirectoryInfo(root));
            while (pending.Count > 0)
            {
                var d = pending.Pop();
                FileInfo[] files;
                DirectoryInfo[] subs;
                try { files = d.GetFiles(); subs = d.GetDirectories(); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                foreach (var f in files) yield return f;
                foreach (var sub in subs) if ((sub.Attributes & FileAttributes.ReparsePoint) == 0) pending.Push(sub);
            }
        }

        static object? Read(string manifest)
        {
            try { return Json.Parse(File.ReadAllText(manifest)); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is InvalidOperationException) { return null; }
        }

        static string Str(IDictionary d, string key) => d.Contains(key) && d[key] != null ? Csv.FormatValue(d[key]!) : "";

        static DateTime Created(string path)
        {
            try { return Directory.Exists(path) ? Directory.GetCreationTimeUtc(path) : File.GetCreationTimeUtc(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return DateTime.MinValue; }
        }

        /// <summary>
        /// Remote-access and tunneling tool names matched against installed software and, when those categories ran,
        /// running processes and services. A hit is presence, not abuse: admin RMM and file-transfer tools match too.
        /// </summary>
        static object RemoteAccessIndicators(FotonSession s)
        {
            var known = PatternLists.RemoteAccessToolNames.Select(k => k.ToLowerInvariant()).ToList();
            var rows = new List<Dictionary<string, object?>>();
            void Scan(string source, string? task, Func<object, string> haystack, string detail, string publisher, string extra)
            {
                if (task == null || !(s.Data.TryGetValue(task, out var data) && data is IEnumerable items)) return;
                foreach (var item in items.Cast<object?>().Where(i => i != null))
                {
                    var n = haystack(item!).ToLowerInvariant();
                    var hit = known.FirstOrDefault(k => n.Contains(k));
                    if (hit != null)
                        rows.Add(new Dictionary<string, object?>
                        {
                            ["Source"] = source, ["Match"] = hit, ["Detail"] = Field(item!, detail), ["Publisher"] = Field(item!, publisher), ["Extra"] = Field(item!, extra),
                        });
                }
            }
            Scan("InstalledSoftware", "installed_software", i => Field(i, "DisplayName") + " " + Field(i, "Publisher"), "DisplayName", "Publisher", "InstallLocation");
            Scan("RunningProcess", "running_processes", i => Field(i, "Name") + " " + Field(i, "Path"), "Name", "Signer", "Path");
            Scan("Service", "services", i => Field(i, "Name") + " " + Field(i, "DisplayName") + " " + Field(i, "PathName"), "DisplayName", "Signer", "PathName");
            return rows;
        }

        /// <summary>A named field of a task row (a dictionary or an object), as text.</summary>
        internal static string Field(object row, string name)
        {
            object? v = row is IDictionary d ? (d.Contains(name) ? d[name] : null) : row.GetType().GetProperty(name)?.GetValue(row);
            return v == null ? "" : Csv.FormatValue(v);
        }

        static object DriverStore(FotonSession s)
        {
            var repo = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\DriverStore\FileRepository");
            if (!Directory.Exists(repo))
                return new[]
                {
                    new Dictionary<string, object?> { ["Path"] = repo, ["SizeBytes"] = 0L, ["Extension"] = "", ["ModifiedUtc"] = "", ["SHA256"] = "", ["Note"] = "DriverStore FileRepository not found. Visibility gap." },
                };
            var hashed = new[] { ".sys", ".inf", ".cat" };
            var rows = new List<Dictionary<string, object?>>();
            foreach (var f in Files(repo))
                rows.Add(new Dictionary<string, object?>
                {
                    ["Path"] = f.FullName, ["SizeBytes"] = f.Length, ["Extension"] = f.Extension, ["ModifiedUtc"] = FotonTime.Format(f.LastWriteTimeUtc),
                    ["SHA256"] = hashed.Any(h => h.Equals(f.Extension, StringComparison.OrdinalIgnoreCase)) ? Hashing.SafeHash(f.FullName, s.Options.SkipHashing) : "",
                    ["Note"] = "",
                });
            return rows.OrderBy(r => (string)r["Path"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }
    }
}
