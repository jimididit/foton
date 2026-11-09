using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>
    /// File-system execution evidence, copied artifacts for workstation parsing (Prefetch, Amcache, SRUM, hives, LNK,
    /// task XML, browser databases, host logs), and device history (Invoke-FotonFilesystemCollection). Copies are
    /// read-only with FileShare.ReadWrite; nothing is parsed on the endpoint.
    /// </summary>
    public static class FilesystemCollection
    {
        const string Cat = "Filesystem";

        static readonly string[] ExecutableExtensions = { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".jar", ".lnk", ".msi", ".sys", ".com", ".pif" };
        static readonly Regex SystemBinary = new Regex(@"\.(exe|dll|sys|ps1|bat|cmd)$", RegexOptions.IgnoreCase);

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting filesystem artifacts, execution evidence, and device history", StatusLevel.Step);
            var profiles = HostInfo.Profiles(s.IsElevated);
            var skip = s.Options.SkipHashing;
            Task(s, Cat, "executables_in_user_writable_paths", "Executable content in temp/appdata/programdata/public paths", TaskFormat.Csv, () => UserWritableExecutables(s, profiles));
            Task(s, Cat, "recently_modified_system_files", "System32/SysWOW64 binaries modified inside the collection window", TaskFormat.Csv, () => RecentSystemFiles(s));
            Task(s, Cat, "prefetch_listing", "Prefetch entries (execution evidence, names and timestamps only)", TaskFormat.Csv, PrefetchListing, elevated: true);
            Task(s, Cat, "prefetch_files", "Copied Prefetch .pf files (capped; parse these, not the live directory)", TaskFormat.Csv,
                () => HostCopy.CappedDirectory(Path.Combine(HostInfo.WindowsDir, "Prefetch"), "*.pf", Dest(s, "prefetch"), Rel("prefetch"), skip), elevated: true);
            Task(s, Cat, "amcache_hive", "Copied Amcache.hve plus hive logs (locked-file copy)", TaskFormat.Csv,
                () => HostCopy.Family(Path.Combine(HostInfo.WindowsDir, @"AppCompat\Programs\Amcache.hve"), Dest(s, "amcache"), Rel("amcache"), skip), elevated: true);
            Task(s, Cat, "srum_database", "Copied SRUM database folder (System32\\sru: SRUDB.dat, ESE logs, checkpoint; capped; locked-file copy)", TaskFormat.Csv,
                () => HostCopy.CappedDirectory(SrumDirectory(HostInfo.WindowsDir), "*", Dest(s, "srum"), Rel("srum"), skip, 64, 1073741824,
                    "SRUM folder not found or not readable. SRUM exists on Windows 8 and later; a missing folder is a visibility gap, not proof SRUM was off."), elevated: true);
            Task(s, Cat, "registry_hives_machine", "SYSTEM/SOFTWARE/DEFAULT hives exported with reg save (loaded hives cannot be file-copied; not parsed on the endpoint). SAM and SECURITY are not collected by design. For RECmd / Registry Explorer.", TaskFormat.Csv,
                () => MachineHives(s), elevated: true);
            Task(s, Cat, "registry_hives_user", "NTUSER.DAT and UsrClass.dat per profile: file copy for unloaded hives, reg save for loaded ones (capped; not parsed on the endpoint).", TaskFormat.Csv,
                () => UserHiveCopies(s, profiles), elevated: true);
            Task(s, Cat, "usn_journal", "USN queryjournal metadata; optional $J copy when -IncludeUsnJournal is set. $MFT is not copied (use KAPE/ORC).", TaskFormat.Csv, () => UsnJournal(s), elevated: true);
            Task(s, Cat, "bam_dam_user_settings", "BAM/DAM UserSettings (path = value name; FILETIME in data). Admin. Not a baseline.", TaskFormat.Csv, BamDam, elevated: true);
            Task(s, Cat, "appcompatcache_export", "Raw AppCompatCache (Shimcache) blob copied into the package; entries are not parsed", TaskFormat.Csv, () => AppCompatCache(s), elevated: true);
            Task(s, Cat, "alternate_data_streams", "Non-default NTFS streams in user paths (Zone.Identifier and beyond)", TaskFormat.Csv, () => AlternateStreams(s, profiles));
            Task(s, Cat, "recycle_bin_contents", "Deleted items still present in $Recycle.Bin per SID", TaskFormat.Csv, RecycleBin);
            Task(s, Cat, "usb_device_history", "USBSTOR entries and mounted device history (exfiltration pivot)", TaskFormat.Csv, UsbHistory);
            Task(s, Cat, "shortcut_and_jumplist_inventory", "Recent LNK and jump list files (file access evidence)", TaskFormat.Csv, () => RecentInventory(profiles));
            Task(s, Cat, "shortcut_and_jumplist_files", "Copied Recent .lnk and jumplist files (capped). Parse these copies, not the live profile.", TaskFormat.Csv,
                () => HostCopy.CappedList(RecentCopies(profiles), Dest(s, "lnk_jumplist"), Rel("lnk_jumplist"), skip, 400, 83886080), elevated: true);
            Task(s, Cat, "scheduled_task_xml", "Copied %SystemRoot%\\System32\\Tasks XML (capped). Complements the task CSV; not parsed on the endpoint.", TaskFormat.Csv,
                () => HostCopy.CappedList(TaskXml(), Dest(s, "task_xml"), Rel("task_xml"), skip, 500, 52428800), elevated: true);
            if (s.Options.Deep)
                Task(s, Cat, "task_action_scripts", "Deep: copied local script files referenced by scheduled-task Execute/Arguments (raised caps; UNC skipped; under 2 GiB free skips copy).", TaskFormat.Csv,
                    () => TaskActionScripts(s));
            Task(s, Cat, "browser_databases", "Copied browser History/Cookies/places.sqlite (capped). No cookie decryption, no Graph. Locked files are coverage gaps.", TaskFormat.Csv,
                () => HostCopy.CappedList(BrowserDatabases(profiles), Dest(s, "browser_db"), Rel("browser_db"), skip, 80, 104857600), elevated: true);
            Task(s, Cat, "host_text_logs", "Copied setupapi.dev.log, CBS.log (capped), and PowerShell transcripts if the policy path exists.", TaskFormat.Csv,
                () => HostCopy.CappedList(HostLogs(), Dest(s, "host_logs"), Rel("host_logs"), skip, 50, 52428800), elevated: true);
            Task(s, Cat, "onedrive_teams_local", "OneDrive/Teams local folders and account registry (no Graph, no cookie/DB copy)", TaskFormat.Csv,
                () => CloudClients.Rows(profiles, HostInfo.HiveRoots(s.IsElevated)));
            Task(s, Cat, "hidden_or_odd_root_items", "Hidden or unexpected items at drive roots and ProgramData", TaskFormat.Csv, HiddenRootItems);
        }

        static string Dest(FotonSession s, string sub) => Path.Combine(s.Dirs[Cat], sub);

        /// <summary>
        /// The SRUM ESE database folder. 1.38.x and v2 before 2.4.0 looked for SRUDB.dat under ProgramData, where it
        /// never is, so no package held SRUM. The whole folder is copied: the database alone is dirty without its
        /// logs (SRU*.log, SRU.chk), which do not share its name.
        /// </summary>
        internal static string SrumDirectory(string windowsDir) => Path.Combine(windowsDir, "System32", "sru");
        static string Rel(string sub) => Path.Combine(CaseCategories.FolderOf(Cat), sub);
        static string Utc(DateTime t) => FotonTime.Format(t);

        static string PublicDir => Environment.GetEnvironmentVariable("PUBLIC") is string p && p.Length > 0
            ? p : Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)) ?? @"C:\Users\Public";

        /// <summary>Sort-Object -Unique over paths: case-insensitive order and uniqueness.</summary>
        static List<string> UniqueSorted(IEnumerable<string> paths) =>
            paths.Distinct(StringComparer.InvariantCultureIgnoreCase).OrderBy(p => p, StringComparer.InvariantCultureIgnoreCase).ToList();

        static readonly ConditionalWeakTable<FotonSession, Dictionary<string, bool>> CaseOutputCache = new ConditionalWeakTable<FotonSession, Dictionary<string, bool>>();
        static readonly Regex PackageFolder = new Regex(@"(?i)^(?<root>.*?[\\/](?:Win)?Foton(?:Baseline)?_[^\\/]+_\d{8}-\d{6}Z)(?:[\\/]|$)");

        /// <summary>
        /// Test-FotonCaseOutputPath: true inside this run's case folder or an earlier Foton package, so a profile scan
        /// does not sweep a package's copied artifacts back in as host files. A name alone is not enough (anything can be
        /// named like a package): the folder must hold collection.log or baseline.json. Every skip is logged, and
        /// earlier packages are listed in collection_coverage.json because the markers can be forged.
        /// </summary>
        internal static bool IsCaseOutputPath(FotonSession s, string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            if (!string.IsNullOrEmpty(s.CaseRoot) && path.StartsWith(s.CaseRoot!.TrimEnd('\\', '/') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
            var m = PackageFolder.Match(path);
            if (!m.Success) return false;
            var root = m.Groups["root"].Value;
            var cache = CaseOutputCache.GetOrCreateValue(s);
            if (cache.TryGetValue(root, out var known)) return known;
            bool own = !string.IsNullOrEmpty(s.CaseRoot) && string.Equals(s.CaseRoot!.TrimEnd('\\', '/'), root, StringComparison.OrdinalIgnoreCase);
            bool package = own || File.Exists(Path.Combine(root, @"00_Collection\collection.log")) || File.Exists(Path.Combine(root, "baseline.json"));
            cache[root] = package;
            if (package)
            {
                s.Status.Write($"Skipping {(own ? "this collection's own case folder" : "earlier Foton package")} in profile scan: {root}", StatusLevel.Info);
                if (!own && !s.ExcludedEarlierPackages.Contains(root)) s.ExcludedEarlierPackages.Add(root);
            }
            return package;
        }

        static object UserWritableExecutables(FotonSession s, List<UserProfile> profiles)
        {
            var roots = new List<string> { Path.Combine(HostInfo.WindowsDir, "Temp"), HostInfo.ProgramDataDir, PublicDir };
            foreach (var p in profiles.Where(p => p.Exists))
                roots.AddRange(new[] { @"AppData\Local\Temp", @"AppData\Roaming", "Downloads", "Desktop" }.Select(sub => Path.Combine(p.ProfilePath, sub)));
            var depth = s.Options.IncludeFileTimeline ? 6 : 3;
            var rows = new List<Dictionary<string, object?>>();
            foreach (var r in UniqueSorted(roots).Where(HostInfo.Accessible))
                foreach (var f in FileWalk.Files(r, depth))
                {
                    if (!ExecutableExtensions.Contains(f.Extension.ToLowerInvariant()) || IsCaseOutputPath(s, f.FullName)) continue;
                    var sig = Authenticode.Check(f.FullName);
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["Path"] = f.FullName, ["SizeBytes"] = f.Length, ["CreatedUtc"] = Utc(f.CreationTimeUtc), ["ModifiedUtc"] = Utc(f.LastWriteTimeUtc),
                        ["AccessedUtc"] = Utc(f.LastAccessTimeUtc), ["Extension"] = f.Extension, ["SignatureStatus"] = sig.Status, ["Signer"] = sig.Signer,
                        ["SHA256"] = Hashing.SafeHash(f.FullName, s.Options.SkipHashing),
                    });
                }
            return rows.OrderByDescending(r => (string)r["ModifiedUtc"]!, StringComparer.Ordinal).ToList();
        }

        static object RecentSystemFiles(FotonSession s)
        {
            var cutoff = DateTime.UtcNow.AddDays(-s.Options.EventLogDays);
            var win = HostInfo.WindowsDir;
            var rows = new List<Dictionary<string, object?>>();
            foreach (var dir in new[] { Path.Combine(win, "System32"), Path.Combine(win, "SysWOW64"), win }.Where(Directory.Exists))
                foreach (var f in FileWalk.Files(dir, 0).Where(f => f.LastWriteTimeUtc > cutoff && SystemBinary.IsMatch(f.Extension)))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["Path"] = f.FullName, ["SizeBytes"] = f.Length, ["ModifiedUtc"] = Utc(f.LastWriteTimeUtc), ["CreatedUtc"] = Utc(f.CreationTimeUtc),
                        ["SignatureStatus"] = Authenticode.Check(f.FullName).Status, ["SHA256"] = Hashing.SafeHash(f.FullName, s.Options.SkipHashing),
                    });
            return rows.OrderByDescending(r => (string)r["ModifiedUtc"]!, StringComparer.Ordinal).ToList();
        }

        static object PrefetchListing()
        {
            var pf = Path.Combine(HostInfo.WindowsDir, "Prefetch");
            if (!Directory.Exists(pf)) return new List<object>();
            return new DirectoryInfo(pf).GetFiles("*.pf")
                .Select(f => new Dictionary<string, object?> { ["Name"] = f.Name, ["Length"] = f.Length, ["CreatedUtc"] = Utc(f.CreationTimeUtc), ["LastRunUtc_FileWrite"] = Utc(f.LastWriteTimeUtc) })
                .OrderByDescending(r => (string)r["LastRunUtc_FileWrite"]!, StringComparer.Ordinal).ToList();
        }

        static object MachineHives(FotonSession s)
        {
            var rows = new List<CopyRow>();
            foreach (var h in new[] { new[] { @"HKLM\SYSTEM", "SYSTEM" }, new[] { @"HKLM\SOFTWARE", "SOFTWARE" }, new[] { @"HKU\.DEFAULT", "DEFAULT" } })
                rows.Add(HostCopy.SaveHive(h[0], Path.Combine(Dest(s, @"hives\machine"), h[1]), Path.Combine(Rel(@"hives\machine"), h[1]), s.Options.SkipHashing));
            // SAM and SECURITY hold local password hashes and LSA secrets; exporting them is the credential-theft step EDR
            // watches for. The account and policy facts Foton needs come from live queries. Disclosed, not silently omitted.
            foreach (var name in new[] { "SAM", "SECURITY" })
                rows.Add(new CopyRow
                {
                    SourcePath = @"HKLM\" + name, Status = "NotCollectedByDesign",
                    Note = "Credential hive. Not exported: it holds password hashes / LSA secrets and exporting it matches credential-theft detections. Use a full image or KAPE if the case needs it.",
                });
            return rows;
        }

        static object UserHiveCopies(FotonSession s, List<UserProfile> profiles)
        {
            var rows = new List<CopyRow>();
            long budget = 209715200;
            foreach (var p in profiles.Where(p => p.Exists))
            {
                var seg = HostCopy.SafeSegment(p.UserName);
                var userDest = Path.Combine(Dest(s, @"hives\users"), seg);
                var userRel = Path.Combine(Rel(@"hives\users"), seg);
                // The SID goes on the reg.exe command line, so only a well-formed one can fall back to reg save.
                bool loaded = HostCopy.IsSid(p.Sid) && Reg.Exists(@"Registry::HKEY_USERS\" + p.Sid);
                foreach (var h in new[]
                {
                    new { Src = Path.Combine(p.ProfilePath, "NTUSER.DAT"), Key = @"HKU\" + p.Sid, File = "NTUSER.DAT" },
                    new { Src = Path.Combine(p.ProfilePath, @"AppData\Local\Microsoft\Windows\UsrClass.dat"), Key = @"HKU\" + p.Sid + "_Classes", File = "UsrClass.dat" },
                })
                {
                    if (budget <= 0) break;
                    var fam = HostCopy.Family(h.Src, userDest, userRel, s.Options.SkipHashing, budget);
                    var primary = fam.FirstOrDefault(r => string.Equals(Path.GetFileName(r.SourcePath), h.File, StringComparison.OrdinalIgnoreCase));
                    // A signed-in user's hive is loaded and locked like the machine hives: export the loaded key instead.
                    // The copied sidecars (.LOG*, .regtrans-ms) stay as context.
                    if (primary != null && primary.Status == "CopyError" && loaded && Reg.Exists("Registry::HKEY_USERS\\" + h.Key.Substring(4)))
                    {
                        long onDisk = 0;
                        try { onDisk = new FileInfo(h.Src).Length; } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                        var saved = onDisk > budget
                            ? new CopyRow { SourcePath = h.Key, SizeBytes = onDisk, Status = "CappedSkip", Note = "Loaded hive exceeds the remaining user-hive copy budget; not exported." }
                            : HostCopy.SaveHive(h.Key, Path.Combine(userDest, h.File), Path.Combine(userRel, h.File), s.Options.SkipHashing);
                        var rest = fam.Where(r => r != primary).ToList();
                        if (saved.Status == "Saved")
                            foreach (var r in rest.Where(r => r.Status == "CopyError"))
                            {
                                r.Status = "SupersededBySave";
                                r.Note = "Locked transaction log of a loaded hive; the reg save export already includes its changes.";
                            }
                        fam = rest.Concat(new[] { saved }).ToList();
                    }
                    rows.AddRange(fam);
                    budget -= fam.Where(r => r.Status == "Copied" || r.Status == "Saved").Sum(r => r.SizeBytes);
                }
            }
            if (rows.Count == 0)
                rows.Add(new CopyRow { Status = "NoData", Note = "No profile hives were copied. Standard-user collect skips other users; missing NTUSER is a visibility gap." });
            return rows;
        }

        static object UsnJournal(FotonSession s)
        {
            var destDir = Dest(s, "usn");
            Directory.CreateDirectory(destDir);
            var rel = Rel("usn");
            var drive = Path.GetPathRoot(HostInfo.WindowsDir)?.TrimEnd('\\') is string d && d.Length > 0 ? d : "C:";
            var rows = new List<CopyRow>();
            var meta = Path.Combine(destDir, "usn_queryjournal.txt");
            try
            {
                File.WriteAllText(meta, Exec.System32("fsutil.exe", "usn queryjournal " + drive) + "\r\n", TextFile.Utf8Bom);
                rows.Add(new CopyRow
                {
                    SourcePath = "fsutil usn queryjournal " + drive, DestRelative = Path.Combine(rel, "usn_queryjournal.txt"), SizeBytes = new FileInfo(meta).Length,
                    SHA256 = Hashing.SafeHash(meta, s.Options.SkipHashing), Status = "Copied", Note = "Journal metadata only. Not a full USN parse.",
                });
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                rows.Add(new CopyRow { SourcePath = "fsutil usn queryjournal " + drive, Status = "CopyError", Note = ex.Message });
            }
            if (s.Options.IncludeUsnJournal)
                rows.Add(UsnRecords(drive, destDir, rel, s.Options.SkipHashing));
            else
                rows.Add(new CopyRow
                {
                    SourcePath = @"$Extend\$UsnJrnl:$J", Status = "Skipped",
                    Note = "Full USN $J copy is off by default (size). Re-collect with -IncludeUsnJournal. $MFT is never copied by Foton.",
                });
            return rows;
        }

        const long UsnCap = 1073741824;

        /// <summary>
        /// $J exported through FSCTL_READ_USN_JOURNAL. 1.38.x and v2 before 2.4.0 opened "C:\$Extend\$UsnJrnl:$J" as a
        /// file, which Windows does not allow, so the copy was always Missing. The export holds the records only (no
        /// sparse leading zeros), in on-disk layout, so MFTECmd parses it as $J. Parent paths need $MFT (KAPE/ORC).
        /// </summary>
        static CopyRow UsnRecords(string drive, string destDir, string rel, bool skipHashing)
        {
            var dest = Path.Combine(destDir, "UsnJrnl_J.bin");
            var row = new CopyRow { SourcePath = drive + @"\$Extend\$UsnJrnl:$J", DestRelative = Path.Combine(rel, "UsnJrnl_J.bin"), Status = "CopyError" };
            UsnExport export;
            try
            {
                using (var fs = File.Create(dest)) export = Foton.Win.UsnJournal.Export(drive, fs, UsnCap);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                row.Note = "Could not write the change-journal export: " + ex.Message;
                return row;
            }
            var how = $"Records read with FSCTL_READ_USN_JOURNAL (journal {export.JournalId:X}, USN {export.StartUsn} to {export.NextUsn}), written in on-disk record layout without the sparse region; MFTECmd parses it as $J. Parent paths need $MFT (KAPE/ORC).";
            if (export.Records == 0)
            {
                try { File.Delete(dest); } catch (IOException) { }
                row.Note = (export.Error ?? "The change journal returned no records.") + " Visibility gap, not proof no files changed.";
                row.Status = export.Error == null ? "NoData" : "CopyError";
                row.DestRelative = "";
                return row;
            }
            row.SizeBytes = export.Bytes;
            row.SHA256 = Hashing.SafeHash(dest, skipHashing);
            row.Status = "Copied";
            row.Note = how
                + (export.Capped ? $" Capped at {UsnCap.ToString(System.Globalization.CultureInfo.InvariantCulture)} bytes: the newest records were kept, older ones were not exported." : "")
                + (export.Error != null ? " " + export.Error : "");
            return row;
        }

        /// <summary>ConvertFrom-FotonFileTimeUtc: the FILETIME at the start of the data, or (not set) / (unparsed).</summary>
        internal static string FileTimeText(object? raw)
        {
            if (!(raw is byte[] b)) return raw == null ? "(not set)" : "(unparsed)";
            if (b.Length < 8) return "(not set)";
            var ticks = BitConverter.ToInt64(b, 0);
            if (ticks <= 0) return "(not set)";
            try { return FotonTime.Format(DateTime.FromFileTimeUtc(ticks)); }
            catch (ArgumentOutOfRangeException) { return "(unparsed)"; }
        }

        static object BamDam()
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var kr in new[]
            {
                new[] { "BAM", @"HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" }, new[] { "BAM", @"HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings" },
                new[] { "DAM", @"HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings" }, new[] { "DAM", @"HKLM:\SYSTEM\CurrentControlSet\Services\dam\UserSettings" },
            })
            {
                string kind = kr[0], root = kr[1];
                foreach (var sid in Reg.SubKeyNames(root).Where(n => n.Length > 0))
                    using (var k = Reg.Open(Reg.Join(root, sid)))
                    {
                        if (k == null) continue;
                        foreach (var name in k.GetValueNames().Where(n => n.Length > 0 && n != "(default)"))
                        {
                            object? raw;
                            try { raw = k.GetValue(name); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException) { continue; }
                            rows.Add(new Dictionary<string, object?>
                            {
                                ["Kind"] = kind, ["SID"] = sid, ["Path"] = name, ["LastExecuteUtc"] = FileTimeText(raw), ["DataBytes"] = raw is byte[] b ? b.Length : 0,
                            });
                        }
                    }
            }
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return rows.Where(r => seen.Add($"{r["Kind"]}|{r["SID"]}|{r["Path"]}"))
                .OrderBy(r => (string)r["Kind"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["SID"]!, StringComparer.InvariantCultureIgnoreCase)
                .ThenBy(r => (string)r["Path"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }

        /// <summary>The raw Shimcache blob as one row. Not an ICopyRow column set, but a CopyError still fails the task.</summary>
        public sealed class AppCompatRow : ICopyRow
        {
            public string SourceKey { get; set; } = "";
            public string DestName { get; set; } = "AppCompatCache.bin";
            public long SizeBytes { get; set; }
            public string SHA256 { get; set; } = "";
            public string Status { get; set; } = "Missing";
            public string HeaderHex { get; set; } = "";
            public string Note { get; set; } = "";
            string ICopyRow.SourcePath => SourceKey;
        }

        static object AppCompatCache(FotonSession s)
        {
            const string key = @"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
            var row = new AppCompatRow { SourceKey = key };
            var blob = Reg.Value(key, "AppCompatCache");
            if (blob == null)
            {
                row.Note = "AppCompatCache value not present or not readable. Visibility gap, not proof Shimcache was empty.";
                return new[] { row };
            }
            if (!(blob is byte[] bytes) || bytes.Length == 0)
            {
                row.Status = "CopyError";
                row.Note = "Value was not REG_BINARY. Structured Shimcache parse was not attempted.";
                return new[] { row };
            }
            try
            {
                var dest = Path.Combine(Directory.CreateDirectory(Dest(s, "appcompat")).FullName, "AppCompatCache.bin");
                File.WriteAllBytes(dest, bytes);
                row.SizeBytes = new FileInfo(dest).Length;
                row.SHA256 = Hashing.SafeHash(dest, s.Options.SkipHashing);
                row.Status = "Copied";
                row.HeaderHex = string.Concat(bytes.Take(8).Select(x => x.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)));
                row.Note = "Raw blob at 08_Filesystem/appcompat/AppCompatCache.bin. Entry-level Shimcache parse is not implemented; wrong execution times would be worse than this export.";
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                row.Status = "CopyError";
                row.Note = ex.Message;
            }
            return new[] { row };
        }

        static object AlternateStreams(FotonSession s, List<UserProfile> profiles)
        {
            var roots = new List<string> { PublicDir };
            foreach (var p in profiles.Where(p => p.Exists))
                roots.AddRange(new[] { "Downloads", "Desktop", @"AppData\Local\Temp" }.Select(sub => Path.Combine(p.ProfilePath, sub)));
            var rows = new List<Dictionary<string, object?>>();
            foreach (var r in UniqueSorted(roots).Where(HostInfo.Accessible))
                foreach (var f in FileWalk.Files(r, 3))
                {
                    if (IsCaseOutputPath(s, f.FullName)) continue;
                    foreach (var st in FileStreams.List(f.FullName).Where(x => x.Stream != ":$DATA"))
                        rows.Add(new Dictionary<string, object?>
                        {
                            ["File"] = f.FullName, ["Stream"] = st.Stream, ["LengthBytes"] = st.Length,
                            ["Content"] = st.Length < 4096 && !Hashing.IsCloudPlaceholder(f.Attributes) ? StreamText(f.FullName, st.Stream) : "",
                        });
                }
            return rows;
        }

        /// <summary>Get-Content -Stream joined with " | ": BOM-detected, else the ANSI code page, one entry per line.</summary>
        static string StreamText(string path, string stream)
        {
            try
            {
                var lines = new List<string>();
                using (var fs = FileStreams.Open(path, stream))
                using (var reader = new StreamReader(fs, Encoding.Default, true))
                    for (string? line; (line = reader.ReadLine()) != null;) lines.Add(line);
                return string.Join(" | ", lines);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) { return ""; }
        }

        /// <summary>Local fixed and removable volumes; mapped network drives are never walked (no SMB connection).</summary>
        static IEnumerable<string> LocalDriveRoots()
        {
            DriveInfo[] drives;
            try { drives = DriveInfo.GetDrives(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { yield break; }
            foreach (var d in drives)
            {
                bool ready;
                try { ready = d.DriveType != DriveType.Network && d.DriveType != DriveType.NoRootDirectory && d.IsReady; }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { ready = false; }
                if (ready) yield return d.RootDirectory.FullName;
            }
        }

        static object RecycleBin()
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var root in LocalDriveRoots())
            {
                var rb = Path.Combine(root, "$Recycle.Bin");
                if (!Directory.Exists(rb)) continue;
                foreach (var f in FileWalk.Files(rb, int.MaxValue))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["Drive"] = root, ["SidFolder"] = f.Directory?.Name ?? "", ["FileName"] = f.Name, ["SizeBytes"] = f.Length,
                        ["DeletedUtc"] = Utc(f.CreationTimeUtc), ["FullName"] = f.FullName,
                    });
            }
            return rows.OrderByDescending(r => (string)r["DeletedUtc"]!, StringComparer.Ordinal).ToList();
        }

        static object UsbHistory()
        {
            const string usbstor = @"HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR";
            var rows = new List<Dictionary<string, object?>>();
            foreach (var dev in Reg.SubKeyNames(usbstor))
                foreach (var inst in Reg.SubKeyNames(Reg.Join(usbstor, dev)))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["Source"] = "USBSTOR", ["Device"] = dev, ["SerialOrId"] = inst,
                        ["FriendlyName"] = BaselineDocument.PsString(Reg.Value(Reg.Join(Reg.Join(usbstor, dev), inst), "FriendlyName")), ["Value"] = "",
                    });
            foreach (var v in Reg.ValueList(@"HKLM:\SYSTEM\MountedDevices"))
                rows.Add(new Dictionary<string, object?> { ["Source"] = "MountedDevices", ["Device"] = v.Name, ["SerialOrId"] = "", ["FriendlyName"] = "", ["Value"] = v.Value });
            return rows;
        }

        static readonly string RecentDir = @"AppData\Roaming\Microsoft\Windows\Recent";

        static object RecentInventory(List<UserProfile> profiles)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var p in profiles.Where(p => p.Exists))
                foreach (var dir in new[] { RecentDir, RecentDir + @"\AutomaticDestinations", RecentDir + @"\CustomDestinations" }.Select(d => Path.Combine(p.ProfilePath, d)).Where(HostInfo.Accessible))
                    foreach (var f in FileWalk.Files(dir, 0))
                        rows.Add(new Dictionary<string, object?>
                        {
                            ["User"] = p.UserName, ["Folder"] = Path.GetFileName(dir), ["Name"] = f.Name, ["SizeBytes"] = f.Length,
                            ["ModifiedUtc"] = Utc(f.LastWriteTimeUtc), ["FullName"] = f.FullName,
                        });
            return rows.OrderByDescending(r => (string)r["ModifiedUtc"]!, StringComparer.Ordinal).ToList();
        }

        static IEnumerable<FileInfo> Matching(string dir, string filter)
        {
            if (!HostInfo.Accessible(dir)) return new FileInfo[0];
            try { return new DirectoryInfo(dir).GetFiles(filter); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new FileInfo[0]; }
        }

        static List<CopyItem> RecentCopies(List<UserProfile> profiles)
        {
            var items = new List<CopyItem>();
            foreach (var p in profiles.Where(p => p.Exists))
            {
                var seg = HostCopy.SafeSegment(p.UserName);
                foreach (var spec in new[]
                {
                    new[] { RecentDir, "*.lnk", "Recent" },
                    new[] { RecentDir + @"\AutomaticDestinations", "*.automaticDestinations-ms", "AutomaticDestinations" },
                    new[] { RecentDir + @"\CustomDestinations", "*.customDestinations-ms", "CustomDestinations" },
                })
                    items.AddRange(Matching(Path.Combine(p.ProfilePath, spec[0]), spec[1]).Select(f => new CopyItem(f.FullName, Path.Combine(seg, spec[2], f.Name))));
            }
            return items;
        }

        static List<CopyItem> TaskXml()
        {
            var root = Path.Combine(HostInfo.WindowsDir, @"System32\Tasks");
            if (!Directory.Exists(root)) return new List<CopyItem>();
            return FileWalk.Files(root, int.MaxValue).Select(f => new CopyItem(f.FullName, f.FullName.Substring(root.Length).TrimStart('\\'))).ToList();
        }

        static readonly Regex QuotedScript = new Regex(@"""([^""]+\.(?:ps1|bat|cmd|vbs|js|wsf|hta))""", RegexOptions.IgnoreCase);
        static readonly Regex BareScript = new Regex(@"(?:^|[\s=])((?:[A-Za-z]:\\|\\\\)[^\s""]+\.(?:ps1|bat|cmd|vbs|js|wsf|hta))\b", RegexOptions.IgnoreCase);
        static readonly string[] ScriptExtensions = { ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta" };

        /// <summary>Get-FotonTaskActionScriptPath: script paths named by an action's Execute or Arguments (UNC kept, never resolved).</summary>
        internal static List<string> TaskActionScriptPaths(string execute, string arguments)
        {
            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(execute)) candidates.Add(execute);
            if (!string.IsNullOrWhiteSpace(arguments))
            {
                candidates.AddRange(QuotedScript.Matches(arguments).Cast<Match>().Select(m => m.Groups[1].Value));
                candidates.AddRange(BareScript.Matches(arguments).Cast<Match>().Select(m => m.Groups[1].Value));
            }
            var found = new List<string>();
            foreach (var raw in candidates)
            {
                var p = Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"').Trim('\''));
                if (p.Length == 0) continue;
                string ext;
                try { ext = Path.GetExtension(p); } catch (ArgumentException) { continue; }
                if (!ScriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                bool rooted;
                try { rooted = Path.IsPathRooted(p); } catch (ArgumentException) { continue; }
                if (!rooted) continue;
                if (p.StartsWith(@"\\", StringComparison.Ordinal) || p.StartsWith("//", StringComparison.Ordinal)) { found.Add(p); continue; }
                try { p = Path.GetFullPath(p); }
                catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException || ex is System.Security.SecurityException) { continue; }
                if (!Regex.IsMatch(p, @"^[A-Za-z]:\\")) continue;
                found.Add(p);
            }
            return found.Distinct().ToList();
        }

        static readonly Regex DotDot = new Regex(@"(^|[\\/])\.\.([\\/]|$)");

        static object TaskActionScripts(FotonSession s)
        {
            if (!DeepDiskBudget(s.CaseRoot ?? ""))
                return new[] { new CopyRow { Status = "SkippedLowDisk", Note = "Deep task-script copy skipped: output volume has under 2 GiB free. Visibility gap, not proof scripts were absent." } };
            var items = new List<CopyItem>();
            var pre = new List<CopyRow>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                foreach (var t in Wmi.Query(@"root\Microsoft\Windows\TaskScheduler", "SELECT Actions FROM MSFT_ScheduledTask"))
                    foreach (var a in (Raw(t, "Actions") as ManagementBaseObject[] ?? new ManagementBaseObject[0]).Where(a => a != null))
                        foreach (var p in TaskActionScriptPaths(Wmi.Str(a, "Execute"), Wmi.Str(a, "Arguments")))
                        {
                            if (!seen.Add(p.ToLowerInvariant())) continue;
                            if (!Hashing.IsLocalPath(p))
                            {
                                pre.Add(new CopyRow { SourcePath = p, Status = "SkippedUnc", Note = "UNC task-script path refused. Deep Collect does not follow remote paths (NTLM / network footprint)." });
                                continue;
                            }
                            // C:\Temp\x.ps1 -> C\Temp\x.ps1: the drive letter keeps C: and D: copies apart.
                            var rel = (p.Substring(0, 1) + p.Substring(2)).Replace(':', '_');
                            if (DotDot.IsMatch(rel)) continue;
                            items.Add(new CopyItem(p, rel));
                        }
            }
            catch (ManagementException) { }
            catch (System.Runtime.InteropServices.COMException) { }
            catch (UnauthorizedAccessException) { }
            return pre.Concat(HostCopy.CappedList(items, Dest(s, "task_scripts"), Rel("task_scripts"), s.Options.SkipHashing, 10000, 1073741824)).ToList();
        }

        /// <summary>Test-FotonDeepDiskBudget: at least 2 GiB free on the output volume; a failed probe allows the copy (byte caps still apply).</summary>
        static bool DeepDiskBudget(string caseRoot)
        {
            try
            {
                var root = Path.GetPathRoot(caseRoot);
                if (string.IsNullOrEmpty(root)) return true;
                var di = new DriveInfo(root);
                return !di.IsReady || di.AvailableFreeSpace >= 2147483648L;
            }
            catch (Exception ex) when (ex is ArgumentException || ex is IOException || ex is UnauthorizedAccessException) { return true; }
        }

        static List<CopyItem> BrowserDatabases(List<UserProfile> profiles)
        {
            var items = new List<CopyItem>();
            foreach (var p in profiles.Where(p => p.Exists))
            {
                var seg = HostCopy.SafeSegment(p.UserName);
                var local = Path.Combine(p.ProfilePath, @"AppData\Local");
                foreach (var bd in new[] { new[] { "Chrome", @"Google\Chrome\User Data\Default" }, new[] { "Edge", @"Microsoft\Edge\User Data\Default" } })
                    foreach (var leaf in new[] { "History", "Cookies", "Login Data" })
                    {
                        var c = Path.Combine(local, bd[1], leaf);
                        if (HostInfo.Accessible(c) && File.Exists(c)) items.Add(new CopyItem(c, Path.Combine(seg, bd[0], leaf)));
                    }
                var ff = Path.Combine(p.ProfilePath, @"AppData\Roaming\Mozilla\Firefox\Profiles");
                if (!HostInfo.Accessible(ff)) continue;
                DirectoryInfo[] ffProfiles;
                try { ffProfiles = new DirectoryInfo(ff).GetDirectories(); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                foreach (var d in ffProfiles)
                    foreach (var leaf in new[] { "places.sqlite", "cookies.sqlite" })
                    {
                        var c = Path.Combine(d.FullName, leaf);
                        if (File.Exists(c)) items.Add(new CopyItem(c, Path.Combine(seg, "Firefox_" + d.Name, leaf)));
                    }
            }
            return items;
        }

        static List<CopyItem> HostLogs()
        {
            var win = HostInfo.WindowsDir;
            var items = new List<CopyItem>();
            var setup = Path.Combine(win, @"inf\setupapi.dev.log");
            if (File.Exists(setup)) items.Add(new CopyItem(setup, "setupapi.dev.log"));
            var cbs = Path.Combine(win, @"Logs\CBS\CBS.log");
            if (File.Exists(cbs)) items.Add(new CopyItem(cbs, "CBS.log"));
            // The transcription directory is policy data and is often a central share: a non-local path is recorded, never listed.
            var tx = BaselineDocument.PsString(Reg.Value(@"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "OutputDirectory"));
            if (tx.Length > 0 && !Hashing.IsLocalPath(tx)) items.Add(new CopyItem(tx, "powershell_transcript"));
            else if (tx.Length > 0 && Directory.Exists(tx))
                items.AddRange(FileWalk.Files(tx, int.MaxValue).Where(f => f.Name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)).Take(40)
                    .Select(f => new CopyItem(f.FullName, Path.Combine("powershell_transcript", f.Name))));
            // Every top-level CodeIntegrity file (policies, driver.stl trust lists), as 1.38.x copied them, plus the
            // multiple-policy-format files under CiPolicies\Active.
            var ci = Path.Combine(win, @"System32\CodeIntegrity");
            if (Directory.Exists(ci))
                items.AddRange(FileWalk.Files(ci, 0).Select(f => new CopyItem(f.FullName, Path.Combine("codeintegrity", f.Name))));
            var active = Path.Combine(ci, @"CiPolicies\Active");
            if (Directory.Exists(active))
                items.AddRange(FileWalk.Files(active, 0).Where(f => f.Extension.Equals(".cip", StringComparison.OrdinalIgnoreCase))
                    .Select(f => new CopyItem(f.FullName, Path.Combine(@"codeintegrity\Active", f.Name))));
            return items;
        }

        static object HiddenRootItems()
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var root in LocalDriveRoots())
            {
                FileSystemInfo[] entries;
                try
                {
                    var di = new DirectoryInfo(root);
                    entries = di.GetDirectories().Cast<FileSystemInfo>().Concat(di.GetFiles()).ToArray();
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                foreach (var i in entries.Where(i => (i.Attributes & FileAttributes.Hidden) != 0))
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["Location"] = root, ["Name"] = i.Name, ["IsDirectory"] = i is DirectoryInfo, ["Attributes"] = i.Attributes.ToString(), ["ModifiedUtc"] = Utc(i.LastWriteTimeUtc),
                    });
            }
            return rows;
        }
    }
}
