using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using Foton.Analyze;
using Foton.Collect;
using Foton.Core;
using Foton.Win;
using Xunit;

namespace Foton.Tests
{
    /// <summary>The collect orchestrator on this host (no categories are needed to exercise the package lifecycle).</summary>
    public class CollectTests
    {
        static StatusLog Quiet() => new StatusLog(new StringWriter());

        [Fact]
        public void A_run_writes_a_hashed_case_package_whose_findings_a_workstation_reproduces()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, Examiner = "examiner", CaseNumber = "CASE-0001" }, Quiet());
                var r = CollectRun.Run(s, only: new string[0]);

                var col = Path.Combine(r.CaseRoot, "00_Collection");
                foreach (var f in new[] { "chain_of_custody.txt", "collection_coverage.json", "collection_manifest.csv", "collection.log", "findings.csv", "hashes.csv", "hashes.txt" })
                    Assert.True(File.Exists(Path.Combine(col, f)), f);
                Assert.True(File.Exists(r.ReportPath));
                Assert.Contains("CASE-0001", File.ReadAllText(Path.Combine(col, "chain_of_custody.txt")));
                Assert.Equal(CaseCategories.All.Select(kv => kv.Key).Where(k => k != "Collection").OrderBy(k => k), Categories.InOrder.Select(c => c.Key).OrderBy(k => k));
                Assert.Contains(Csv.Read(Path.Combine(col, "hashes.csv")), h => h["RelativePath"] == "Foton_Report.html");
                Assert.Equal(r.ZipPath, r.CaseRoot + ".zip");
                Assert.True(File.Exists(r.CaseRoot + "_PACKAGE_HASH.txt"));
                Assert.Equal(Hashing.Sha256Hex(r.ZipPath!), r.ZipSha256);

                // Endpoint analysis reads the written case, so the workstation (given the same empty pattern list) agrees.
                Assert.Contains(s.Findings, f => f.Title == "Suspicious-command pattern matching did not run");
                var again = Analyzer.RunPackage(r.CaseRoot, Quiet(), new string[0]);
                Assert.Equal(File.ReadAllBytes(Path.Combine(col, "findings.csv")), File.ReadAllBytes(again.FindingsPath!));
            }
        }

        [Fact]
        public void Every_task_a_Deep_collection_records_is_in_the_profile_task_list()
        {
            using (var t = new TempDir())
            {
                // Only Users runs; every other task is recorded NotSelected, so the manifest names every task cheaply.
                var o = new SessionOptions { OutputPath = t.Path, NoZip = true, Deep = true, IncludeFileTimeline = true, IncludeUsnJournal = true, Profile = CollectionProfile.FromCategories("Users") };
                var s = CollectRun.NewSession(o, Quiet());
                CollectRun.Run(s);
                var listed = CollectTasks.ByCategory.SelectMany(kv => kv.Value.Where(t => t != CollectionProfile.EvtxExport).Select(t => kv.Key + "/" + t));
                Assert.Equal(listed.OrderBy(n => n, StringComparer.Ordinal), s.Manifest.Select(m => m.Category + "/" + m.Task).OrderBy(n => n, StringComparer.Ordinal));
                Assert.All(s.Manifest.Where(m => m.Category != "Users"), m => Assert.Equal(TaskStatus.NotSelected, m.Status));
            }
            Assert.Equal(CollectionProfile.AllCategories.OrderBy(k => k), CollectTasks.ByCategory.Keys.OrderBy(k => k));
            Assert.Equal("EventLogs", CollectTasks.CategoryOf(CollectionProfile.EvtxExport));
            Assert.Empty(CollectTasks.Unknown(new[] { "bits_jobs", "EVTX_EXPORT", "Named_Pipes" }));
            Assert.Equal(new[] { "bits_jobz" }, CollectTasks.Unknown(new[] { "bits_jobz", "bits_jobs" }));
        }

        [Fact]
        public void System_and_Users_run_every_task_on_this_host_without_task_errors()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                CollectRun.Run(s, only: new[] { "System", "Users" });
                var tasks = s.Manifest.Select(m => m.Task).ToList();
                foreach (var name in new[] { "os_info", "entra_workplace_join", "time_sync", "hotfixes", "boot_and_firmware", "disks_and_volumes", "environment_variables",
                    "system_restore_and_shadowcopies", "local_users", "local_group_membership", "user_profiles", "logged_on_sessions", "password_and_lockout_policy",
                    "user_rights_and_secpol", "rdp_configuration", "stored_credentials_and_trusts" })
                    Assert.Contains(name, tasks);
                Assert.DoesNotContain(s.Manifest, m => m.Status == TaskStatus.Error || m.Status == TaskStatus.WriteError);
                Assert.Equal(s.Hostname, ((System.Collections.Generic.Dictionary<string, object?>)s.Data["os_info"]!)["Hostname"]);
                Assert.Contains(s.Manifest, m => m.Task == "local_users" && m.Records > 0);
            }
        }

        [Fact]
        public void Group_members_get_Get_LocalGroupMember_class_and_source()
        {
            var machine = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3");
            var msa = new System.Collections.Generic.HashSet<string> { "S-1-5-21-1-2-3-1002" };
            Assert.Equal("Local", UserCollection.PrincipalSource("S-1-5-21-1-2-3-1001", machine, msa));
            Assert.Equal("MicrosoftAccount", UserCollection.PrincipalSource("S-1-5-21-1-2-3-1002", machine, msa));
            Assert.Equal("ActiveDirectory", UserCollection.PrincipalSource("S-1-5-21-9-9-9-1105", machine, msa));
            Assert.Equal("AzureAD", UserCollection.PrincipalSource("S-1-12-1-111-222-333-444", machine, msa));
            Assert.Equal("Unknown", UserCollection.PrincipalSource("S-1-5-4", machine, msa));
            Assert.Equal("Unknown", UserCollection.PrincipalSource("not a sid", machine, msa));
            Assert.Equal("Unknown", UserCollection.PrincipalSource("S-1-5-21-1-2-3-1001", null, msa));
            Assert.True(CloudJoin.IsJoinKeyName("0123456789ABCDEF0123456789abcdef01234567"));
            Assert.True(CloudJoin.IsJoinKeyName("{8F3A1B2C-0000-4D5E-9F10-123456789ABC}"));
            Assert.False(CloudJoin.IsJoinKeyName("Status"));
            var table = CollectText.Table(new[] { "A", "B" }, new[] { new[] { "1", "2", "extra" }, new[] { "only" } }).ToList();
            Assert.Equal(new[] { "", "A    B", "---- -", "1    2", "only", "" }, table);
            Assert.Null(CollectText.DmtfTime("2026-not-a-dmtf"));
            Assert.Equal("", CollectText.Dmtf("99999999999999.999999+999"));
            Assert.Equal(new[] { "User", "Group", "Group", "Group", "" }, new[] { 1, 2, 4, 5, 6 }.Select(UserCollection.ObjectClass));
        }

        [Fact]
        public void Software_runs_every_task_on_this_host_without_task_errors()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true, SkipHashing = true }, Quiet());
                CollectRun.Run(s, only: new[] { "Software" });
                foreach (var name in new[] { "installed_software", "drivers", "browser_extensions", "remote_access_tool_indicators", "appx_packages" })
                    Assert.Contains(s.Manifest, m => m.Task == name);
                Assert.DoesNotContain(s.Manifest, m => m.Status == TaskStatus.Error || m.Status == TaskStatus.WriteError);
                Assert.Contains(s.Manifest, m => m.Task == "drivers" && m.Records > 0);
                Assert.Contains(s.Manifest, m => m.Task == "appx_packages" && m.Records > 0);
            }
        }

        [Fact]
        public void A_hive_mounted_by_LoadUserHives_is_exported_from_its_mount_key()
        {
            const string sid = "S-1-5-21-1-2-3-1002";
            Assert.Equal(@"HKU\" + sid, FilesystemCollection.NtUserKey(sid, k => k == @"HKU\" + sid));
            Assert.Equal(@"HKU\Foton_" + sid, FilesystemCollection.NtUserKey(sid, k => k == @"HKU\Foton_" + sid));
            // Signed in wins over a stale mount; neither loaded keeps the plain key (the file copy works then).
            Assert.Equal(@"HKU\" + sid, FilesystemCollection.NtUserKey(sid, k => true));
            Assert.Equal(@"HKU\" + sid, FilesystemCollection.NtUserKey(sid, k => false));
        }

        [Fact]
        public void Parallel_signature_checks_match_sequential_ones_in_input_order()
        {
            var files = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.System))
                .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase).Take(150).ToList();
            Func<string, string> check = f =>
            {
                var sig = Foton.Win.Authenticode.Check(f);
                return string.Join("|", f, sig.Status, sig.Signer, sig.IsOSBinary, Hashing.SafeHash(f, false));
            };
            var sequential = files.Select(check).ToArray();
            Assert.Equal(sequential, FilesystemCollection.InOrder(files, check));
            Assert.Empty(FilesystemCollection.InOrder(new List<string>(), check));
        }

        [Fact]
        public void Authenticode_reads_catalog_and_embedded_signatures_like_Get_AuthenticodeSignature()
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var notepad = Foton.Win.Authenticode.Check(Path.Combine(sys, "notepad.exe"));
            Assert.Equal("Valid", notepad.Status);
            Assert.Contains("Microsoft", notepad.Signer);
            Assert.True(notepad.IsOSBinary);
            using (var t = new TempDir())
            {
                // Reference values from Get-AuthenticodeSignature: a script with no signature, and a type with no signature format.
                File.WriteAllText(t.File("plain.ps1"), "Write-Output 1");
                File.WriteAllText(t.File("plain.txt"), "not signed");
                Assert.Equal("NotSigned", Foton.Win.Authenticode.Check(t.File("plain.ps1")).Status);
                Assert.Equal("UnknownError", Foton.Win.Authenticode.Check(t.File("plain.txt")).Status);
                Assert.Equal("FileNotFound", Foton.Win.Authenticode.Check(t.File("missing.sys")).Status);
                // The no-format shortcut is decided by content, not extension: a signed binary renamed .lnk still verifies.
                File.Copy(Path.Combine(sys, "notepad.exe"), t.File("renamed.lnk"));
                Assert.Equal("Valid", Foton.Win.Authenticode.Check(t.File("renamed.lnk")).Status);
            }
            Assert.Equal("Unknown", Foton.Win.Authenticode.Check("").Status);
            Assert.Equal(new[] { "NotSigned", "UnknownError", "NotSigned", "HashMismatch", "HashMismatch", "Valid", "Valid", "NotTrusted", "UnknownError" },
                Enumerable.Range(0, 9).Select(i => Foton.Win.Authenticode.StatusOf((uint)i)));
            Assert.Equal(@"C:\Program Files\x.sys", Foton.Win.Authenticode.Openable(@"\??\C:\Program Files\x.sys"));
            Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\drivers\y.sys"),
                Foton.Win.Authenticode.Openable(@"\SystemRoot\System32\drivers\y.sys"));
            Assert.Equal(@"C:\Windows\z.sys", Foton.Win.Authenticode.Openable(@"C:\Windows\z.sys"));
            Assert.Equal(@"C:\Program Files\q.sys", Foton.Win.Authenticode.Openable(@"""\??\C:\Program Files\q.sys"""));
            Assert.Equal(@"\\server\share\d.sys", Foton.Win.Authenticode.Openable(@"\??\UNC\server\share\d.sys"));
            // Host-supplied paths that are not plainly local are never opened: no SMB connection, no credential offer.
            foreach (var other in new[]
            {
                @"\\server\share\d.sys", @"\\?\UNC\server\share\d.sys", @"\??\UNC\server\share\d.sys", @"""\\10.0.0.5\c$\x.sys""", "//server/share/x.sys",
                @"\??\GLOBALROOT\Device\Mup\server\share\x.sys", @"\\?\GLOBALROOT\Device\Mup\server\share\x.sys", @"\\.\PhysicalDrive0",
            })
            {
                Assert.False(Hashing.IsLocalPath(other), other);
                Assert.Equal("SkippedNonLocalPath", Hashing.SafeHash(other, false));
                Assert.Equal("NonLocalPathNotChecked", Foton.Win.Authenticode.Check(other).Status);
            }
            foreach (var local in new[] { @"C:\Windows\x.sys", @"\\?\C:\Windows\x.sys", @"\\.\C:\x.sys", @"\??\C:\x.sys", @"\\?\Volume{0a1b2c3d-0000-0000-0000-000000000000}\x.sys", @"System32\drivers\x.sys", @"\Windows\x.sys" })
                Assert.True(Hashing.IsLocalPath(local), local);
        }

        [Fact]
        public void Remote_access_matching_reads_dictionary_and_object_rows()
        {
            Assert.Equal("AnyDesk", SoftwareCollection.Field(new System.Collections.Generic.Dictionary<string, object?> { ["DisplayName"] = "AnyDesk" }, "DisplayName"));
            Assert.Equal("", SoftwareCollection.Field(new System.Collections.Generic.Dictionary<string, object?>(), "DisplayName"));
            Assert.Equal("svc", SoftwareCollection.Field(new { Name = "svc" }, "Name"));
            Assert.Equal("x", SoftwareCollection.Field(new System.Collections.Generic.Dictionary<string, string> { ["Path"] = "x" }, "Path"));
        }

        [Fact]
        public void Security_runs_every_task_and_reads_the_hardening_table()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                CollectRun.Run(s, only: new[] { "Security" });
                foreach (var name in new[] { "defender_status", "defender_preferences_and_exclusions", "defender_detections", "installed_av_products", "hardening_registry_settings",
                    "audit_policy", "smb_and_winrm_config", "powershell_environment", "non_microsoft_root_certificates", "applocker_wdac_and_policy" })
                    Assert.Contains(s.Manifest, m => m.Task == name);
                // Defender and Security Center are absent on some SKUs (a recorded task error); everything else must run.
                var optional = new[] { "defender_status", "defender_preferences_and_exclusions", "defender_detections", "installed_av_products" };
                Assert.DoesNotContain(s.Manifest, m => m.Status == TaskStatus.WriteError || (m.Status == TaskStatus.Error && !optional.Contains(m.Task)));
                Assert.Equal(HardeningChecks.All.Count, s.Manifest.Single(m => m.Task == "hardening_registry_settings").Records);
                Assert.Contains(s.Manifest, m => m.Task == "non_microsoft_root_certificates" && m.Records > 0);
            }
        }

        [Fact]
        public void Persistence_runs_every_task_and_reads_tasks_and_services()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                CollectRun.Run(s, only: new[] { "Persistence" });
                foreach (var name in new[] { "autorun_registry_keys", "startup_folder_items", "startup_approved", "scheduled_tasks", "scheduled_task_files", "services",
                    "wmi_event_subscriptions", "winlogon_lsa_and_dll_hijacks", "accessibility_binary_integrity", "cmd_autorun", "session_manager_boot", "known_dlls",
                    "winsock_lsp", "active_setup", "silent_process_exit", "netsh_helpers", "time_providers", "screensaver", "com_hijack_candidates", "bits_jobs",
                    "office_addins_and_templates" })
                    Assert.Contains(s.Manifest, m => m.Task == name);
                Assert.DoesNotContain(s.Manifest, m => m.Status == TaskStatus.WriteError || m.Status == TaskStatus.Error);
                foreach (var name in new[] { "scheduled_tasks", "services", "known_dlls", "winsock_lsp" })
                    Assert.Contains(s.Manifest, m => m.Task == name && m.Records > 0);
                Assert.Equal(7, s.Manifest.Single(m => m.Task == "accessibility_binary_integrity").Records);
            }
        }

        [Fact]
        public void Event_queries_and_messages_follow_1_38()
        {
            Assert.Equal("*[System[(EventID=104 or EventID=6005) and TimeCreated[@SystemTime>='2026-01-02T03:04:05.000Z']]]",
                EventLogCollection.XPath(new[] { 104, 6005 }, new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc)));
            Assert.Equal("a b c", EventLogCollection.Collapse("a\r\n\tb   c"));
            var capped = EventLogCollection.Collapse(new string('x', 2500));
            Assert.Equal(2000 + "...[truncated]".Length, capped.Length);
            Assert.EndsWith("...[truncated]", capped);
        }

        [Fact]
        public void EventLogs_runs_every_query_and_exports_evtx()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true, EventLogDays = 1, MaxEventsPerLog = 50 }, Quiet());
                CollectRun.Run(s, only: new[] { "EventLogs" });
                var events = s.Manifest.Where(m => m.Category == "EventLogs").ToList();
                Assert.Equal(21, events.Count);
                Assert.All(events.Where(m => m.Task.StartsWith("security_", StringComparison.Ordinal)),
                    m => Assert.True(s.IsElevated ? m.Status != TaskStatus.SkippedNotElevated : m.Status == TaskStatus.SkippedNotElevated, m.Task));
                Assert.All(events, m => Assert.True(m.Records <= 50, m.Task));
                Assert.DoesNotContain(events, m => m.Status == TaskStatus.WriteError);
                Assert.Contains(events, m => m.Task == "system_log_and_boot" && m.Status != TaskStatus.Error);
                Assert.Equal(9, events.Single(m => m.Task == "event_log_configuration").Records);
                Assert.True(File.Exists(Path.Combine(s.Dirs["EventLogs"], "evtx", "System.evtx")));
                Assert.Equal(s.IsElevated, File.Exists(Path.Combine(s.Dirs["EventLogs"], "evtx", "Security.evtx")));
            }
        }

        [Fact]
        public void Cloud_placeholders_are_recognised_only_by_bits_user_mode_cannot_set()
        {
            const FileAttributes recallOnDataAccess = (FileAttributes)0x400000, recallOnOpen = (FileAttributes)0x40000;
            Assert.True(Hashing.IsCloudPlaceholder(FileAttributes.Archive | recallOnDataAccess));
            Assert.True(Hashing.IsCloudPlaceholder(recallOnOpen));
            Assert.True(Hashing.IsCloudPlaceholder(FileAttributes.Offline | FileAttributes.ReparsePoint | recallOnDataAccess));
            Assert.False(Hashing.IsCloudPlaceholder(FileAttributes.Offline | FileAttributes.ReparsePoint));
            Assert.False(Hashing.IsCloudPlaceholder(FileAttributes.Offline));
            Assert.False(Hashing.IsCloudPlaceholder(FileAttributes.ReparsePoint));

            // A file that marks itself Offline (any user can) is still hashed, signature-checked, and copied.
            using (var t = new TempDir())
            {
                var f = Path.Combine(t.Path, "evasive.exe");
                File.WriteAllText(f, "MZ");
                File.SetAttributes(f, FileAttributes.Offline);
                try
                {
                    Assert.False(Hashing.IsCloudPlaceholder(f));
                    Assert.Equal(64, Hashing.SafeHash(f, false).Length);
                    Assert.NotEqual("CloudPlaceholderNotChecked", Authenticode.Check(f).Status);
                    Assert.Equal("Copied", HostCopy.CopyFile(f, Path.Combine(t.Path, @"out\evasive.exe"), false).Status);
                }
                finally { File.SetAttributes(f, FileAttributes.Normal); }
            }
            Assert.Equal(TaskStatus.Success, CopyTaskStatus.Evaluate(new[] { new CopyRow { SourcePath = "x", Status = "SkippedCloudPlaceholder" } }).Status);
        }

        [Fact]
        public void Capped_list_copies_newest_first_and_refuses_escapes_and_remote_sources()
        {
            using (var t = new TempDir())
            {
                var src = Directory.CreateDirectory(Path.Combine(t.Path, "src")).FullName;
                var older = Path.Combine(src, "older.lnk");
                var newer = Path.Combine(src, "newer.lnk");
                File.WriteAllText(older, "aaaa");
                File.WriteAllText(newer, "bbbbbb");
                File.SetLastWriteTimeUtc(older, new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
                var dest = Path.Combine(t.Path, "dest");
                var rows = HostCopy.CappedList(new[]
                {
                    new CopyItem(older, @"u\older.lnk"), new CopyItem(newer, @"u\newer.lnk"), new CopyItem(@"\\server\share\x.lnk", "x.lnk"),
                    new CopyItem(newer, @"..\escape.lnk"), new CopyItem(Path.Combine(src, "gone.lnk"), "gone.lnk"),
                }, dest, @"08_Filesystem\lnk", skipHashing: false, maxFiles: 1);
                Assert.Equal(new[] { "CappedSkip", "Copied", "CopyError", "Missing", "SkippedUnc" }, rows.Select(r => r.Status).OrderBy(x => x, StringComparer.Ordinal).ToArray());
                var copied = rows.Single(r => r.Status == "Copied");
                Assert.Equal(newer, copied.SourcePath);
                Assert.Equal(@"08_Filesystem\lnk\u\newer.lnk", copied.DestRelative);
                Assert.Equal(64, copied.SHA256.Length);
                Assert.True(File.Exists(Path.Combine(dest, @"u\newer.lnk")));
                Assert.False(File.Exists(Path.Combine(t.Path, "escape.lnk")));
                Assert.Equal(TaskStatus.Partial, CopyTaskStatus.Evaluate(rows).Status);
                Assert.Equal("NoData", HostCopy.CappedList(new CopyItem[0], dest, "", false).Single().Status);
            }
        }

        [Fact]
        public void Usn_records_are_written_whole_and_a_malformed_record_ends_the_batch()
        {
            // A record header: RecordLength, MajorVersion, USN, and FileNameLength / FileNameOffset at the end of the
            // fixed header (60 bytes in V2, 76 in V3), with the name placed right after it.
            void Rec(byte[] b, int at, int length, ushort major, long usn, ushort nameLength)
            {
                int header = major == 3 ? 76 : 60;
                BitConverter.GetBytes(length).CopyTo(b, at);
                BitConverter.GetBytes(major).CopyTo(b, at + 4);
                BitConverter.GetBytes(usn).CopyTo(b, at + (major == 3 ? 40 : 24));
                BitConverter.GetBytes(nameLength).CopyTo(b, at + header - 4);
                BitConverter.GetBytes((ushort)header).CopyTo(b, at + header - 2);
            }

            // FSCTL_READ_USN_JOURNAL output: an 8-byte next USN, then records whose first DWORD is RecordLength.
            var buffer = new byte[8 + 64 + 72 + 8];
            BitConverter.GetBytes(4096L).CopyTo(buffer, 0);
            Rec(buffer, 8, 64, 2, 10, 4);
            Rec(buffer, 72, 72, 2, 20, 12);
            BitConverter.GetBytes(3).CopyTo(buffer, 144);   // malformed: shorter than a record header
            using (var all = new MemoryStream())
            {
                Assert.Equal(136, UsnJournal.WriteRecords(buffer, buffer.Length, all, long.MaxValue, out var records, out var full, out _));
                Assert.Equal(2, records);
                Assert.False(full);
                Assert.Equal(136, all.Length);
            }
            using (var capped = new MemoryStream())
            {
                Assert.Equal(64, UsnJournal.WriteRecords(buffer, buffer.Length, capped, 100, out var records, out var full, out _));
                Assert.Equal(1, records);
                Assert.True(full);   // the second record would pass the budget: stop at a whole record
            }

            // A corrupt length near int.MaxValue must not overflow the bounds check and reach Stream.Write.
            var corrupt = new byte[8 + 64];
            BitConverter.GetBytes(0x7FFFFFF8).CopyTo(corrupt, 8);
            using (var none = new MemoryStream())
            {
                Assert.Equal(0, UsnJournal.WriteRecords(corrupt, corrupt.Length, none, long.MaxValue, out var records, out var full, out _));
                Assert.Equal(0, records);
                Assert.False(full);
            }

            // A capped export ends at the pass-1 snapshot: records at or past the stop USN (V2 at offset 24, V3 at 40) are not written.
            var snap = new byte[8 + 64 + 80];
            Rec(snap, 8, 64, 2, 1000, 4);
            Rec(snap, 72, 80, 3, 2000, 4);
            Assert.Equal(1000, UsnJournal.RecordUsn(snap, 8));
            Assert.Equal(2000, UsnJournal.RecordUsn(snap, 72));
            using (var upTo = new MemoryStream())
            {
                Assert.Equal(64, UsnJournal.WriteRecords(snap, snap.Length, upTo, long.MaxValue, out var records, out var full, out var stopped, 1500));
                Assert.Equal(1, records);
                Assert.True(stopped);
                Assert.False(full);
            }

            // Per-version header sizes and a file name inside the record: a V3 record shorter than its 76-byte header,
            // a name running past the record, a name inside the header, and an unknown major version are all refused.
            var shapes = new byte[8 + 96];
            Rec(shapes, 8, 64, 3, 1, 0);
            Assert.False(UsnJournal.WellFormed(shapes, 8, 64, shapes.Length));
            Rec(shapes, 8, 72, 2, 1, 16);
            Assert.False(UsnJournal.WellFormed(shapes, 8, 72, shapes.Length));
            Rec(shapes, 8, 72, 2, 1, 8);
            Assert.True(UsnJournal.WellFormed(shapes, 8, 72, shapes.Length));
            BitConverter.GetBytes((ushort)40).CopyTo(shapes, 8 + 58);
            Assert.False(UsnJournal.WellFormed(shapes, 8, 72, shapes.Length));
            Rec(shapes, 8, 72, 4, 1, 8);
            Assert.False(UsnJournal.WellFormed(shapes, 8, 72, shapes.Length));

            // Capped start: the earliest batch from which the newest batches fit, counting record bytes (not USN span,
            // which can be larger), and the end when not even the newest batch fits.
            var batches = new List<KeyValuePair<long, long>>
            {
                new KeyValuePair<long, long>(100, 40), new KeyValuePair<long, long>(400, 40), new KeyValuePair<long, long>(900, 40),
            };
            Assert.Equal(400, UsnJournal.StartForCap(batches, 80, 1000));
            Assert.Equal(400, UsnJournal.StartForCap(batches, 119, 1000));
            Assert.Equal(100, UsnJournal.StartForCap(batches, 120, 1000));
            Assert.Equal(1000, UsnJournal.StartForCap(batches, 39, 1000));

            // A cap below one read batch could skip every batch; it is refused before the volume is opened.
            using (var tiny = new MemoryStream())
            {
                var r = UsnJournal.Export("C:", tiny, UsnJournal.BatchBytes - 1);
                Assert.Contains("at least", r.Error);
                Assert.Equal(0, tiny.Length);
            }
        }

        [Fact]
        public void SRUM_is_copied_from_System32_sru_with_its_logs()
        {
            Assert.Equal(@"C:\Windows\System32\sru", FilesystemCollection.SrumDirectory(@"C:\Windows"));
            using (var t = new TempDir())
            {
                // The ESE logs and checkpoint do not share SRUDB.dat's name; the folder copy takes them all.
                var src = Directory.CreateDirectory(Path.Combine(t.Path, "sru")).FullName;
                foreach (var f in new[] { "SRUDB.dat", "SRU.chk", "SRU.log", "SRU0001A.log", "SRUDB.jfm" }) File.WriteAllText(Path.Combine(src, f), f);
                var rows = HostCopy.CappedDirectory(src, "*", Path.Combine(t.Path, "d"), @"08_Filesystem\srum", false, 64, 1073741824, "SRUM missing");
                Assert.Equal(5, rows.Count(r => r.Status == "Copied"));
                Assert.Contains(rows, r => r.DestRelative == @"08_Filesystem\srum\SRU.chk");
                Assert.Equal("SRUM missing", HostCopy.CappedDirectory(Path.Combine(t.Path, "absent"), "*", t.Path, "", false, missingNote: "SRUM missing").Single().Note);
            }
        }

        [Fact]
        public void Default_output_is_a_Foton_folder_on_the_Windows_drive()
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory)!;
            Assert.Equal(Path.Combine(root, "Foton", "Cases"), OutputFolder.Default("Cases"));
            Assert.Equal(Path.Combine(root, "Foton", "Baselines"), OutputFolder.Default("Baselines"));
        }

        [Fact]
        public void Default_output_folders_are_created_private_and_existing_ones_are_checked()
        {
            using (var t = new TempDir())
            {
                var leaf = Path.Combine(t.Path, "Foton", "Cases");
                Assert.Null(OutputFolder.EnsurePrivate(leaf, t.Path));
                Assert.Null(OutputFolder.EnsurePrivate(leaf, t.Path));   // already private: still accepted
                var mine = new[]
                {
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    WindowsIdentity.GetCurrent().User!,
                };
                foreach (var dir in new[] { Path.Combine(t.Path, "Foton"), leaf })
                {
                    var acl = Directory.GetAccessControl(dir);
                    Assert.True(acl.AreAccessRulesProtected, dir + " still inherits from its parent");
                    foreach (FileSystemAccessRule r in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                        Assert.Contains((SecurityIdentifier)r.IdentityReference, mine);
                }

                // A folder someone else prepared (here: Users may read it) is refused and left as it was.
                var open = Directory.CreateDirectory(Path.Combine(t.Path, "open")).FullName;
                var sec = Directory.GetAccessControl(open);
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(open, sec);
                var problem = OutputFolder.EnsurePrivate(Path.Combine(open, "Cases"), t.Path);
                Assert.NotNull(problem);
                Assert.Contains("gives access to", problem);
                Assert.False(Directory.GetAccessControl(open).AreAccessRulesProtected);
                Assert.False(Directory.Exists(Path.Combine(open, "Cases")));   // nothing created inside a refused folder

                // A junction in the chain is refused even when its target is private.
                var link = Path.Combine(t.Path, "link");
                Exec.System32("cmd.exe", $"/c mklink /J \"{link}\" \"{Path.Combine(t.Path, "Foton")}\"", out var code, 30000);
                Assert.Equal(0, code);
                Assert.Contains("junction", OutputFolder.Problem(Path.Combine(link, "Cases"), t.Path));
                Directory.Delete(link);
            }
        }

        [Fact]
        public void A_long_shortcut_name_is_shortened_to_fit_and_keeps_its_extension()
        {
            using (var t = new TempDir())
            {
                // Game Bar and phone-notification shortcuts in Recent carry 150-200 character names.
                var src = Directory.CreateDirectory(Path.Combine(t.Path, "s")).FullName;
                var longName = "ms-gamebar--hotkey-gamepadCommand=GPCMD_NEXUS_LONGPRESS&source=GbEm&deviceId=" + new string('0', 64) + ".lnk";
                var longSrc = Path.Combine(src, longName);
                File.WriteAllText(longSrc, "lnk");
                var shortSrc = Path.Combine(src, "short.lnk");
                File.WriteAllText(shortSrc, "lnk2");
                var rows = HostCopy.CappedList(new[] { new CopyItem(longSrc, @"user1\Recent\" + longName), new CopyItem(shortSrc, @"user1\Recent\short.lnk") },
                    Path.Combine(t.Path, "d"), @"08_Filesystem\lnk_jumplist", skipHashing: false);

                var fitted = rows.Single(r => r.SourcePath == longSrc);
                Assert.Equal("Copied", fitted.Status);
                Assert.True(fitted.DestRelative.Length <= 160, fitted.DestRelative.Length.ToString());
                Assert.StartsWith(@"08_Filesystem\lnk_jumplist\user1\Recent\ms-gamebar--hotkey", fitted.DestRelative);
                Assert.Matches(@"~[0-9A-F]{8}\.lnk$", fitted.DestRelative);
                Assert.Contains("SourcePath holds the original name", fitted.Note);
                Assert.True(File.Exists(Path.Combine(t.Path, "d", fitted.DestRelative.Substring(@"08_Filesystem\lnk_jumplist\".Length))));

                var plain = rows.Single(r => r.SourcePath == shortSrc);
                Assert.Equal(@"08_Filesystem\lnk_jumplist\user1\Recent\short.lnk", plain.DestRelative);
                Assert.DoesNotContain("shortened", plain.Note);
            }
        }

        [Fact]
        public void Family_copy_takes_the_primary_first_and_respects_the_budget()
        {
            using (var t = new TempDir())
            {
                var src = Directory.CreateDirectory(Path.Combine(t.Path, "src")).FullName;
                File.WriteAllText(Path.Combine(src, "NTUSER.DAT"), "hive");
                File.WriteAllText(Path.Combine(src, "NTUSER.DAT.LOG1"), new string('x', 50));
                File.WriteAllText(Path.Combine(src, "ntuser.ini"), "not family");
                var rows = HostCopy.Family(Path.Combine(src, "NTUSER.DAT"), Path.Combine(t.Path, "dest"), "rel", false, maxTotalBytes: 10);
                Assert.Equal(new[] { "NTUSER.DAT", "NTUSER.DAT.LOG1" }, rows.Select(r => Path.GetFileName(r.SourcePath)).ToArray());
                Assert.Equal(new[] { "Copied", "CappedSkip" }, rows.Select(r => r.Status).ToArray());
                Assert.Equal(@"rel\NTUSER.DAT", rows[0].DestRelative);
                Assert.Equal("Missing", HostCopy.Family(Path.Combine(src, "none.hve"), t.Path, "", false).Single().Status);
                Assert.Equal("Missing", HostCopy.CappedDirectory(Path.Combine(src, "nodir"), "*.pf", t.Path, "", false).Single().Status);
                Assert.Equal("NoData", HostCopy.CappedDirectory(src, "*.pf", t.Path, "", false).Single().Status);
                Assert.Equal("a_b_c", HostCopy.SafeSegment("a:b?c"));
                Assert.Equal("unknown", HostCopy.SafeSegment(" "));
                Assert.Equal("__", HostCopy.SafeSegment(".."));
                Assert.True(HostCopy.IsSid("S-1-5-21-1-2-3-1001"));
                Assert.False(HostCopy.IsSid("S-1-5-21-1\" \"C:\\x"));
            }
        }

        [Fact]
        public void Streams_bam_times_and_task_scripts_decode_like_1_38()
        {
            using (var t = new TempDir())
            {
                var f = Path.Combine(t.Path, "dl.exe");
                File.WriteAllText(f, "x");
                File.WriteAllText(@"\\?\" + f + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
                var streams = FileStreams.List(f);
                Assert.Contains(streams, x => x.Stream == ":$DATA");
                Assert.Contains(streams, x => x.Stream == "Zone.Identifier" && x.Length > 0);
                using (var r = new StreamReader(FileStreams.Open(f, "Zone.Identifier"))) Assert.StartsWith("[ZoneTransfer]", r.ReadToEnd());
                Assert.Empty(FileStreams.List(@"\\server\share\x.exe"));
            }
            Assert.Equal("(not set)", FilesystemCollection.FileTimeText(null));
            Assert.Equal("(not set)", FilesystemCollection.FileTimeText(new byte[4]));
            Assert.Equal("(unparsed)", FilesystemCollection.FileTimeText("text"));
            Assert.Equal("2026-01-02 03:04:05", FilesystemCollection.FileTimeText(BitConverter.GetBytes(new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc())));
            Assert.Equal(new[] { @"C:\Scripts\run.ps1", @"\\srv\share\x.bat" },
                FilesystemCollection.TaskActionScriptPaths("powershell.exe", @"-File ""C:\Scripts\run.ps1"" \\srv\share\x.bat").ToArray());
            Assert.Equal(new[] { @"C:\Tools\job.cmd" }, FilesystemCollection.TaskActionScriptPaths(@"C:\Tools\job.cmd", "").ToArray());
            Assert.Empty(FilesystemCollection.TaskActionScriptPaths("notepad.exe", "readme.txt"));
        }

        [Fact]
        public void Profile_scans_skip_this_case_and_marked_earlier_packages_only()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path }, Quiet());
                CaseLayout.Create(s, Path.Combine(t.Path, "out"));
                var earlier = Directory.CreateDirectory(Path.Combine(t.Path, @"old\Foton_HOST_20260101-000000Z\00_Collection")).Parent!.FullName;
                File.WriteAllText(Path.Combine(earlier, @"00_Collection\collection.log"), "log");
                var lookalike = Directory.CreateDirectory(Path.Combine(t.Path, @"fake\Foton_HOST_20260101-000000Z")).FullName;
                Assert.True(FilesystemCollection.IsCaseOutputPath(s, Path.Combine(s.CaseRoot!, @"08_Filesystem\x.exe")));
                Assert.True(FilesystemCollection.IsCaseOutputPath(s, Path.Combine(earlier, "a.lnk")));
                Assert.False(FilesystemCollection.IsCaseOutputPath(s, Path.Combine(lookalike, "payload.exe")));
                Assert.Equal(new[] { earlier }, s.ExcludedEarlierPackages.ToArray());
            }
        }

        [Fact]
        public void Filesystem_runs_every_task()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true, SkipHashing = true }, Quiet());
                CollectRun.Run(s, only: new[] { "Filesystem" });
                var fs = s.Manifest.Where(m => m.Category == "Filesystem").ToList();
                Assert.Equal(21, fs.Count);
                Assert.DoesNotContain(fs, m => m.Status == TaskStatus.WriteError || m.Status == TaskStatus.Error);
                foreach (var name in new[] { "prefetch_files", "registry_hives_machine", "browser_databases", "host_text_logs" })
                    Assert.Equal(s.IsElevated, fs.Single(m => m.Task == name).Status != TaskStatus.SkippedNotElevated);
            }
        }

        [Fact]
        public void Standard_modules_and_internal_addresses_are_anchored()
        {
            var win = Foton.Win.HostInfo.WindowsDir.TrimEnd('\\');
            Assert.True(ProcessCollection.IsStandardModule(win + @"\System32\kernel32.dll"));
            Assert.True(ProcessCollection.IsStandardModule(Environment.GetEnvironmentVariable("ProgramFiles") + @"\App\x.dll"));
            Assert.False(ProcessCollection.IsStandardModule(@"C:\Users\x\Windows\System32\evil.dll"));
            Assert.False(ProcessCollection.IsStandardModule(@"C:\Users\x\Program Files Fake\evil.dll"));
            foreach (var internalAddress in new[] { "10.1.2.3", "192.168.0.5", "172.20.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.251", "239.255.255.250", "255.255.255.255", "::1", "fe80::1", "ff02::fb", "fd12:3456::1" })
                Assert.False(NetworkCollection.IsExternal(internalAddress), internalAddress);
            foreach (var external in new[] { "8.8.8.8", "172.32.0.1", "2001:4860:4860::8888", "::1:5" })
                Assert.True(NetworkCollection.IsExternal(external), external);
            Assert.Equal(@"a\\b\'c", CollectText.WqlString(@"a\b'c"));
        }

        [Fact]
        public void ServiceDll_resolves_from_Parameters_and_is_empty_for_unknown_services()
        {
            // Task Scheduler is svchost-hosted on every supported Windows; its code is schedsvc.dll.
            Assert.EndsWith(@"\schedsvc.dll", ServiceDll.Resolve("Schedule", out var source), StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Parameters", source);
            Assert.Equal("", ServiceDll.Resolve("NoSuchService_Foton", out source));
            Assert.Equal("", source);
        }

        [Fact]
        public void Service_image_paths_resolve_like_1_38()
        {
            Assert.Equal(@"C:\Program Files\App\svc.exe", PersistenceCollection.ServiceExe(@"""C:\Program Files\App\svc.exe"" -run"));
            Assert.Equal(@"C:\Program Files\App\svc.exe", PersistenceCollection.ServiceExe(@"C:\Program Files\App\svc.exe -run"));
            Assert.Equal(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\system32\svchost.exe",
                PersistenceCollection.ServiceExe(@"%SystemRoot%\system32\svchost.exe -k netsvcs -p"), StringComparer.OrdinalIgnoreCase);
            Assert.Equal(@"C:\tool\run", PersistenceCollection.ServiceExe(@"C:\tool\run --flag"));
            Assert.Equal(@"C:\Apps\x.exeutil\svc.exe", PersistenceCollection.ServiceExe(@"C:\Apps\x.exeutil\svc.exe /run"));
            Assert.Equal("", PersistenceCollection.ServiceExe(""));
        }

        [Fact]
        public void Registry_values_use_PowerShell_truthiness()
        {
            Assert.False(CollectText.Truthy(null));
            Assert.False(CollectText.Truthy(""));
            Assert.False(CollectText.Truthy(0));
            Assert.False(CollectText.Truthy(new string[0]));
            Assert.False(CollectText.Truthy(new[] { "" }));
            Assert.True(CollectText.Truthy("x"));
            Assert.True(CollectText.Truthy(1));
            Assert.True(CollectText.Truthy(new[] { "", "" }));
            Assert.False(CollectText.Truthy(new byte[] { 0 }));
            Assert.True(CollectText.Truthy(new byte[] { 0, 0 }));
        }

        [Fact]
        public void Process_owner_comes_from_the_token()
        {
            var me = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            Assert.Equal(me, new Foton.Win.ProcessOwner().Of(System.Diagnostics.Process.GetCurrentProcess().Id), StringComparer.OrdinalIgnoreCase);
            Assert.Equal("", new Foton.Win.ProcessOwner().Of(-1));
        }

        [Fact]
        public void A_password_never_set_reads_as_never()
        {
            var now = new DateTime(2026, 11, 8, 0, 0, 0, DateTimeKind.Utc);
            Assert.True(Foton.Win.LocalUsers.NeverSet(0, now));
            Assert.True(Foton.Win.LocalUsers.NeverSet(uint.MaxValue, now));
            Assert.False(Foton.Win.LocalUsers.NeverSet(86400, now));
        }

        [Fact]
        public void NoZip_leaves_only_the_case_folder()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                var r = CollectRun.Run(s, only: new string[0]);
                Assert.Null(r.ZipPath);
                Assert.Single(Directory.GetFileSystemEntries(t.Path));
            }
        }
    }
}
