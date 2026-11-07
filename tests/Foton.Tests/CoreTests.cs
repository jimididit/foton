using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    public class CoreTests
    {
        public sealed class Item
        {
            public string Name { get; set; } = "";
            public int Count { get; set; }
            public DateTime When { get; set; }
            public string[] Tags { get; set; } = new string[0];
            public string? Missing { get; set; }
        }

        public sealed class Copy : ICopyRow
        {
            public string SourcePath { get; set; } = "";
            public string Status { get; set; } = "";
            public string Note { get; set; } = "";
        }

        [Fact]
        public void Json_keeps_declaration_order_and_writes_utc_times()
        {
            var item = new Item { Name = "a\"<b>", Count = 3, When = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc), Tags = new[] { "x", "y" } };
            var compact = Json.Compact(item);
            Assert.Equal("{\"Name\":\"a\\\"\\u003cb\\u003e\",\"Count\":3,\"When\":\"2026-01-02 03:04:05\",\"Tags\":[\"x\",\"y\"],\"Missing\":null}", compact);
            var parsed = (Dictionary<string, object>)Json.Parse(Json.Indented(item))!;
            Assert.Equal(new[] { "Name", "Count", "When", "Tags", "Missing" }, parsed.Keys.ToArray());
            Assert.Equal("a\"<b>", parsed["Name"]);
            Assert.Contains("\r\n  \"Count\": 3", Json.Indented(item));
            Assert.Equal("{\r\n  \"A\": [],\r\n  \"B\": {}\r\n}", Json.Indented(new Dictionary<string, object> { ["A"] = new int[0], ["B"] = new Dictionary<string, object>() }));
        }

        [Fact]
        public void Hashes_are_uppercase_sha256_and_sentinels_explain_absence()
        {
            Assert.Equal("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", Hashing.Sha256Hex(System.Text.Encoding.ASCII.GetBytes("abc")));
            using (var t = new TempDir())
            {
                var f = t.File("abc.bin");
                File.WriteAllText(f, "abc");
                Assert.Equal("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", Hashing.SafeHash(f, false));
                Assert.Equal("NotHashed", Hashing.SafeHash(f, true));
                Assert.Equal("FileNotFound", Hashing.SafeHash(t.File("nope"), false));
                Assert.Equal("", Hashing.SafeHash(" ", false));
            }
        }

        [Fact]
        public void Case_layout_matches_the_1_38_tree_and_log_format()
        {
            using (var t = new TempDir())
            {
                var s = Sessions.New(t.Path);
                Assert.Equal(Path.Combine(t.Path, "Foton_HOST_20260115-120000Z"), s.CaseRoot);
                Assert.Equal(CaseCategories.All.Select(kv => kv.Value), Directory.GetDirectories(s.CaseRoot!).Select(Path.GetFileName).OrderBy(x => x));
                s.Status.Write("hello", StatusLevel.Good);
                var log = TextFile.ReadLines(s.LogFile!);
                Assert.Equal("Foton " + FotonVersion.Product + " collection log", log[0]);
                Assert.Equal("2026-01-15 12:00:00 UTC  [Good] hello", log[1]);
            }
        }

        [Fact]
        public void Task_runner_writes_artifact_manifest_and_cache()
        {
            using (var t = new TempDir())
            {
                var s = Sessions.New(t.Path);
                var rows = new[] { new Item { Name = "one", Count = 1 }, new Item { Name = "two", Count = 2 } };
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "System", Name = "items", Format = TaskFormat.Csv, Description = "d" }, () => rows);
                var m = s.Manifest.Single();
                Assert.Equal(("System", "items", @"01_System\items.csv", 2, TaskStatus.Success), (m.Category, m.Task, m.File, m.Records, m.Status));
                Assert.Same(rows, s.Data["items"]);
                Assert.Equal(2, Csv.Read(Path.Combine(s.CaseRoot!, @"01_System\items.csv")).Count);
            }
        }

        [Fact]
        public void Task_runner_records_skips_errors_no_data_and_copy_failures()
        {
            using (var t = new TempDir())
            {
                var s = Sessions.New(t.Path, elevated: false);
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "Security", Name = "auditpol", Format = TaskFormat.Txt, RequiresElevation = true }, () => throw new InvalidOperationException("must not run"));
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "System", Name = "boom" }, () => throw new InvalidOperationException("unit-fail"));
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "System", Name = "empty", Format = TaskFormat.Csv }, () => new Item[0]);
                TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = "Filesystem", Name = "copies", Format = TaskFormat.Csv }, () => new[]
                {
                    new Copy { SourcePath = "a", Status = "Copied" }, new Copy { SourcePath = @"C:\Windows\x", Status = "CopyError", Note = "in use" },
                });

                Assert.Equal(new[] { TaskStatus.SkippedNotElevated, TaskStatus.Error, TaskStatus.NoData, TaskStatus.Partial }, s.Manifest.Select(m => m.Status));
                Assert.Equal(TaskRunner.SkippedText("auditpol") + "\r\n", File.ReadAllText(Path.Combine(s.Dir("Security"), "auditpol.txt")));
                Assert.Equal("Foton: no data returned for 'boom'. Status: Error. unit-fail", TextFile.ReadLines(Path.Combine(s.Dir("System"), "boom.json"))[0]);
                Assert.Equal("Foton: no data returned for 'empty'. Status: NoData. ", TextFile.ReadLines(Path.Combine(s.Dir("System"), "empty.csv"))[0]);
                Assert.Equal(new[] { "boom: unit-fail", "copies: Partial: 1 of 2 file(s) not captured. First: C:\\Windows\\x - in use" },
                    s.Errors.Select(e => e.Task + ": " + e.Error));
            }
        }

        [Fact]
        public void Hashes_skip_hash_files_and_a_nested_copy_and_zip_keeps_the_case_folder()
        {
            using (var t = new TempDir())
            {
                var s = Sessions.New(t.Path);
                File.WriteAllText(Path.Combine(s.Dir("System"), "os.json"), "{}");
                var nested = Path.Combine(s.CaseRoot!, "Foton_HOST_20260115-120000Z", "00_Collection");
                Directory.CreateDirectory(nested);
                File.WriteAllText(Path.Combine(nested, "dup.txt"), "dup");
                PackageFiles.WriteManifestFiles(s);
                Assert.Equal(3, PackageFiles.WriteArtifactHashes(s)); // collection.log, collection_manifest.csv, os.json
                var hashes = Csv.Read(Path.Combine(s.Dir("Collection"), "hashes.csv"));
                Assert.Contains(hashes, r => r["RelativePath"] == @"01_System\os.json" && r["SHA256"] == Hashing.Sha256Hex(System.Text.Encoding.ASCII.GetBytes("{}")));
                Assert.DoesNotContain(hashes, r => r["RelativePath"]!.Contains("dup"));
                Assert.False(File.Exists(Path.Combine(s.Dir("Collection"), "findings.csv")));
                var txt = TextFile.ReadLines(Path.Combine(s.Dir("Collection"), "hashes.txt"));
                Assert.Equal("Foton artifact hashes (SHA-256) - generated 2026-01-15 12:00:00 UTC", txt[0]);

                var zip = PackageFiles.CompressCase(s)!;
                using (var z = ZipFile.OpenRead(zip))
                {
                    Assert.All(z.Entries, e => Assert.StartsWith("Foton_HOST_20260115-120000Z/", e.FullName));
                    Assert.Contains(z.Entries, e => e.FullName == "Foton_HOST_20260115-120000Z/01_System/os.json");
                    Assert.DoesNotContain(z.Entries, e => e.FullName.EndsWith("dup.txt"));
                }
                var hash = PackageFiles.WritePackageHashRecord(s, zip);
                var record = TextFile.ReadLines(s.CaseRoot + "_PACKAGE_HASH.txt");
                Assert.Equal("SHA-256      : " + hash, record[3]);
                Assert.Equal("Case         : CASE-0001", record[8]);
            }
        }

        [Fact]
        public void Coverage_names_the_profile_and_every_gap()
        {
            using (var t = new TempDir())
            {
                var s = Sessions.New(t.Path, elevated: false);
                s.Manifest.Add(new ManifestRow { Task = "auditpol", Status = TaskStatus.SkippedNotElevated });
                s.Manifest.Add(new ManifestRow { Task = "hives", Status = TaskStatus.Partial });
                var c = Coverage.Write(s);
                Assert.Equal("StandardUser", c.CoverageProfile);
                Assert.Equal(new[] { "auditpol" }, c.SkippedTasks);
                Assert.Equal(new[] { "hives (Partial)" }, c.IncompleteTasks);
                var json = (Dictionary<string, object>)Json.Parse(File.ReadAllText(Path.Combine(s.Dir("Collection"), "collection_coverage.json")))!;
                Assert.Equal("CoverageProfile", json.Keys.First());
                Assert.Equal(@"DOMAIN\user", json["CollectionAccount"]);
            }
        }

        [Fact]
        public void Custody_discloses_the_coverage_profile_and_hive_handling()
        {
            using (var t = new TempDir())
            {
                var user = ChainOfCustody.Lines(Sessions.New(t.File("a"), elevated: false, new SessionOptions { LoadUserHives = true, Examiner = "e" }), new CustodyFacts());
                Assert.Contains("Coverage profile STANDARD USER. This process was not elevated. The package", user);
                Assert.Contains("The -LoadUserHives option was requested but ignored: mounting NTUSER.DAT", user);
                Assert.Contains("Operating System     : unknown", user);
                Assert.Contains("Case Number          : (not supplied)", user);

                var admin = ChainOfCustody.Lines(Sessions.New(t.File("b"), elevated: true), new CustodyFacts { OsCaption = "Windows 11 Pro", OsVersion = "10.0.26100", OsBuild = "26100", ExecutableSha256 = "AB" });
                Assert.Contains("SAM and SECURITY are not collected by design (credential material).", admin);
                Assert.Contains("Operating System     : Windows 11 Pro 10.0.26100 (build 26100)", admin);
                Assert.Contains("Executable SHA-256   : AB", admin);
                Assert.DoesNotContain(admin, l => l.StartsWith("Coverage profile STANDARD USER"));
            }
        }

        [Fact]
        public void Case_tree_helpers_tolerate_missing_folders_and_either_separator()
        {
            Assert.Null(CaseTree.FindCaseRoot(Path.Combine(Path.GetTempPath(), "foton-missing-" + Guid.NewGuid().ToString("N"))));
            Assert.True(CaseTree.IsUnder(@"C:\cases\x\copy\a.txt", "C:/cases/x/copy"));
            Assert.True(CaseTree.IsUnder("C:/cases/x/copy/a.txt", @"C:\cases\x\copy\"));
            Assert.False(CaseTree.IsUnder(@"C:\cases\x\copy2\a.txt", @"C:\cases\x\copy"));
            Assert.False(CaseTree.IsUnder(@"C:\cases\x\a.txt", null));
        }

        [Fact]
        public void Collection_window_is_unknown_when_the_log_cannot_be_read()
        {
            using (var t = new TempDir())
            {
                var root = Path.Combine(t.Path, "case");
                Directory.CreateDirectory(Path.Combine(root, "00_Collection"));
                var log = Path.Combine(root, "00_Collection", "collection.log");
                TextFile.Write(log, "2026-01-15 12:00:05 UTC  [Info] a");
                using (new FileStream(log, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    Assert.Null(CollectionWindow.FromCase(root));
            }
        }

        [Fact]
        public void Collection_window_spans_the_logged_stamps_or_is_unknown()
        {
            using (var t = new TempDir())
            {
                var root = Path.Combine(t.Path, "case");
                Directory.CreateDirectory(Path.Combine(root, "00_Collection"));
                Assert.Null(CollectionWindow.FromCase(root));
                TextFile.WriteLines(Path.Combine(root, "00_Collection", "collection.log"), new[]
                {
                    "Foton 2.0.0 collection log",
                    "2026-01-15 12:00:05 UTC  [Info] a",
                    "2026-01-15 12:03:00 UTC  [Good] b",
                    "garbage",
                });
                var w = CollectionWindow.FromCase(root)!;
                Assert.Equal(new DateTime(2026, 1, 15, 12, 0, 5, DateTimeKind.Utc), w.StartUtc);
                Assert.Equal(new DateTime(2026, 1, 15, 12, 3, 0, DateTimeKind.Utc), w.EndUtc);
                Assert.True(w.Contains(new DateTime(2026, 1, 15, 12, 1, 0, DateTimeKind.Utc)));
                Assert.True(w.Contains(new DateTime(2026, 1, 15, 12, 3, 0, 700, DateTimeKind.Utc)));  // within the last logged second
                Assert.False(w.Contains(new DateTime(2026, 1, 15, 12, 3, 1, DateTimeKind.Utc)));
                Assert.False(w.Contains(new DateTime(2026, 1, 15, 12, 0, 4, 900, DateTimeKind.Utc)));
            }
        }
    }
}
