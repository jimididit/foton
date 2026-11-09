using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Foton.Core;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class PackageTests
    {
        static string CopyFixture(TempDir t)
        {
            var dest = Path.Combine(t.Path, Path.GetFileName(TestPaths.Fixture));
            foreach (var f in Directory.GetFiles(TestPaths.Fixture, "*", SearchOption.AllDirectories))
            {
                var target = Path.Combine(dest, f.Substring(TestPaths.Fixture.Length + 1));
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(f, target);
            }
            return dest;
        }

        [Fact]
        public void Opens_a_historical_WinFoton_case_folder()
        {
            var p = FotonPackage.Open(TestPaths.Fixture);
            Assert.Equal(PackageKind.Folder, p.Kind);
            Assert.Equal(new DateTime(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc), p.StartTimeUtc);
            Assert.Single(p.Manifest);
            // security_process_creation.csv is a "Foton: no data returned" sentinel: a recorded outcome, not data.
            Assert.Equal(new[] { "collection_coverage", "defender_status", "hardening_registry_settings", "os_info", "running_processes" },
                p.Artifacts.Keys.OrderBy(k => k, StringComparer.Ordinal));
            var procs = p.Artifacts["running_processes"];
            Assert.Equal(ArtifactKind.Csv, procs.Kind);
            Assert.True(Artifact.Bool(procs.Rows[1], "UserWritablePath"));
            Assert.False(Artifact.Bool(procs.Rows[0], "UserWritablePath"));
            Assert.Equal(ArtifactKind.Json, p.Artifacts["os_info"].Kind);
        }

        [Fact]
        public void Opens_a_parent_folder_and_a_zip_with_the_same_artifacts()
        {
            using (var t = new TempDir())
            {
                var folder = CopyFixture(t);
                Assert.Equal(folder, FotonPackage.Open(t.Path).CaseRoot);

                var zip = t.File("case.zip");
                ZipFile.CreateFromDirectory(folder, zip, CompressionLevel.Fastest, includeBaseDirectory: true);
                var z = FotonPackage.Open(zip, t.Path);
                Assert.Equal(PackageKind.Zip, z.Kind);
                Assert.Equal(FotonPackage.Open(folder).Artifacts.Keys.OrderBy(k => k), z.Artifacts.Keys.OrderBy(k => k));
                Assert.True(Directory.Exists(z.ExtractedTo));
                z.DeleteExtraction();
                Assert.False(Directory.Exists(z.ExtractedTo));
                Assert.True(Directory.Exists(folder)); // a folder package is never touched
            }
        }

        [Fact]
        public void A_zip_entry_too_long_to_extract_is_reported_not_fatal()
        {
            using (var t = new TempDir())
            {
                var folder = CopyFixture(t);
                var rel = @"08_Filesystem\lnk_jumplist\user1\Recent\" + new string('n', 230) + ".lnk";
                File.AppendAllText(Path.Combine(folder, "00_Collection", "hashes.csv"), rel + ",3," + new string('B', 64) + ",2026-01-15 12:00:00\r\n");
                var zip = t.File("case.zip");
                ZipFile.CreateFromDirectory(folder, zip, CompressionLevel.Fastest, includeBaseDirectory: true);
                using (var z = ZipFile.Open(zip, ZipArchiveMode.Update))
                using (var w = new StreamWriter(z.CreateEntry(Path.GetFileName(folder) + "/" + rel.Replace('\\', '/')).Open())) w.Write("lnk");

                var temp = Directory.CreateDirectory(Path.Combine(t.Path, "temp")).FullName;
                var p = FotonPackage.Open(zip, temp);
                Assert.Single(p.NotExtracted);
                Assert.Matches(@"^FotonPkg-[0-9a-f]{8}$", Path.GetFileName(p.ExtractedTo));
                var v = p.VerifyHashes();
                Assert.Equal(new[] { rel }, v.NotExtracted);
                Assert.DoesNotContain(rel, v.Missing);
                Assert.False(v.Intact);
                p.DeleteExtraction();
            }
        }

        [Theory]
        [InlineData("../escape.txt")]
        [InlineData("a/../../escape.txt")]
        [InlineData("C:/Windows/escape.txt")]
        public void Refuses_zip_entries_outside_the_extraction_folder(string entryName)
        {
            using (var t = new TempDir())
            {
                var zip = t.File("evil.zip");
                using (var z = ZipFile.Open(zip, ZipArchiveMode.Create))
                using (var w = new StreamWriter(z.CreateEntry(entryName).Open())) w.Write("x");
                var extract = Path.Combine(t.Path, "x");
                Assert.Throws<InvalidDataException>(() => SafeZip.Extract(zip, extract));
                Assert.False(File.Exists(Path.Combine(t.Path, "escape.txt")));

                var temp = Path.Combine(t.Path, "temp");
                Directory.CreateDirectory(temp);
                Assert.Throws<InvalidDataException>(() => FotonPackage.Open(zip, temp));
                Assert.Empty(Directory.GetDirectories(temp)); // a refused ZIP leaves no extraction behind
            }
        }

        [Fact]
        public void Skip_texts_are_not_loaded_as_data()
        {
            using (var t = new TempDir())
            {
                var folder = CopyFixture(t);
                TextFile.Write(Path.Combine(folder, "06_Security_Posture", "auditpol.csv"), TaskRunner.SkippedText("auditpol"));
                Assert.False(FotonPackage.Open(folder).Artifacts.ContainsKey("auditpol"));
            }
        }

        [Fact]
        public void A_verified_copy_of_the_case_is_skipped_as_a_duplicate()
        {
            using (var t = new TempDir())
            {
                var folder = CopyFixture(t);
                var child = Path.Combine(folder, "re-extracted");
                Directory.CreateDirectory(Path.Combine(child, "00_Collection"));
                File.Copy(Path.Combine(folder, "00_Collection", "hashes.csv"), Path.Combine(child, "00_Collection", "hashes.csv"));
                File.WriteAllText(Path.Combine(child, "inner_only.json"), "{\"a\":1}");
                var p = FotonPackage.Open(folder);
                Assert.Equal(child, p.NestedDuplicate);
                Assert.Empty(p.OtherNestedCases);
                Assert.False(p.Artifacts.ContainsKey("inner_only"));
                Assert.DoesNotContain(p.VerifyHashes().Unlisted, u => u.Contains("inner_only"));
            }
        }

        [Theory]
        [InlineData("planted")]
        [InlineData("same-name-as-the-case")]
        public void A_planted_case_folder_is_reported_not_loaded_and_stays_visible_to_verification(string name)
        {
            // A crafted package could plant a child 00_Collection, even one named like the case, to hide files.
            // Without an identical hashes.csv it is not a copy: reported, cannot override this case's
            // artifacts, and its files show as unlisted.
            using (var t = new TempDir())
            {
                var folder = CopyFixture(t);
                var planted = Path.Combine(folder, name == "planted" ? "planted" : Path.GetFileName(folder));
                Directory.CreateDirectory(Path.Combine(planted, "00_Collection"));
                File.WriteAllText(Path.Combine(planted, "os_info.json"), "{\"forged\":true}");
                var p = FotonPackage.Open(folder);
                Assert.Null(p.NestedDuplicate);
                Assert.Equal(new[] { planted }, p.OtherNestedCases);
                var os = (System.Collections.Generic.Dictionary<string, object>)p.Artifacts["os_info"].Json!;
                Assert.False(os.ContainsKey("forged"));
                Assert.Contains(Path.GetFileName(planted) + @"\os_info.json", p.VerifyHashes().Unlisted);
            }
        }

        [Fact]
        public void Verifies_hashes_and_reports_tampering()
        {
            // The fixture's hashes.csv carries a placeholder hash, so its one listed file must show as changed.
            var fixture = FotonPackage.Open(TestPaths.Fixture).VerifyHashes();
            Assert.False(fixture.Intact);
            Assert.Equal(new[] { @"01_System\os_info.json" }, fixture.Mismatched);
            Assert.DoesNotContain(@"01_System\os_info.json", fixture.Unlisted);

            using (var t = new TempDir())
            {
                var s = Sessions.New(t.Path);
                File.WriteAllText(Path.Combine(s.Dir("System"), "os.json"), "{}");
                PackageFiles.WriteArtifactHashes(s);
                Assert.True(FotonPackage.Open(s.CaseRoot!).VerifyHashes().Intact);

                File.WriteAllText(Path.Combine(s.Dir("System"), "os.json"), "{\"changed\":true}");
                File.Delete(Path.Combine(s.Dir("Collection"), "collection.log"));
                File.WriteAllText(Path.Combine(s.CaseRoot!, "Foton_Report.html"), "<html></html>");
                var v = FotonPackage.Open(s.CaseRoot!).VerifyHashes();
                Assert.False(v.Intact);
                Assert.Equal(new[] { @"01_System\os.json" }, v.Mismatched);
                Assert.Equal(new[] { @"00_Collection\collection.log" }, v.Missing);
                Assert.Equal(new[] { "Foton_Report.html" }, v.Unlisted);
            }
        }

        [Fact]
        public void Hash_rows_pointing_outside_the_case_are_reported_not_read()
        {
            // hashes.csv is untrusted package content: a crafted RelativePath must not make Foton read elsewhere.
            using (var t = new TempDir())
            {
                File.WriteAllText(t.File("secret.txt"), "outside");
                var s = Sessions.New(Path.Combine(t.Path, "cases"));
                var csv = Path.Combine(s.Dir("Collection"), "hashes.csv");
                Csv.Write(csv, new[] { new HashRow { RelativePath = @"..\..\secret.txt", SizeBytes = 7, SHA256 = Hashing.Sha256Hex(t.File("secret.txt")) } });
                var v = FotonPackage.Open(s.CaseRoot!).VerifyHashes();
                Assert.Equal(new[] { @"..\..\secret.txt (path outside the case)" }, v.Mismatched);
                Assert.Equal(0, v.Matched);
            }
        }

        [Fact]
        public void Missing_paths_and_cases_fail_clearly()
        {
            Assert.Throws<FileNotFoundException>(() => FotonPackage.Open(Path.Combine(Path.GetTempPath(), "foton-no-such-" + Guid.NewGuid().ToString("N"))));
            using (var t = new TempDir())
                Assert.Throws<InvalidDataException>(() => FotonPackage.Open(t.Path));
        }
    }
}
