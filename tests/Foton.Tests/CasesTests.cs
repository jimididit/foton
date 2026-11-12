using System.Diagnostics;
using System.IO;
using System.Linq;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class CasesTests
    {
        static void Write(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text);
        }

        [Fact]
        public void Cases_and_baselines_are_listed_from_their_own_files_newest_first()
        {
            using (var t = new TempDir())
            {
                // A collected, analyzed case with its ZIP beside it.
                var a = t.File("Foton_HOST_20261110-120000Z");
                Write(Path.Combine(a, @"00_Collection\chain_of_custody.txt"), "Foton chain of custody\r\nCase Number          : CASE-0001\r\nExaminer             : Jane Doe\r\nParameters Used\r\n");
                Write(Path.Combine(a, @"00_Collection\collection_coverage.json"), "{\"Elevated\":true,\"ProfileName\":\"Quick\"}");
                Write(Path.Combine(a, @"00_Collection\findings.csv"), "\"Severity\",\"Title\"\r\n\"High\",\"x\"\r\n\"Info\",\"y\"\r\n");
                Write(Path.Combine(a, @"analysis\findings.csv"), "\"Severity\",\"Title\"\r\n\"Medium\",\"x\"\r\n\"Medium\",\"y\"\r\n\"Low\",\"z\"\r\n");
                Write(Path.Combine(a, @"analysis\parsed_records.csv"), "x");
                File.WriteAllText(a + ".zip", "zip");
                // A newer case whose coverage file is damaged: still listed, with the reason.
                var b = t.File("Foton_HOST_20261111-090000Z");
                Write(Path.Combine(b, @"00_Collection\collection_coverage.json"), "{");
                // A downloaded ZIP with no folder, and one already extracted beside it.
                File.WriteAllText(t.File("Foton_OTHER_20261109-000000Z.zip"), "zip");
                File.WriteAllText(t.File("Foton_X_20261108-000000Z.zip"), "zip");
                Write(t.File(@"Foton_X_20261108-000000Z-extracted\Foton_X_20261108-000000Z\00_Collection\chain_of_custody.txt"), "Case Number          : CASE-0002\r\n");
                // Baselines: one readable, one damaged; a folder without baseline.json is not a baseline.
                Directory.CreateDirectory(t.File("FotonBaseline_HOST_20261101-000000Z"));
                File.Copy(TestPaths.Golden("baseline-ref.json"), t.File(@"FotonBaseline_HOST_20261101-000000Z\baseline.json"));
                Write(t.File(@"FotonBaseline_BAD_20261102-000000Z\baseline.json"), "not json");
                Directory.CreateDirectory(t.File("FotonBaseline_EMPTY_20261103-000000Z"));
                Directory.CreateDirectory(t.File("Unrelated"));

                var list = CaseIndex.Scan(new[] { t.Path, t.Path + "\\", t.File("missing") });

                Assert.Equal(new[] { "Foton_HOST_20261111-090000Z", "Foton_HOST_20261110-120000Z", "Foton_OTHER_20261109-000000Z", "Foton_X_20261108-000000Z" }, list.Cases.Select(c => c.Name));
                var full = list.Cases[1];
                Assert.Equal("HOST|2026-11-10 12:00:00|Folder|CASE-0001|Jane Doe|True|Quick",
                    string.Join("|", full.Host, full.CollectedUtc, full.Kind, full.CaseNumber, full.Examiner, full.Elevated, full.Profile));
                Assert.Equal("analysis|0|2|1|0", string.Join("|", full.FindingsSource, full.High, full.Medium, full.Low, full.Info));
                Assert.True(full.Parsed && full.Analyzed && full.HasZip && !full.Composed);
                Assert.Equal("", full.Problem);
                Assert.Contains("coverage", list.Cases[0].Problem);
                Assert.Null(list.Cases[0].Elevated);
                var zip = list.Cases[2];
                Assert.Equal("Zip|" + t.File("Foton_OTHER_20261109-000000Z.zip") + "|", string.Join("|", zip.Kind, zip.Path, zip.CaseNumber));
                var extracted = list.Cases[3];
                Assert.Equal("ZipExtracted|" + t.File("Foton_X_20261108-000000Z.zip") + "|CASE-0002", string.Join("|", extracted.Kind, extracted.Path, extracted.CaseNumber));

                Assert.Equal(new[] { "FotonBaseline_BAD_20261102-000000Z", "FotonBaseline_HOST_20261101-000000Z" }, list.Baselines.Select(b2 => b2.Name));
                Assert.Contains("baseline.json", list.Baselines[0].Problem);
                Assert.Equal("", list.Baselines[1].Problem);
                // The header, not the folder name, gives host and time (here the golden fixture's own values).
                Assert.Equal("PC1|2026-01-01 00:00:00|True|00", string.Join("|", list.Baselines[1].Host, list.Baselines[1].CapturedUtc, list.Baselines[1].Elevated, list.Baselines[1].PayloadSha256));
                Assert.Contains(list.Notes, n => n.StartsWith("Not found: "));

                // foton cases prints the same rows.
                var lines = CaseIndex.Lines(list).ToList();
                Assert.Equal("Cases (4), newest first", lines[0]);
                Assert.Contains("  2026-11-10 12:00:00  HOST  CASE-0001  admin  profile Quick  H0 M2 L1 I0 (analysis)  parsed analyzed  Folder+zip", lines);
                Assert.Contains(lines, l => l.StartsWith("      unreadable: coverage"));
                Assert.Contains("Baselines (2), newest first", lines);

                // A control sequence planted in package metadata (here an ANSI escape in the case number) never reaches the text.
                Write(Path.Combine(a, @"00_Collection\chain_of_custody.txt"), "Case Number          : CASE\u001b[2J\u009b31m-9\r\n");
                var planted = CaseIndex.Lines(CaseIndex.Scan(new[] { t.Path })).ToList();
                Assert.Contains(planted, l => l.Contains("CASE [2J 31m-9"));
                Assert.DoesNotContain(planted, l => l.Any(ch => char.IsControl(ch)));
            }
        }

        static bool Junction(string link, string target)
        {
            var p = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"") { UseShellExecute = false, CreateNoWindow = true });
            p!.WaitForExit(30000);
            return Directory.Exists(link);
        }

        [Fact]
        public void Links_inside_or_named_like_a_package_are_not_followed()
        {
            using (var t = new TempDir())
            {
                var outside = t.File("outside");
                Write(Path.Combine(outside, @"00_Collection\chain_of_custody.txt"), "Case Number          : SECRET\r\n");
                Write(Path.Combine(outside, @"00_Collection\findings.csv"), "\"Severity\"\r\n\"High\"\r\n");
                Write(Path.Combine(outside, "findings.csv"), "\"Severity\"\r\n\"High\"\r\n");
                var root = Directory.CreateDirectory(t.File("cases")).FullName;
                // The package folder itself is a junction.
                if (!Junction(Path.Combine(root, "Foton_HOST_20261110-120000Z"), outside)) return;   // junctions unavailable here
                // A real package folder whose 00_Collection is a junction.
                Directory.CreateDirectory(Path.Combine(root, "Foton_HOST_20261111-000000Z"));
                Junction(Path.Combine(root, @"Foton_HOST_20261111-000000Z\00_Collection"), Path.Combine(outside, "00_Collection"));
                // A real package whose analysis folder is a junction: its findings are not read from there.
                var c = Path.Combine(root, "Foton_HOST_20261112-000000Z");
                Write(Path.Combine(c, @"00_Collection\findings.csv"), "\"Severity\"\r\n\"Info\"\r\n");
                Junction(Path.Combine(c, "analysis"), outside);

                var list = CaseIndex.Scan(new[] { root });
                var only = Assert.Single(list.Cases);
                Assert.Equal(c, only.Path);
                Assert.False(only.Analyzed);
                Assert.Equal("collect|0|1", string.Join("|", only.FindingsSource, only.High, only.Info));
                Assert.Equal(2, list.Notes.Count(n => n.StartsWith("Link or junction not followed")));
                Assert.DoesNotContain(list.Cases, x => x.CaseNumber == "SECRET");
            }
        }

        [Fact]
        public void A_zip_beside_a_folder_that_is_not_a_case_is_listed_and_a_drive_root_is_the_drive()
        {
            using (var t = new TempDir())
            {
                Directory.CreateDirectory(t.File("Foton_Y_20261107-000000Z"));   // no 00_Collection: not a case
                File.WriteAllText(t.File("Foton_Y_20261107-000000Z.zip"), "zip");
                var zip = Assert.Single(CaseIndex.Scan(new[] { t.Path }).Cases);
                Assert.Equal("Zip", zip.Kind);

                // "D:\" must not become "D:" (the current folder on D:); other folders lose their trailing backslash.
                Assert.Equal(@"D:\", CaseIndex.Normalize(@"D:\"));
                Assert.Equal(@"D:\Cases", CaseIndex.Normalize(@"D:\Cases\"));
                Assert.Equal(@"\\server\share\Cases", CaseIndex.Normalize(@"\\server\share\Cases\"));
            }
        }
    }
}
