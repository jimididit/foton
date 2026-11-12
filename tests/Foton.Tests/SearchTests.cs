using System;
using System.IO;
using System.Linq;
using System.Threading;
using Foton.Core;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class SearchTests
    {
        static string Case(TempDir t)
        {
            var c = t.File("Foton_HOST_20261110-120000Z");
            Directory.CreateDirectory(Path.Combine(c, CaseTree.CollectionFolder));
            Directory.CreateDirectory(Path.Combine(c, "05_Persistence"));
            Directory.CreateDirectory(Path.Combine(c, @"analysis\external\pecmd"));
            File.WriteAllText(Path.Combine(c, @"05_Persistence\scheduled_tasks.csv"), "TaskName,Actions\r\nUpdater,C:\\Users\\x\\INVOICE.exe\r\nOther,b.exe\r\n");
            File.WriteAllText(Path.Combine(c, @"analysis\external\pecmd\pe_Timeline.csv"), "RunTime,ExecutableName\r\n2026-11-09 08:00:00,\\VOLUME{x}\\INVOICE.EXE\r\n");
            File.WriteAllText(Path.Combine(c, @"00_Collection\collection.log"), "Foton 2.14.0 collection log\r\nline two\r\nran invoice.exe here\r\n");
            File.WriteAllText(Path.Combine(c, @"01_os.json"), "{\"Name\":\"invoice\"}");
            File.WriteAllBytes(Path.Combine(c, @"05_Persistence\SYSTEM"), new byte[] { 0x72, 0x65, 0x67, 0x66, 0, 0, 0x69, 0x6E, 0x76, 0x6F, 0x69, 0x63, 0x65 });
            Directory.CreateDirectory(Path.Combine(c, "analysis"));
            File.WriteAllText(Path.Combine(c, @"analysis\search_20261101-000000Z.csv"), "Artifact,Snippet\r\nx,invoice\r\n");
            return c;
        }

        [Fact]
        public void Text_is_found_in_csv_cells_and_text_lines_and_binaries_and_earlier_results_are_left_out()
        {
            using (var t = new TempDir())
            {
                var run = PackageSearch.Search(Case(t), "invoice", new SearchOptions());
                Assert.Equal(new[]
                {
                    @"00_Collection\collection.log|0|3|",
                    @"01_os.json|0|1|",
                    @"05_Persistence\scheduled_tasks.csv|1|0|Actions",
                    @"analysis\external\pecmd\pe_Timeline.csv|1|0|ExecutableName",
                }, run.Hits.Select(h => $"{h.Artifact}|{h.Row}|{h.Line}|{h.Column}").OrderBy(s => s, StringComparer.Ordinal));
                Assert.Equal(4, run.Matches);
                Assert.Equal(4, run.FilesWithMatches);
                Assert.Equal(new[] { @"05_Persistence\SYSTEM" }, run.Binary);
                Assert.Equal("ran invoice.exe here", run.Hits.Single(h => h.Line == 3).Snippet);

                // A header cell is row 0.
                Assert.Equal(0, PackageSearch.Search(Case(t), "taskname", new SearchOptions()).Hits.Single().Row);
            }
        }

        [Fact]
        public void Regular_expressions_hits_cap_file_size_and_stop_are_honoured_and_said()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var re = PackageSearch.Search(c, @"invoice\.exe$", new SearchOptions { Regex = true });
                Assert.Equal(2, re.Matches);   // the task action and the PECmd name end with it; the log line does not
                Assert.Throws<ArgumentException>(() => PackageSearch.Search(c, "(unclosed", new SearchOptions { Regex = true }));
                Assert.Throws<ArgumentException>(() => PackageSearch.Search(c, "", new SearchOptions()));

                var capped = PackageSearch.Search(c, "invoice", new SearchOptions { MaxHits = 1 });
                Assert.Single(capped.Hits);
                Assert.Equal(4, capped.Matches);

                var small = PackageSearch.Search(c, "invoice", new SearchOptions { MaxFileBytes = 40 });
                Assert.Contains(small.NotSearched, n => n.StartsWith(@"05_Persistence\scheduled_tasks.csv (larger than 40 bytes)", StringComparison.Ordinal));

                using (var stop = new CancellationTokenSource())
                {
                    stop.Cancel();
                    var stopped = PackageSearch.Search(c, "invoice", new SearchOptions(), stop.Token);
                    Assert.True(stopped.Stopped);
                    Assert.Equal(0, stopped.Matches);
                }
            }
        }

        [Fact]
        public void A_search_writes_its_hits_and_what_it_searched()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var run = PackageSearch.Run(c, "invoice", new SearchOptions(), new StatusLog(new StringWriter()), default, new DateTime(2026, 11, 12, 12, 0, 0, DateTimeKind.Utc));
                Assert.Equal(Path.Combine(c, @"analysis\search_20261112-120000Z.csv"), run.ResultsPath);
                Assert.Equal(4, Csv.Read(run.ResultsPath!).Count);
                var summary = File.ReadAllText(run.SummaryPath!);
                Assert.Contains("Text: invoice (case-insensitive)", summary);
                Assert.Contains(@"05_Persistence\SYSTEM", summary);

                var none = PackageSearch.Run(c, "no-such-value", new SearchOptions(), new StatusLog(new StringWriter()), default, new DateTime(2026, 11, 12, 12, 0, 1, DateTimeKind.Utc));
                Assert.StartsWith("\"Artifact\"", File.ReadAllText(none.ResultsPath!).TrimStart('\uFEFF'));

                // A results name already taken (a file, or a link planted in the package) is never written over or through.
                var before = File.ReadAllText(run.ResultsPath!);
                Assert.Throws<IOException>(() => PackageSearch.Run(c, "other", new SearchOptions(), new StatusLog(new StringWriter()), default, new DateTime(2026, 11, 12, 12, 0, 0, DateTimeKind.Utc)));
                Assert.Equal(before, File.ReadAllText(run.ResultsPath!));
                Assert.False(PackageSearch.Occupied(Path.Combine(c, "analysis", "nothing-here.csv")));
            }
        }

        [Fact]
        public void Snippets_show_the_text_around_a_match_on_one_line()
        {
            var text = new string('a', 200) + "MATCH\r\n" + new string('b', 200);
            var s = PackageSearch.Snippet(text, 200, 5);
            Assert.StartsWith("...", s);
            Assert.EndsWith("...", s);
            Assert.Contains("MATCH", s);
            Assert.DoesNotContain("\n", s);
        }
    }
}
