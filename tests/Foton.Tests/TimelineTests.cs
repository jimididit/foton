using System;
using System.IO;
using System.Linq;
using Foton.Analyze.Timeline;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    public class TimelineTests
    {
        static void Write(string path, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text);
        }

        /// <summary>A Foton 2 case collected 2026-11-10 12:00:00-12:05:00 UTC with a few sources in each tool's real header.</summary>
        static string Case(TempDir t)
        {
            var c = t.File("Foton_HOST_20261110-120000Z");
            Write(Path.Combine(c, @"00_Collection\collection.log"),
                "Foton 2.12.0 collection log\r\n2026-11-10 12:00:00 UTC  [Step] start\r\n2026-11-10 12:05:00 UTC  [Good] done\r\n");
            Write(Path.Combine(c, @"analysis\external\pecmd\pecmd_Timeline.csv"),
                "RunTime,ExecutableName,SourceFilename,PathValidated\r\n2026-11-09 08:00:00,\\VOLUME{x}\\TOOL.EXE,TOOL.EXE-1.pf,True\r\n2026-11-10 12:01:00,\\VOLUME{x}\\CMD.EXE,CMD.EXE-2.pf,True\r\n");
            Write(Path.Combine(c, @"analysis\external\evtxecmd\evtxecmd.csv"),
                "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,MapDescription,PayloadData1\r\n1,1,2026-11-09 07:59:59.5000000,4624,Info,Microsoft-Windows-Security-Auditing,Security,Successful logon,Target: alice\r\n");
            Write(Path.Combine(c, @"analysis\external\hayabusa\hayabusa.csv"),
                "\"Timestamp\",\"RuleTitle\",\"Level\",\"Computer\",\"Channel\",\"EventID\",\"RecordID\",\"Details\",\"ExtraFieldInfo\",\"RuleID\"\r\n\"2026-11-09 08:00:00.000 +00:00\",\"Rule A\",\"high\",\"PC\",\"Sec\",\"4624\",\"1\",\"\",\"\",\"r\"\r\n");
            Write(Path.Combine(c, @"analysis\external\chainsaw\sigma.csv"),
                "timestamp,detections,path,count,Event.System.Provider,Event ID,Record ID,Computer,Event Data\r\n2026-11-09T10:00:00.000000+02:00,Rule B,x.evtx,1,p,4688,2,PC,d\r\n");
            Write(Path.Combine(c, @"analysis\external\appcompatcacheparser\appcompatcache.csv"),
                "ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,Duplicate,SourceFile,FromSlack\r\n1,0,C:\\x\\a.exe,2026-11-01 00:00:00,NA,False,SYSTEM,False\r\n1,1,C:\\x\\b.exe,,NA,False,SYSTEM,False\r\n");
            Write(Path.Combine(c, @"analysis\external\srumecmd\20261110_SrumECmd_AppResourceUseInfo_Output.csv"),
                "Id,Timestamp,ExeInfo\r\n1,2026-11-09 08:00:00,a.exe\r\n");
            Write(Path.Combine(c, @"analysis\external\lecmd\lecmd.csv"), "NotTheColumns,Other\r\nx,y\r\n");
            // Only one of SBECmd's two time columns: the other is named as missing, the present one still read.
            Write(Path.Combine(c, @"analysis\external\sbecmd\u_NTUSER.csv"), "AbsolutePath,LastInteracted\r\nC:\\Data,2026-11-02 00:00:00\r\n");
            Write(Path.Combine(c, @"05_Persistence\scheduled_tasks.csv"),
                "\"TaskPath\",\"TaskName\",\"State\",\"Author\",\"RunAsUser\",\"RunLevel\",\"Triggers\",\"Actions\",\"LastRunTime\"\r\n\"\\\",\"T1\",\"Ready\",\"\",\"\",\"\",\"\",\"x.exe\",\"2026-11-09 08:00:00\"\r\n");
            Write(Path.Combine(c, @"07_Event_Logs\security_logon_events.csv"),
                "\"TimeCreatedUtc\",\"Log\",\"EventId\",\"Level\",\"Provider\",\"Computer\",\"UserSid\",\"RecordId\",\"Message\"\r\n\"2026-11-09 07:59:59\",\"Security\",\"4624\",\"\",\"\",\"\",\"\",\"1\",\"An account was logged on.\"\r\n");
            Write(Path.Combine(c, @"08_Filesystem\bam_dam_user_settings.csv"), "Foton: bam_dam_user_settings collected no data (NoData).");
            return c;
        }

        [Fact]
        public void The_timeline_orders_every_source_by_UTC_and_keeps_what_each_time_means()
        {
            using (var t = new TempDir())
            {
                var run = TimelineBuilder.Build(Case(t), new TimelineOptions());
                Assert.Equal(new[]
                {
                    "2026-11-01 00:00:00|AppCompatCacheParser|File modified (Shimcache entry; not a run time)|C:\\x\\a.exe",
                    "2026-11-02 00:00:00|SBECmd|Folder last interacted with (shellbag)|C:\\Data",
                    "2026-11-09 07:59:59|EvtxECmd|Event logged|4624 Security:  Successful logon  Target: alice",
                    "2026-11-09 08:00:00|Chainsaw|Rule hit (Chainsaw)|Rule B  (event 4688)",
                    "2026-11-09 08:00:00|Foton|Scheduled task last ran|\\T1  x.exe",
                    "2026-11-09 08:00:00|Hayabusa|Rule hit (Hayabusa)|high:  Rule A  (Sec 4624)",
                    "2026-11-09 08:00:00|PECmd|Ran (Prefetch run time)|\\VOLUME{x}\\TOOL.EXE",
                    "2026-11-10 12:01:00|PECmd|Ran (Prefetch run time)|\\VOLUME{x}\\CMD.EXE",
                }, run.Rows.Select(r => string.Join("|", r.TimeUtc, r.Source, r.Meaning, r.Summary)));
                Assert.Equal(new[] { false, false, false, false, false, false, false, true }, run.Rows.Select(r => r.DuringCollection));
                Assert.Equal("FirstInteracted", run.Sources.Single(s => s.Artifact.EndsWith("u_NTUSER.csv")).MissingColumns);
                Assert.Equal(@"analysis\external\pecmd\pecmd_Timeline.csv", run.Rows.Last().Artifact);
                // The root spelled with forward slashes or a trailing separator gives the same relative artifact paths.
                var c = run.Rows.Last();
                foreach (var spelling in new[] { Case(t).Replace('\\', '/'), Case(t) + "\\" })
                    Assert.Equal(c.Artifact, TimelineBuilder.Build(spelling, new TimelineOptions()).Rows.Last().Artifact);
                Assert.Equal(2, run.Rows.Last().Row);

                string Left(string artifactEnd) => run.Sources.Single(s => s.Artifact.EndsWith(artifactEnd, StringComparison.OrdinalIgnoreCase)).LeftOut;
                Assert.Equal("hourly counters; included with -All", Left("AppResourceUseInfo_Output.csv"));
                Assert.Equal("EvtxECmd output covers the same events", Left("security_logon_events.csv"));
                Assert.StartsWith("columns not found", Left("lecmd.csv"));
                Assert.Equal("no data (the task left a note)", Left("bam_dam_user_settings.csv"));
                Assert.Equal(1, run.Sources.Single(s => s.Artifact.EndsWith("appcompatcache.csv")).TimesWithoutValue);
                Assert.False(run.Capped);
            }
        }

        [Fact]
        public void Options_add_bulk_tables_limit_the_window_and_cap_the_rows()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                Assert.Contains(TimelineBuilder.Build(c, new TimelineOptions { All = true }).Rows, r => r.Meaning.StartsWith("Resource use"));
                var window = TimelineBuilder.Build(c, new TimelineOptions { FromUtc = new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc), ToUtc = new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc) });
                Assert.Equal(4, window.Rows.Count);
                Assert.True(window.Sources.Sum(s => s.OutsideWindow) > 0);
                var capped = TimelineBuilder.Build(c, new TimelineOptions { MaxRows = 2 });
                Assert.True(capped.Capped);
                Assert.Equal(2, capped.Rows.Count);
                Assert.Contains(capped.Sources, s => s.LeftOut == "row cap reached");
                // The source being read when the cap hit says it was cut short.
                Assert.Single(capped.Sources, s => s.LeftOut.StartsWith("row cap reached after "));
            }
        }

        [Fact]
        public void Older_packages_keep_their_local_time_columns_out_and_files_are_written()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                File.WriteAllText(Path.Combine(c, @"00_Collection\collection.log"), "WinFoton 1.38.2 collection log\r\n");
                var run = TimelineBuilder.Run(c, new StatusLog(new StringWriter()), new TimelineOptions());
                Assert.Equal("written in local time by packages before Foton 2", run.Sources.Single(s => s.Artifact.EndsWith("scheduled_tasks.csv")).LeftOut);
                Assert.DoesNotContain(run.Rows, r => r.DuringCollection);   // no collection window in that log
                var csv = Csv.Read(run.TimelinePath!);
                Assert.Equal(run.Rows.Count, csv.Count);
                Assert.Equal(new[] { "TimeUtc", "Source", "Meaning", "Summary", "Artifact", "Row", "DuringCollection" }, csv[0].Keys);
                Assert.True(File.Exists(run.SourcesPath));

                // An empty timeline still has its header.
                var empty = t.File("Foton_EMPTY_20261110-120000Z");
                Directory.CreateDirectory(Path.Combine(empty, "00_Collection"));
                var none = TimelineBuilder.Run(empty, new StatusLog(new StringWriter()), new TimelineOptions());
                Assert.StartsWith("\"TimeUtc\"", File.ReadAllText(none.TimelinePath!).TrimStart('\uFEFF'));
            }
        }

        [Theory]
        [InlineData("2026-11-09 08:00:00", "2026-11-09 08:00:00")]
        [InlineData("2026-11-09 08:00:00.9999999", "2026-11-09 08:00:00")]
        [InlineData("2026-11-09T10:00:00+02:00", "2026-11-09 08:00:00")]
        [InlineData("2026-11-09 03:00:00.000 -05:00", "2026-11-09 08:00:00")]
        [InlineData("2026-11-09T08:00:00Z", "2026-11-09 08:00:00")]
        public void Times_in_every_tool_format_are_read_as_UTC(string text, string utc)
        {
            Assert.True(TimelineBuilder.TryTime(text, out var t));
            Assert.Equal(utc, FotonTime.Format(t));
        }

        [Theory]
        [InlineData("")]
        [InlineData("(not set)")]
        [InlineData("1601-01-01 00:00:00")]
        [InlineData("11/9/2026 8:00 AM")]
        [InlineData("2026-11-09 08:00:00 +99:99")]
        [InlineData("2026-11-09 08:00:00 +15:00")]
        [InlineData("0001-01-01 00:00:00 +05:00")]
        [InlineData("9999-12-31 23:59:59 -05:00")]
        [InlineData("2026-11-09 08:00:00.12345678")]
        [InlineData("2026-11-09 08:00:00.\u0661\u0662")]
        [InlineData("\u0662\u0660\u0662\u0666-11-09 08:00:00")]
        public void Values_that_are_not_times_are_not_guessed(string text) => Assert.False(TimelineBuilder.TryTime(text, out _));

        [Fact]
        public void An_artifact_that_fails_partway_says_how_far_it_got()
        {
            var partly = new TimelineSourceStat { RowsRead = 5, TimesUsed = 3 };
            Assert.Equal("partly read: 3 time(s) from its first 5 row(s) are in the timeline, then: disk error", TimelineBuilder.Stopped(partly, new IOException("disk error")));
            Assert.Equal("unreadable: locked", TimelineBuilder.Stopped(new TimelineSourceStat(), new IOException("locked")));
        }

        [Fact]
        public void The_reader_filters_a_written_timeline_and_counts_every_match()
        {
            using (var t = new TempDir())
            {
                var run = TimelineBuilder.Run(Case(t), new StatusLog(new StringWriter()), new TimelineOptions());
                var all = TimelineReader.Read(run.TimelinePath!, new TimelineFilter(), 100);
                Assert.Null(all.Problem);
                Assert.Equal(run.Rows.Count, all.Matches);
                Assert.Equal(run.Rows.Select(r => r.TimeUtc + "|" + r.Artifact + "|" + r.Row + "|" + r.DuringCollection),
                    all.Rows.Select(r => r.TimeUtc + "|" + r.Artifact + "|" + r.Row + "|" + r.DuringCollection));
                Assert.Equal(new[] { "AppCompatCacheParser", "Chainsaw", "EvtxECmd", "Foton", "Hayabusa", "PECmd", "SBECmd" }, all.Sources);

                Assert.Equal(2, TimelineReader.Read(run.TimelinePath!, new TimelineFilter { Source = "pecmd" }, 100).Matches);
                Assert.Equal("EvtxECmd", TimelineReader.Read(run.TimelinePath!, new TimelineFilter { Text = "ALICE" }, 100).Rows.Single().Source);
                var window = TimelineReader.Read(run.TimelinePath!, new TimelineFilter
                {
                    FromUtc = new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc), ToUtc = new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc),
                }, 100);
                Assert.Equal(4, window.Matches);
                // Only the first rows are kept; the count is still every match, and the source list still every source.
                var few = TimelineReader.Read(run.TimelinePath!, new TimelineFilter(), 3);
                Assert.Equal(3, few.Rows.Count);
                Assert.Equal(run.Rows.Count, few.Matches);
                Assert.Equal(all.Sources, TimelineReader.Read(run.TimelinePath!, new TimelineFilter { Source = "SBECmd" }, 100).Sources);

                var other = t.File("other.csv");
                File.WriteAllText(other, "A,B\r\n1,2\r\n");
                Assert.StartsWith("not a timeline file", TimelineReader.Read(other, new TimelineFilter(), 100).Problem);
            }
        }

        [Fact]
        public void Filter_times_are_UTC_and_a_bare_To_date_includes_that_day()
        {
            Assert.True(TimelineReader.ParseUtc(" 2026-11-09 08:00:00 ", false, out var exact));
            Assert.Equal(new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc), exact);
            Assert.True(TimelineReader.ParseUtc("2026-11-09", true, out var end));
            Assert.Equal(new DateTime(2026, 11, 10, 0, 0, 0, DateTimeKind.Utc).AddTicks(-1), end);
            Assert.True(TimelineReader.ParseUtc("9999-12-31", true, out var last));
            Assert.Equal(DateTime.MaxValue.Ticks, last.Ticks);
            Assert.False(TimelineReader.ParseUtc("11/9/2026", false, out _));
        }

        [Fact]
        public void A_viewer_row_gives_the_time_the_timeline_takes_from_it()
        {
            var header = new[] { "RunTime", "ExecutableName" };
            Assert.True(TimelineReader.TimeOfRow(@"analysis\external\pecmd\x_Timeline.csv", header, new[] { "2026-11-09 08:00:00.5", "A.EXE" }, out var utc));
            Assert.Equal("2026-11-09 08:00:00", FotonTime.Format(utc));
            Assert.False(TimelineReader.TimeOfRow(@"analysis\external\pecmd\x_Timeline.csv", header, new[] { "", "A.EXE" }, out _));
            Assert.False(TimelineReader.TimeOfRow(@"analysis\external\pecmd\x.csv", header, new[] { "2026-11-09 08:00:00", "A.EXE" }, out _));
            Assert.True(TimelineReader.ReadsFile("05_Persistence/scheduled_tasks.csv"));
            Assert.False(TimelineReader.ReadsFile(@"05_Persistence\scheduled_tasks.json"));
            Assert.False(TimelineReader.ReadsFile(@"analysis\findings.csv"));
            // SBECmd: the first time column the row has a value in.
            Assert.True(TimelineReader.TimeOfRow(@"analysis\external\sbecmd\u_NTUSER.csv", new[] { "AbsolutePath", "FirstInteracted", "LastInteracted" },
                new[] { "C:\\Data", "", "2026-11-02 00:00:00" }, out var sb));
            Assert.Equal("2026-11-02 00:00:00", FotonTime.Format(sb));
        }

        [Fact]
        public void Fractions_keep_every_100ns_tick()
        {
            Assert.True(TimelineBuilder.TryTime("2026-11-09 08:00:00.0000001", out var one));
            Assert.Equal(new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc).Ticks + 1, one.Ticks);
            Assert.True(TimelineBuilder.TryTime("2026-11-09 08:00:00.9999999", out var last));
            Assert.Equal(new DateTime(2026, 11, 9, 8, 0, 0, DateTimeKind.Utc).Ticks + 9999999, last.Ticks);
            Assert.True(TimelineBuilder.TryTime("2026-11-09 08:00:00.12", out var two));
            Assert.Equal(1200000, two.Ticks % TimeSpan.TicksPerSecond);
        }
    }
}
