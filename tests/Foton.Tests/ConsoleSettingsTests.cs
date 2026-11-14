using System.IO;
using Foton.Tools;
using Xunit;

namespace Foton.Tests
{
    public class ConsoleSettingsTests
    {
        [Fact]
        public void Each_setting_falls_back_on_its_own_and_good_ones_are_kept()
        {
            var s = ConsoleSettings.Parse(@"{
                ""Examiner"": ""Examiner A\r\nforged"",
                ""OpenOnStart"": ""Somewhere"",
                ""RecentCount"": 99,
                ""RecentCases"": [""D:\\Cases\\Foton_A"", ""relative\\path"", ""D:\\Cases\\Foton_A"", 5],
                ""CaseFolders"": [""\\\\server\\share\\Cases"", ""C:relative""],
                ""CasesOutput"": ""D:\\Cases"",
                ""BaselinesOutput"": ""not a path"",
                ""BundlesOutput"": ""relative\\Bundles"",
                ""Theme"": ""Dark"",
                ""TextSize"": 13
            }");
            Assert.Equal("Examiner A  forged", s.Examiner);
            Assert.Equal(ConsoleSettings.StartOnCases, s.OpenOnStart);
            Assert.Equal(8, s.RecentCount);
            Assert.Equal(new[] { @"D:\Cases\Foton_A" }, s.RecentCases);
            Assert.Equal(new[] { @"\\server\share\Cases" }, s.CaseFolders);
            Assert.Equal(@"D:\Cases", s.CasesFolder);
            Assert.Equal("", s.BaselinesOutput);
            Assert.EndsWith(@"Foton\Baselines", s.BaselinesFolder);
            Assert.Equal("", s.BundlesOutput);
            Assert.EndsWith(@"Foton\Bundles", s.BundlesFolder);
            Assert.Equal(ConsoleSettings.ThemeDark, s.Theme);
            Assert.Equal(9, s.TextSize);

            Assert.Equal(new ConsoleSettings().ToJson(), ConsoleSettings.Parse("{ not json").ToJson());
            Assert.Equal(new ConsoleSettings().ToJson(), ConsoleSettings.Parse("[1,2]").ToJson());
        }

        [Fact]
        public void Every_offered_theme_is_kept_and_an_unknown_one_falls_back_to_Light()
        {
            foreach (var theme in ConsoleSettings.Themes)
                Assert.Equal(theme, ConsoleSettings.Parse("{ \"Theme\": \"" + theme + "\" }").Theme);
            Assert.Equal(ConsoleSettings.ThemeLight, ConsoleSettings.Parse("{ \"Theme\": \"Neon\" }").Theme);
            Assert.Equal(ConsoleSettings.ThemeLight, ConsoleSettings.Parse("{ \"Theme\": \"solarizeddark\" }").Theme);
        }

        [Fact]
        public void Log_pane_settings_are_kept_in_range()
        {
            var s = ConsoleSettings.Parse("{ \"ShowLog\": false, \"LogPercent\": 35 }");
            Assert.False(s.ShowLog);
            Assert.Equal(35, s.LogPercent);
            var bad = ConsoleSettings.Parse("{ \"ShowLog\": \"no\", \"LogPercent\": 95 }");
            Assert.True(bad.ShowLog);
            Assert.Equal(22, bad.LogPercent);
            Assert.Equal(22, ConsoleSettings.Parse("{ \"LogPercent\": 5 }").LogPercent);
        }

        [Fact]
        public void The_update_check_at_start_is_off_by_default_and_runs_at_most_once_a_day()
        {
            var now = new System.DateTime(2026, 11, 20, 12, 0, 0, System.DateTimeKind.Utc);
            Assert.False(new ConsoleSettings().CheckUpdatesOnStart);
            Assert.False(new ConsoleSettings().UpdateCheckDue(now));

            var s = ConsoleSettings.Parse("{ \"CheckUpdatesOnStart\": true, \"LastUpdateCheckUtc\": \"2026-11-19 13:00:00\" }");
            Assert.True(s.CheckUpdatesOnStart);
            Assert.Equal("2026-11-19 13:00:00", s.LastUpdateCheckUtc);
            Assert.False(s.UpdateCheckDue(now));                    // 23 hours ago
            Assert.True(s.UpdateCheckDue(now.AddHours(1)));         // 24 hours ago
            s.LastUpdateCheckUtc = "2026-11-21 08:00:00";
            Assert.True(s.UpdateCheckDue(now));                     // dated in the future: the clock moved back
            s.LastUpdateCheckUtc = "";
            Assert.True(s.UpdateCheckDue(now));                     // never checked

            var bad = ConsoleSettings.Parse("{ \"CheckUpdatesOnStart\": \"yes\", \"LastUpdateCheckUtc\": \"yesterday\" }");
            Assert.False(bad.CheckUpdatesOnStart);
            Assert.Equal("", bad.LastUpdateCheckUtc);
        }

        [Fact]
        public void Recent_cases_are_most_recent_first_once_and_capped()
        {
            var s = new ConsoleSettings { RecentCount = 2 };
            s.AddRecent(@"D:\Cases\A");
            s.AddRecent(@"D:\Cases\B");
            s.AddRecent(@"d:\cases\a");
            s.AddRecent(@"D:\Cases\C");
            s.AddRecent("relative");
            Assert.Equal(new[] { @"D:\Cases\C", @"d:\cases\a" }, s.RecentCases);
        }

        [Fact]
        public void Settings_round_trip_through_the_file()
        {
            using (var t = new TempDir())
            {
                var path = t.File(@"Foton\console-settings.json");
                var s = new ConsoleSettings { Examiner = "Examiner A", OpenOnStart = ConsoleSettings.StartOnLastCase, HandoffsOutput = @"E:\Handoffs", BundlesOutput = @"E:\Bundles", Theme = ConsoleSettings.ThemeWindows, TextSize = 11, CheckUpdatesOnStart = true, LastUpdateCheckUtc = "2026-11-19 13:00:00" };
                s.CaseFolders.Add(@"D:\More");
                s.AddRecent(@"D:\Cases\Foton_A");
                Assert.True(s.Save(out _, path));
                Assert.Equal(s.ToJson(), ConsoleSettings.Load(path).ToJson());
                Assert.Equal(@"E:\Bundles", ConsoleSettings.Load(path).BundlesFolder);
                Assert.Equal(new ConsoleSettings().ToJson(), ConsoleSettings.Load(t.File("missing.json")).ToJson());
            }
        }
    }
}
