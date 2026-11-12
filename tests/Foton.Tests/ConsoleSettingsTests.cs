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
            Assert.Equal(ConsoleSettings.ThemeDark, s.Theme);
            Assert.Equal(9, s.TextSize);

            Assert.Equal(new ConsoleSettings().ToJson(), ConsoleSettings.Parse("{ not json").ToJson());
            Assert.Equal(new ConsoleSettings().ToJson(), ConsoleSettings.Parse("[1,2]").ToJson());
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
                var s = new ConsoleSettings { Examiner = "Examiner A", OpenOnStart = ConsoleSettings.StartOnLastCase, HandoffsOutput = @"E:\Handoffs", Theme = ConsoleSettings.ThemeWindows, TextSize = 11 };
                s.CaseFolders.Add(@"D:\More");
                s.AddRecent(@"D:\Cases\Foton_A");
                Assert.True(s.Save(out _, path));
                Assert.Equal(s.ToJson(), ConsoleSettings.Load(path).ToJson());
                Assert.Equal(new ConsoleSettings().ToJson(), ConsoleSettings.Load(t.File("missing.json")).ToJson());
            }
        }
    }
}
