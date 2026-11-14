using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;

namespace Foton.Tools
{
    /// <summary>
    /// foton-console's own settings in %LOCALAPPDATA%\Foton\console-settings.json. Nothing here is evidence or goes
    /// into a package. Each key is read on its own: a missing, damaged, or out-of-range value falls back to its
    /// default and never stops the console or costs the other settings. To add a setting, add a property with its
    /// default, read it in Parse with its check, and write it in ToJson.
    /// </summary>
    public sealed class ConsoleSettings
    {
        const long MaxBytes = 256 * 1024;
        const int MaxText = 200, MaxPath = 260, MaxFolders = 50;
        public const int MaxRecent = 20;
        public const string StartOnCases = "Cases", StartOnLastCase = "LastCase";
        public const string ThemeLight = "Light", ThemeDark = "Dark", ThemeWindows = "Windows";
        public const string ThemeCampbell = "Campbell", ThemeSolarizedDark = "SolarizedDark", ThemeSolarizedLight = "SolarizedLight";
        /// <summary>Every theme, in the order the console offers them (Windows: follow Windows' light or dark app setting).</summary>
        public static readonly string[] Themes = { ThemeLight, ThemeDark, ThemeCampbell, ThemeSolarizedDark, ThemeSolarizedLight, ThemeWindows };
        public static readonly int[] TextSizes = { 9, 10, 11, 12 };

        /// <summary>Folders the Cases tab lists besides the case and baseline output folders.</summary>
        public List<string> CaseFolders { get; } = new List<string>();
        /// <summary>The examiner name filled in for collections and notes ("" uses the case's or the account's).</summary>
        public string Examiner { get; set; } = "";
        public string OpenOnStart { get; set; } = StartOnCases;
        public int RecentCount { get; set; } = 8;
        /// <summary>Package paths opened, most recent first.</summary>
        public List<string> RecentCases { get; } = new List<string>();
        /// <summary>Output folders ("" means the standard C:\Foton\... folder).</summary>
        public string CasesOutput { get; set; } = "";
        public string BaselinesOutput { get; set; } = "";
        public string HandoffsOutput { get; set; } = "";
        public string BundlesOutput { get; set; } = "";
        public string Theme { get; set; } = ThemeLight;
        /// <summary>Font size in points.</summary>
        public int TextSize { get; set; } = 9;
        /// <summary>Whether the log pane under the tabs is shown, and its share of the window height in percent.</summary>
        public bool ShowLog { get; set; } = true;
        public int LogPercent { get; set; } = 22;
        public const int MinLogPercent = 10, MaxLogPercent = 60;
        /// <summary>Opt-in: check GitHub for a signed update when the console starts, at most once a day. Off by default.</summary>
        public bool CheckUpdatesOnStart { get; set; }
        /// <summary>UTC time (yyyy-MM-dd HH:mm:ss) of the last update check that reached GitHub; "" before the first.</summary>
        public string LastUpdateCheckUtc { get; set; } = "";

        /// <summary>
        /// True when the opt-in startup check should run: on, and no check reached GitHub in the last 24 hours. A last
        /// check dated in the future (the clock moved back) counts as due, so a wrong clock cannot silence it.
        /// </summary>
        public bool UpdateCheckDue(DateTime utcNow)
        {
            if (!CheckUpdatesOnStart) return false;
            if (!DateTime.TryParseExact(LastUpdateCheckUtc, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var last)) return true;
            return last > utcNow || utcNow - last >= TimeSpan.FromHours(24);
        }

        public string CasesFolder => CasesOutput.Length > 0 ? CasesOutput : CaseTree.DefaultOutput("Cases");
        public string BaselinesFolder => BaselinesOutput.Length > 0 ? BaselinesOutput : CaseTree.DefaultOutput("Baselines");
        public string HandoffsFolder => HandoffsOutput.Length > 0 ? HandoffsOutput : CaseTree.DefaultOutput("Handoffs");
        public string BundlesFolder => BundlesOutput.Length > 0 ? BundlesOutput : CaseTree.DefaultOutput("Bundles");

        public static string DefaultPath()
        {
            var baseDir = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(baseDir)) baseDir = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? "", "AppData", "Local");
            return Path.Combine(baseDir, "Foton", "console-settings.json");
        }

        /// <summary>The settings in the file; defaults when it is missing, too large, or unreadable.</summary>
        public static ConsoleSettings Load(string? path = null)
        {
            try
            {
                var info = new FileInfo(path ?? DefaultPath());
                if (!info.Exists || info.Length > MaxBytes) return new ConsoleSettings();
                return Parse(File.ReadAllText(info.FullName, Encoding.UTF8));
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException
                || ex is System.Security.SecurityException) { return new ConsoleSettings(); }
        }

        /// <summary>Settings from JSON, key by key; anything not usable keeps its default.</summary>
        public static ConsoleSettings Parse(string json)
        {
            var s = new ConsoleSettings();
            IDictionary? d;
            try { d = Json.Parse(json.TrimStart('\uFEFF')) as IDictionary; }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException || ex is FormatException || ex is InvalidCastException) { return s; }
            if (d == null) return s;
            object? V(string key) => d.Contains(key) ? d[key] : null;

            foreach (var f in Paths(V("CaseFolders"), MaxFolders))
                if (!s.CaseFolders.Contains(f, StringComparer.OrdinalIgnoreCase)) s.CaseFolders.Add(f);
            s.Examiner = Text(V("Examiner"), MaxText) ?? "";
            if (V("OpenOnStart") is string start && (start == StartOnCases || start == StartOnLastCase)) s.OpenOnStart = start;
            if (V("RecentCount") is int n && n >= 0 && n <= MaxRecent) s.RecentCount = n;
            foreach (var r in Paths(V("RecentCases"), s.RecentCount))
                if (!s.RecentCases.Contains(r, StringComparer.OrdinalIgnoreCase)) s.RecentCases.Add(r);
            s.CasesOutput = FullPath(V("CasesOutput")) ?? "";
            s.BaselinesOutput = FullPath(V("BaselinesOutput")) ?? "";
            s.HandoffsOutput = FullPath(V("HandoffsOutput")) ?? "";
            s.BundlesOutput = FullPath(V("BundlesOutput")) ?? "";
            if (V("Theme") is string theme && Array.IndexOf(Themes, theme) >= 0) s.Theme = theme;
            if (V("TextSize") is int size && TextSizes.Contains(size)) s.TextSize = size;
            if (V("ShowLog") is bool show) s.ShowLog = show;
            if (V("LogPercent") is int log && log >= MinLogPercent && log <= MaxLogPercent) s.LogPercent = log;
            if (V("CheckUpdatesOnStart") is bool check) s.CheckUpdatesOnStart = check;
            if (V("LastUpdateCheckUtc") is string lastCheck && DateTime.TryParseExact(lastCheck, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out _))
                s.LastUpdateCheckUtc = lastCheck;
            return s;
        }

        /// <summary>One line of text, trimmed, at most max characters; null when not a string.</summary>
        static string? Text(object? value, int max)
        {
            if (!(value is string t)) return null;
            t = TextFile.OneLine(t).Trim();
            return t.Length > max ? t.Substring(0, max) : t;
        }

        /// <summary>A full local or UNC path (drive or \\server\share), or null: a relative path would resolve against wherever the console started.</summary>
        public static string? FullPath(object? value)
        {
            var t = Text(value, MaxPath + 1);
            if (string.IsNullOrEmpty(t) || t!.Length > MaxPath || t.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
            if (!(t.Length >= 3 && char.IsLetter(t[0]) && t[1] == ':' && (t[2] == '\\' || t[2] == '/')) && !t.StartsWith(@"\\", StringComparison.Ordinal)) return null;
            try { return Path.GetFullPath(t); }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException || ex is System.Security.SecurityException) { return null; }
        }

        static IEnumerable<string> Paths(object? value, int max)
        {
            if (!(value is IEnumerable list) || value is string) yield break;
            int n = 0;
            foreach (var item in list)
            {
                if (n >= max) yield break;
                var p = FullPath(item);
                if (p != null) { n++; yield return p; }
            }
        }

        /// <summary>Puts a package path first in the recent list (once), trimmed to RecentCount.</summary>
        public void AddRecent(string path)
        {
            var p = FullPath(path);
            if (p == null) return;
            RecentCases.RemoveAll(r => string.Equals(r, p, StringComparison.OrdinalIgnoreCase));
            RecentCases.Insert(0, p);
            TrimRecent();
        }

        public void TrimRecent()
        {
            if (RecentCases.Count > RecentCount) RecentCases.RemoveRange(RecentCount, RecentCases.Count - RecentCount);
        }

        public string ToJson() => Json.Indented(new Dictionary<string, object?>
        {
            ["Examiner"] = Examiner, ["OpenOnStart"] = OpenOnStart, ["RecentCount"] = RecentCount, ["RecentCases"] = RecentCases,
            ["CaseFolders"] = CaseFolders, ["CasesOutput"] = CasesOutput, ["BaselinesOutput"] = BaselinesOutput, ["HandoffsOutput"] = HandoffsOutput, ["BundlesOutput"] = BundlesOutput,
            ["Theme"] = Theme, ["TextSize"] = TextSize, ["ShowLog"] = ShowLog, ["LogPercent"] = LogPercent,
            ["CheckUpdatesOnStart"] = CheckUpdatesOnStart, ["LastUpdateCheckUtc"] = LastUpdateCheckUtc,
        });

        /// <summary>Writes the settings; false (and the reason) when the file cannot be written.</summary>
        public bool Save(out string? problem, string? path = null)
        {
            problem = null;
            try
            {
                var file = path ?? DefaultPath();
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                TextFile.Write(file, ToJson());
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
            {
                problem = ex.Message;
                return false;
            }
        }
    }
}
