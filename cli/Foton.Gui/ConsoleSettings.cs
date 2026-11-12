using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;

namespace Foton.Gui
{
    /// <summary>
    /// The console's own settings in %LOCALAPPDATA%\Foton\console-settings.json: today, the extra folders the Cases tab
    /// lists. A missing or damaged file means no extra folders; nothing here is evidence or goes into a package.
    /// </summary>
    sealed class ConsoleSettings
    {
        const long MaxBytes = 256 * 1024;
        public List<string> CaseFolders { get; } = new List<string>();

        static string FilePath()
        {
            var baseDir = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(baseDir)) baseDir = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? "", "AppData", "Local");
            return Path.Combine(baseDir, "Foton", "console-settings.json");
        }

        public static ConsoleSettings Load()
        {
            var s = new ConsoleSettings();
            try
            {
                var path = FilePath();
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxBytes) return s;
                if (Json.Parse(File.ReadAllText(path, Encoding.UTF8).TrimStart('\uFEFF')) is IDictionary d && d.Contains("CaseFolders") && d["CaseFolders"] is IEnumerable list)
                    foreach (var f in list.OfType<string>().Where(f => f.Trim().Length > 0))
                        if (!s.CaseFolders.Contains(f.Trim(), StringComparer.OrdinalIgnoreCase)) s.CaseFolders.Add(f.Trim());
            }
            // Anything wrong with the file (unreadable, not JSON, nested too deep, wrong types) means no extra folders.
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is InvalidOperationException
                || ex is NotSupportedException || ex is System.Security.SecurityException || ex is FormatException || ex is InvalidCastException) { }
            return s;
        }

        /// <summary>Writes the settings; false (and the reason) when the file cannot be written.</summary>
        public bool Save(out string? problem)
        {
            problem = null;
            try
            {
                var path = FilePath();
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                TextFile.Write(path, Json.Indented(new Dictionary<string, object?> { ["CaseFolders"] = CaseFolders }));
                return true;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                problem = ex.Message;
                return false;
            }
        }
    }
}
