using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;

namespace Foton.Tools
{
    /// <summary>
    /// tools.json under the Foton tool root (Get-FotonToolRoot / Save-FotonToolManifestEntry): every pinned install
    /// and registered folder, so compose finds tools without PATH changes. Same file and shape as 1.38.x, so either
    /// version reads the other's registrations. Rows are kept as maps, so fields this version does not know survive
    /// a rewrite.
    /// </summary>
    public static class ToolManifest
    {
        public const string FileName = "tools.json";

        /// <summary>%LOCALAPPDATA%\Foton\tools unless overridden. Not PATH, not inside a case.</summary>
        public static string Root(string? toolRoot)
        {
            if (!string.IsNullOrWhiteSpace(toolRoot)) return Path.GetFullPath(toolRoot!.Trim());
            var baseDir = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(baseDir))
                baseDir = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? "", "AppData", "Local");
            return Path.GetFullPath(Path.Combine(baseDir, "Foton", "tools"));
        }

        public static string PathOf(string? toolRoot) => Path.Combine(Root(toolRoot), FileName);

        /// <summary>Every row; empty when the file is missing or unreadable.</summary>
        public static IReadOnlyList<Dictionary<string, object?>> List(string? toolRoot)
        {
            var path = PathOf(toolRoot);
            if (!File.Exists(path)) return new Dictionary<string, object?>[0];
            try { return Rows(Json.Parse(File.ReadAllText(path, Encoding.UTF8))); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is InvalidOperationException)
            {
                return new Dictionary<string, object?>[0];
            }
        }

        public static Dictionary<string, object?>? Find(string name, string? toolRoot)
        {
            var want = name.Trim();
            return List(toolRoot).FirstOrDefault(r => string.Equals(Get(r, "Name"), want, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Upserts one row by Name and rewrites the file. Returns the manifest path.</summary>
        public static string Save(string? toolRoot, Dictionary<string, object?> entry)
        {
            var root = Root(toolRoot);
            Directory.CreateDirectory(root);
            var path = Path.Combine(root, FileName);
            var rows = List(root).Where(r => !string.Equals(Get(r, "Name"), Get(entry, "Name"), StringComparison.OrdinalIgnoreCase)).ToList();
            rows.Add(entry);
            var doc = new Dictionary<string, object?>
            {
                ["ToolRoot"] = root,
                ["UpdatedUtc"] = FotonTime.Format(DateTime.UtcNow),
                ["Installed"] = rows,
            };
            TextFile.Write(path, Json.Indented(doc));
            return path;
        }

        /// <summary>A field as text; "" when absent.</summary>
        public static string Get(IDictionary<string, object?> row, string key) =>
            row.TryGetValue(key, out var v) && v != null ? Csv.FormatValue(v) : "";

        static IReadOnlyList<Dictionary<string, object?>> Rows(object? doc)
        {
            var installed = doc is IDictionary d && d.Contains("Installed") ? d["Installed"] : null;
            var items = installed is IDictionary one ? new object[] { one } : (installed as IEnumerable)?.Cast<object?>() ?? Enumerable.Empty<object?>();
            return items.OfType<IDictionary>().Select(r =>
            {
                var row = new Dictionary<string, object?>();
                foreach (DictionaryEntry kv in r) row[Convert.ToString(kv.Key, System.Globalization.CultureInfo.InvariantCulture) ?? ""] = kv.Value;
                return row;
            }).ToList();
        }
    }
}
