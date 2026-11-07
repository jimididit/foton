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
    /// <summary>One pinned release in the catalog: where it comes from and the SHA-256 it must hash to.</summary>
    public sealed class CatalogTool
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string AssetName { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string ExpectedSha256 { get; set; } = "";
        public string License { get; set; } = "";
        public string ProjectUrl { get; set; } = "";
        public IReadOnlyList<string> ExecutableNames { get; set; } = new string[0];
        public string RulesRelativePath { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    /// <summary>
    /// The pinned external-tool catalog (Get-FotonToolCatalog). Shipped inside foton.exe, so a pin changes only
    /// with a Foton release. To pin a new tool or version, edit Resources\FotonToolCatalog.json.
    /// </summary>
    public static class ToolCatalog
    {
        /// <summary>The embedded catalog, or a JSON file (tests).</summary>
        public static IReadOnlyList<CatalogTool> Load(string? catalogPath = null)
        {
            string text, source;
            if (catalogPath != null)
            {
                if (!File.Exists(catalogPath)) throw new FileNotFoundException("Catalog not found: " + catalogPath, catalogPath);
                text = File.ReadAllText(catalogPath, Encoding.UTF8);
                source = catalogPath;
            }
            else
            {
                using (var s = typeof(ToolCatalog).Assembly.GetManifestResourceStream("Foton.Tools.FotonToolCatalog.json"))
                using (var r = new StreamReader(s ?? throw new InvalidOperationException("Embedded tool catalog missing."), Encoding.UTF8))
                    text = r.ReadToEnd();
                source = "embedded catalog";
            }
            var tools = Json.Parse(text) is IDictionary root && root.Contains("Tools") ? root["Tools"] : null;
            var rows = tools is IDictionary one ? new object[] { one } : (tools as IEnumerable)?.Cast<object?>().ToArray();
            if (rows == null || rows.Length == 0) throw new InvalidDataException("Catalog has no Tools array: " + source);
            return rows.OfType<IDictionary>().Select(d => new CatalogTool
            {
                Name = Str(d, "Name"),
                Version = Str(d, "Version"),
                AssetName = Str(d, "AssetName"),
                DownloadUrl = Str(d, "DownloadUrl"),
                ExpectedSha256 = Str(d, "ExpectedSha256"),
                License = Str(d, "License"),
                ProjectUrl = Str(d, "ProjectUrl"),
                ExecutableNames = Strings(d, "ExecutableNames"),
                RulesRelativePath = Str(d, "RulesRelativePath"),
                Notes = Str(d, "Notes"),
            }).ToList();
        }

        public static CatalogTool Entry(string name, string? catalogPath = null)
        {
            var all = Load(catalogPath);
            var want = name.Trim();
            return all.FirstOrDefault(t => string.Equals(t.Name, want, StringComparison.OrdinalIgnoreCase))
                ?? throw new ArgumentException($"Tool '{name}' is not in the Foton catalog. Supported: {string.Join(", ", all.Select(t => t.Name))}");
        }

        internal static string Str(IDictionary d, string key) =>
            d.Contains(key) && d[key] != null ? Convert.ToString(d[key], CultureInfo.InvariantCulture) ?? "" : "";

        static IReadOnlyList<string> Strings(IDictionary d, string key)
        {
            if (!d.Contains(key) || d[key] == null) return new string[0];
            if (d[key] is string s) return new[] { s };
            return ((IEnumerable)d[key]!).Cast<object?>().Select(x => Convert.ToString(x, CultureInfo.InvariantCulture) ?? "").ToList();
        }
    }
}
