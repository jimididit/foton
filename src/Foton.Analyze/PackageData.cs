using System;
using System.Collections.Generic;
using System.Linq;
using Foton.Core;
using Foton.Package;

namespace Foton.Analyze
{
    /// <summary>
    /// Collected artifacts by name, typed as 1.38.x Import-FotonPackageData loaded them: CSV rows with cells that
    /// are exactly "True"/"False" turned into booleans, JSON as parsed (numbers, booleans, objects, arrays), TXT as
    /// lines. Names are case-insensitive, as the PowerShell hashtable was.
    /// </summary>
    public sealed class PackageData
    {
        readonly Dictionary<string, object?> _data = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        public object? this[string name] => _data.TryGetValue(name, out var v) ? v : null;
        public bool Contains(string name) => _data.ContainsKey(name);
        public IEnumerable<string> Names => _data.Keys;
        public void Set(string name, object? value) => _data[name] = value;

        public static PackageData From(FotonPackage pkg)
        {
            var d = new PackageData();
            foreach (var a in pkg.Artifacts.Values)
            {
                switch (a.Kind)
                {
                    case ArtifactKind.Json: d.Set(a.Name, FromJson(a.Json)); break;
                    case ArtifactKind.Csv: d.Set(a.Name, a.Rows.Select(r => (object?)CsvRow(r)).ToArray()); break;
                    default: d.Set(a.Name, a.Lines.Cast<object?>().ToArray()); break;
                }
            }
            return d;
        }

        /// <summary>Import-Csv row with Convert-FotonCsvBooleans: only exactly "True"/"False" (case-sensitive) become bool.</summary>
        public static PsRow CsvRow(IReadOnlyDictionary<string, string?> row)
        {
            var r = new PsRow();
            foreach (var kv in row)
                r.Set(kv.Key, kv.Value == "True" ? true : kv.Value == "False" ? (object?)false : kv.Value);
            return r;
        }

        public static PsRow CsvRow(Dictionary<string, string?> row) => CsvRow((IReadOnlyDictionary<string, string?>)row);

        /// <summary>ConvertFrom-Json shape: objects become PsRow, arrays object?[], scalars unchanged.</summary>
        public static object? FromJson(object? node)
        {
            switch (node)
            {
                case Dictionary<string, object> o:
                    var r = new PsRow();
                    foreach (var kv in o) r.Set(kv.Key, FromJson(kv.Value));
                    return r;
                case object[] a: return a.Select(FromJson).ToArray();
                case System.Collections.ArrayList l: return l.Cast<object>().Select(FromJson).ToArray();
                default: return node;
            }
        }
    }
}
