using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Foton.Core
{
    /// <summary>
    /// CSV the way "Export-Csv -NoTypeInformation -Encoding UTF8" wrote it in 1.38.x, so existing
    /// readers and spreadsheets see no difference: UTF-8 BOM, CRLF rows, every value quoted with
    /// quotes doubled, embedded newlines kept, and a null value written as nothing (,,) while an
    /// empty string is "". Columns come from the first row, as Export-Csv does.
    /// </summary>
    public static class Csv
    {
        public static void Write(string path, IEnumerable rows)
        {
            var list = rows.Cast<object?>().Where(r => r != null).ToList();
            using (var w = new StreamWriter(path, false, TextFile.Utf8Bom))
            {
                if (list.Count == 0) return;
                var columns = Columns(list[0]!);
                w.Write(string.Join(",", columns.Select(Quote)));
                w.Write("\r\n");
                foreach (var row in list)
                {
                    w.Write(string.Join(",", columns.Select(c => Field(Value(row!, c)))));
                    w.Write("\r\n");
                }
            }
        }

        /// <summary>Column names of a row: dictionary keys, or public properties in declaration order.</summary>
        public static IReadOnlyList<string> Columns(object row)
        {
            if (row is IDictionary<string, object?> d) return d.Keys.ToList();
            if (row is IDictionary<string, string> s) return s.Keys.ToList();
            return Properties(row.GetType()).Select(p => p.Name).ToList();
        }

        internal static IEnumerable<PropertyInfo> Properties(Type t) =>
            t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
             .Where(p => p.GetIndexParameters().Length == 0)
             .OrderBy(p => p.MetadataToken);

        static object? Value(object row, string column)
        {
            if (row is IDictionary<string, object?> d) return d.TryGetValue(column, out var v) ? v : null;
            if (row is IDictionary<string, string> s) return s.TryGetValue(column, out var sv) ? sv : null;
            return row.GetType().GetProperty(column)?.GetValue(row);
        }

        static string Field(object? v) => v == null ? "" : Quote(FormatValue(v));

        static string Quote(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";

        /// <summary>
        /// One cell: invariant culture, booleans as True/False, times as UTC yyyy-MM-dd HH:mm:ss,
        /// lists joined with "; " (1.38.x printed System.Object[] there, which carried no data).
        /// </summary>
        public static string FormatValue(object v)
        {
            switch (v)
            {
                case string s: return s;
                case bool b: return b ? "True" : "False";
                case DateTime t: return FotonTime.Format(t);
                case DateTimeOffset o: return FotonTime.Format(o.UtcDateTime);
                case IFormattable f: return f.ToString(null, CultureInfo.InvariantCulture);
                case IEnumerable e: return string.Join("; ", e.Cast<object?>().Select(x => x == null ? "" : FormatValue(x)));
                default: return v.ToString() ?? "";
            }
        }

        /// <summary>
        /// Rows as column-to-value maps (Import-Csv). Accepts a BOM, CRLF or LF, quoted newlines,
        /// and the "#TYPE" line older Export-Csv calls wrote. A short row leaves later columns null.
        /// </summary>
        public static List<Dictionary<string, string?>> Read(string path)
        {
            var text = File.ReadAllText(path, Encoding.UTF8);
            var records = Parse(text);
            var result = new List<Dictionary<string, string?>>();
            int start = 0;
            if (records.Count > 0 && records[0].Count == 1 && records[0][0].StartsWith("#TYPE", StringComparison.Ordinal)) start = 1;
            if (records.Count <= start) return result;
            var header = records[start];
            for (int i = start + 1; i < records.Count; i++)
            {
                var r = records[i];
                if (r.Count == 1 && r[0].Length == 0) continue; // blank line
                var row = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                for (int c = 0; c < header.Count; c++)
                    row[header[c]] = c < r.Count ? r[c] : null;
                result.Add(row);
            }
            return result;
        }

        static List<List<string>> Parse(string text)
        {
            var records = new List<List<string>>();
            var record = new List<string>();
            var field = new StringBuilder();
            bool quoted = false, any = false;
            for (int i = 0; i < text.Length; i++)
            {
                char ch = text[i];
                if (quoted)
                {
                    if (ch == '"')
                    {
                        if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                        else quoted = false;
                    }
                    else field.Append(ch);
                    continue;
                }
                switch (ch)
                {
                    case '"': quoted = true; any = true; break;
                    case ',': record.Add(field.ToString()); field.Clear(); any = true; break;
                    case '\r': break;
                    case '\n':
                        record.Add(field.ToString()); field.Clear();
                        records.Add(record); record = new List<string>(); any = false;
                        break;
                    default: field.Append(ch); any = true; break;
                }
            }
            if (any || field.Length > 0) { record.Add(field.ToString()); records.Add(record); }
            return records;
        }
    }
}
