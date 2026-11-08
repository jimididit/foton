using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect
{
    /// <summary>Shared helpers for collection tasks: one task call, WMI dates, and plain-text tables for TXT artifacts.</summary>
    static class CollectText
    {
        public static void Task(FotonSession s, string category, string name, string description, TaskFormat format, Func<object?> script, bool elevated = false) =>
            TaskRunner.Run(s, new TaskRunner.TaskSpec { Category = category, Name = name, Description = description, Format = format, RequiresElevation = elevated }, script);

        /// <summary>A WMI DMTF datetime as UTC yyyy-MM-dd HH:mm:ss; "" when absent or unparseable.</summary>
        public static string Dmtf(object? v)
        {
            var t = DmtfTime(v);
            return t.HasValue ? FotonTime.Format(t.Value) : "";
        }

        /// <summary>A WMI DMTF datetime in UTC; null when absent or malformed (host data is never trusted to parse).</summary>
        public static DateTime? DmtfTime(object? v)
        {
            if (!(v is string d) || d.Length == 0) return null;
            try { return ManagementDateTimeConverter.ToDateTime(d).ToUniversalTime(); }
            catch (Exception ex) when (ex is ArgumentException || ex is FormatException || ex is OverflowException) { return null; }
        }

        /// <summary>A WMI value, or null when the class does not define the property.</summary>
        public static object? Raw(ManagementBaseObject mo, string name)
        {
            var v = Wmi.Prop(mo, name);
            return v == Wmi.NotReported ? null : v;
        }

        public static ManagementBaseObject? First(string ns, string wql) => Wmi.Query(ns, wql).FirstOrDefault();

        static readonly System.Text.RegularExpressions.Regex[] UserWritablePatterns = PatternLists.UserWritable
            .Select(p => new System.Text.RegularExpressions.Regex(p, System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant)).ToArray();

        /// <summary>Test-FotonUserWritablePath: a location where system binaries rarely live. A lead, not proof of a dropper.</summary>
        public static bool UserWritable(string? path) => !string.IsNullOrWhiteSpace(path) && UserWritablePatterns.Any(r => r.IsMatch(path!));

        /// <summary>A value for a single-quoted WQL string literal (backslash and quote escaped).</summary>
        public static string WqlString(string v) => v.Replace("\\", "\\\\").Replace("'", "\\'");

        /// <summary>How a WMI read fails: provider errors, access denied, or a COM failure in the WMI service.</summary>
        public static bool WmiFailed(Exception ex) => ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException;

        /// <summary>First instance, or null when the query fails (a class the token cannot read is not an error for optional facts).</summary>
        public static ManagementBaseObject? TryFirst(string ns, string wql)
        {
            try { return First(ns, wql); }
            catch (Exception ex) when (WmiFailed(ex)) { return null; }
        }

        /// <summary>Every property of a WMI instance as "Name : Value" lines (Format-List); arrays as {a, b}.</summary>
        public static IEnumerable<string> PropertyList(ManagementBaseObject o)
        {
            var props = o.Properties.Cast<PropertyData>().ToList();
            int width = props.Count == 0 ? 0 : props.Max(p => p.Name.Length);
            yield return "";
            foreach (var p in props)
            {
                var v = p.Value;
                var text = v is Array a && !(v is string)
                    ? "{" + string.Join(", ", a.Cast<object?>().Select(x => Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture))) + "}"
                    : Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "";
                yield return p.Name.PadRight(width) + " : " + TextFile.OneLine(text);
            }
            yield return "";
        }

        /// <summary>PowerShell truthiness for a registry value: null, "", 0, and empty arrays are false.</summary>
        public static bool Truthy(object? v)
        {
            switch (v)
            {
                case null: return false;
                case string s: return s.Length > 0;
                case Array a: return a.Length > 1 || (a.Length == 1 && Truthy(a.GetValue(0)));
                case byte _: case sbyte _: case short _: case ushort _: case int _: case uint _: case long _: case ulong _: case double _: case float _:
                    return Convert.ToDouble(v, System.Globalization.CultureInfo.InvariantCulture) != 0;
                default: return true;
            }
        }

        /// <summary>A left-aligned text table (header, dashes, rows), in place of the PowerShell formatter's tables in TXT artifacts.</summary>
        public static IEnumerable<string> Table(IReadOnlyList<string> columns, IEnumerable<IReadOnlyList<string>> rows)
        {
            // Each row is fitted to the columns: extra cells are dropped, missing cells are blank.
            var data = rows.Select(r => columns.Select((_, i) => i < r.Count ? TextFile.OneLine(r[i]) : "").ToArray()).ToList();
            var width = columns.Select((c, i) => Math.Max(c.Length, data.Count == 0 ? 0 : data.Max(r => i < r.Length ? r[i].Length : 0))).ToArray();
            string Line(IReadOnlyList<string> cells) => string.Join(" ", cells.Select((c, i) => i == cells.Count - 1 ? c : c.PadRight(width[i]))).TrimEnd();
            yield return "";
            yield return Line(columns);
            yield return Line(width.Select(w => new string('-', w)).ToArray());
            foreach (var r in data) yield return Line(r);
            yield return "";
        }
    }
}
