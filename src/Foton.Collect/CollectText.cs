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

        /// <summary>How a WMI read fails: provider errors, access denied, or a COM failure in the WMI service.</summary>
        public static bool WmiFailed(Exception ex) => ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException;

        /// <summary>First instance, or null when the query fails (a class the token cannot read is not an error for optional facts).</summary>
        public static ManagementBaseObject? TryFirst(string ns, string wql)
        {
            try { return First(ns, wql); }
            catch (Exception ex) when (WmiFailed(ex)) { return null; }
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
