using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Foton.Core
{
    /// <summary>
    /// Runs one collection task: writes the artifact, adds the manifest row, times it, captures errors,
    /// and caches the data (Invoke-FotonCollection). A failure is logged and never stops the run:
    /// partial collection is evidence.
    /// </summary>
    public static class TaskRunner
    {
        public sealed class TaskSpec
        {
            public string Category { get; set; } = "";
            public string Name { get; set; } = "";
            public string Description { get; set; } = "";
            public TaskFormat Format { get; set; } = TaskFormat.Json;
            public bool NoCache { get; set; }
            /// <summary>Skipped with SkippedNotElevated on a standard token: a visibility gap, not an error.</summary>
            public bool RequiresElevation { get; set; }
        }

        public static string SkippedText(string name) => string.Join("\r\n", new[]
        {
            "Foton: task '" + name + "' was not run.",
            "Status: SkippedNotElevated",
            SkippedReason,
            "This is a visibility gap. Do not treat a missing or empty artifact as proof the underlying data was absent on the host.",
        });

        public const string SkippedReason = "Requires an Administrator token; skipped in standard-user coverage.";

        public static string NoDataText(string name, string status, string error) =>
            "Foton: no data returned for '" + name + "'. Status: " + status + ". " + error;

        public static object? Run(FotonSession session, TaskSpec spec, Func<object?> script)
        {
            var dir = session.Dir(spec.Category);
            var leaf = spec.Name + "." + spec.Format.ToString().ToLowerInvariant();
            var file = Path.Combine(dir, leaf);
            var manifestFile = Path.Combine(CaseCategories.FolderOf(spec.Category), leaf);
            var sw = Stopwatch.StartNew();
            string status = TaskStatus.Success, error = "";
            object? data = null;
            int count = 0;

            if (spec.RequiresElevation && !session.IsElevated)
            {
                try { TextFile.Write(file, SkippedText(spec.Name)); } catch (Exception) { }
                sw.Stop();
                session.Manifest.Add(Row(spec, manifestFile, 0, TaskStatus.SkippedNotElevated, (int)sw.ElapsedMilliseconds, SkippedReason));
                if (!spec.NoCache) session.Data[spec.Name] = null;
                session.Status.Write(spec.Name + " - skipped (not elevated)", StatusLevel.Info);
                return null;
            }

            try { data = script(); }
            catch (Exception ex)
            {
                status = TaskStatus.Error;
                error = ex.Message;
                session.Errors.Add(new ErrorRow { Task = spec.Name, Error = error });
            }

            try
            {
                if (IsEmpty(data))
                {
                    if (status == TaskStatus.Success) status = TaskStatus.NoData;
                    TextFile.Write(file, NoDataText(spec.Name, status, error));
                }
                else
                {
                    count = Count(data!);
                    switch (spec.Format)
                    {
                        case TaskFormat.Json: TextFile.Write(file, Json.Indented(data)); break;
                        case TaskFormat.Csv: Csv.Write(file, data is IEnumerable e && !(data is string) ? e : new[] { data }); break;
                        case TaskFormat.Txt: TextFile.WriteLines(file, Lines(data!)); break;
                    }
                }
            }
            catch (Exception ex)
            {
                status = TaskStatus.WriteError;
                error = ex.Message;
                try { TextFile.Write(file, "Foton write error for '" + spec.Name + "': " + error); } catch (Exception) { }
            }
            sw.Stop();

            if (status == TaskStatus.Success)
            {
                var copy = CopyTaskStatus.Evaluate(data);
                if (copy.Status != TaskStatus.Success)
                {
                    status = copy.Status;
                    error = copy.Message;
                    session.Errors.Add(new ErrorRow { Task = spec.Name, Error = status + ": " + error });
                }
            }

            session.Manifest.Add(Row(spec, manifestFile, count, status, (int)sw.ElapsedMilliseconds, error));
            if (!spec.NoCache) session.Data[spec.Name] = data;

            var ms = (int)sw.ElapsedMilliseconds;
            switch (status)
            {
                case TaskStatus.Success: session.Status.Write($"{spec.Name} ({count} records, {ms} ms)", StatusLevel.Good); break;
                case TaskStatus.NoData: session.Status.Write($"{spec.Name} - no data returned", StatusLevel.Info); break;
                case TaskStatus.Partial: session.Status.Write($"{spec.Name} ({count} records) - Partial : {error}", StatusLevel.Warn); break;
                case TaskStatus.Failed: session.Status.Write($"{spec.Name} ({count} records) - Failed : {error}", StatusLevel.Warn); break;
                default: session.Status.Write($"{spec.Name} - {status} : {error}", StatusLevel.Warn); break;
            }
            return data;
        }

        static ManifestRow Row(TaskSpec s, string file, int records, string status, int ms, string error) => new ManifestRow
        {
            Category = s.Category, Task = s.Name, Description = s.Description, File = file,
            Records = records, Status = status, DurationMs = ms, Error = error,
        };

        static bool IsEmpty(object? data) =>
            data == null
            || (data is string s && s.Length == 0)
            || (data is IEnumerable e && !(data is string) && !(data is IDictionary) && !e.Cast<object?>().Any());

        /// <summary>Rows for a list; 1 for a single object or a dictionary (as @($data).Count).</summary>
        static int Count(object data) =>
            data is IEnumerable e && !(data is string) && !(data is IDictionary) ? e.Cast<object?>().Count() : 1;

        static string[] Lines(object data) =>
            data is string s ? s.Replace("\r\n", "\n").Split('\n')
            : data is IEnumerable e ? e.Cast<object?>().Select(x => x == null ? "" : Csv.FormatValue(x)).ToArray()
            : new[] { Csv.FormatValue(data) };
    }
}
