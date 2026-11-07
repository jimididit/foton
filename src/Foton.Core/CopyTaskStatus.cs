using System.Collections;
using System.Linq;

namespace Foton.Core
{
    /// <summary>
    /// Task status from per-file copy rows. Only CopyError / SaveError count as failures: CappedSkip,
    /// Missing, NotCollectedByDesign, and SupersededBySave are recorded outcomes. Rows that are not copy
    /// rows (a PnP device whose Status is Error) are ignored. Rows prove a task ran, not that it captured
    /// anything: on a real host every hive copy failed "in use" while the task was still logged Good.
    /// </summary>
    public static class CopyTaskStatus
    {
        public sealed class Result
        {
            public string Status { get; }
            public string Message { get; }
            public Result(string status, string message) { Status = status; Message = message; }
        }

        static readonly Result Ok = new Result(TaskStatus.Success, "");

        public static Result Evaluate(object? data)
        {
            if (!(data is IEnumerable e) || data is string) return Ok;
            var rows = e.OfType<ICopyRow>().ToList();
            if (rows.Count == 0) return Ok;
            var failed = rows.Where(r => r.Status == "CopyError" || r.Status == "SaveError").ToList();
            if (failed.Count == 0) return Ok;
            bool anyOk = rows.Any(r => r.Status == "Copied" || r.Status == "Saved");
            var msg = string.Format("{0} of {1} file(s) not captured. First: {2} - {3}",
                failed.Count, rows.Count, failed[0].SourcePath, failed[0].Note);
            return new Result(anyOk ? TaskStatus.Partial : TaskStatus.Failed, msg);
        }
    }
}
