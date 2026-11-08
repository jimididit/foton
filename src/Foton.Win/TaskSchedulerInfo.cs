using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Foton.Win
{
    public sealed class TaskRunInfo
    {
        public DateTime? LastRunUtc { get; set; }
        public uint LastResult { get; set; }
        public DateTime? NextRunUtc { get; set; }
    }

    /// <summary>
    /// Last and next run times of every scheduled task the token can see, from the Task Scheduler service
    /// (Schedule.Service, late-bound). Get-ScheduledTaskInfo answered the same through one WMI method call per task.
    /// Keyed by full task path (\Folder\Name); hidden tasks included.
    /// </summary>
    public static class TaskSchedulerInfo
    {
        const int EnumHidden = 1;

        public static Dictionary<string, TaskRunInfo> All()
        {
            var map = new Dictionary<string, TaskRunInfo>(StringComparer.OrdinalIgnoreCase);
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
            var service = Activator.CreateInstance(type)!;
            try
            {
                Call(service, "Connect");
                var root = Call(service, "GetFolder", @"\")!;
                Walk(root, map, 0);
            }
            finally { Marshal.ReleaseComObject(service); }
            return map;
        }

        static void Walk(object folder, Dictionary<string, TaskRunInfo> map, int depth)
        {
            try
            {
                if (depth > 32) return;
                var tasks = Call(folder, "GetTasks", EnumHidden)!;
                try
                {
                    int count = Convert.ToInt32(Get(tasks, "Count"));
                    for (int i = 1; i <= count; i++)
                    {
                        object? task = null;
                        try
                        {
                            task = Get(tasks, "Item", i)!;
                            var info = new TaskRunInfo
                            {
                                LastRunUtc = Time(Get(task, "LastRunTime")),
                                LastResult = unchecked((uint)Convert.ToInt32(Get(task, "LastTaskResult"))),
                                NextRunUtc = Time(Get(task, "NextRunTime")),
                            };
                            map[(string)Get(task, "Path")!] = info;
                        }
                        catch (Exception ex) when (ex is TargetInvocationException || ex is COMException || ex is InvalidCastException) { }
                        finally { if (task != null) Marshal.ReleaseComObject(task); }
                    }
                }
                finally { Marshal.ReleaseComObject(tasks); }

                var subs = Call(folder, "GetFolders", 0)!;
                try
                {
                    int count = Convert.ToInt32(Get(subs, "Count"));
                    for (int i = 1; i <= count; i++)
                    {
                        var sub = Get(subs, "Item", i)!;
                        try { Walk(sub, map, depth + 1); }
                        finally { Marshal.ReleaseComObject(sub); }
                    }
                }
                finally { Marshal.ReleaseComObject(subs); }
            }
            // A folder this token cannot open: its tasks were not listed by Get-ScheduledTask either.
            catch (Exception ex) when (ex is TargetInvocationException || ex is COMException || ex is UnauthorizedAccessException) { }
        }

        /// <summary>The scheduler reports "never" as the OLE zero date (1899-12-30).</summary>
        static DateTime? Time(object? v) => v is DateTime t && t.Year > 1900 ? t.ToUniversalTime() : (DateTime?)null;

        static object? Call(object target, string method, params object[] args) =>
            target.GetType().InvokeMember(method, BindingFlags.InvokeMethod, null, target, args);

        static object? Get(object target, string property, params object[] args) =>
            target.GetType().InvokeMember(property, BindingFlags.GetProperty, null, target, args);
    }
}
