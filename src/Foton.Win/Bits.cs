using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;

[assembly: InternalsVisibleTo("Foton.Tests")]

namespace Foton.Win
{
    // COM interop declarations must list every vtable slot in bits.h order; unused slots are stubs.
    [ComImport, Guid("4991d34b-80a1-4291-83b6-3328366b9097")] class BackgroundCopyManager { }

    [ComImport, Guid("5ce34c0d-0dc9-4c1f-897c-daa1b78cee7c"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IBackgroundCopyManager
    {
        void CreateJob(); void GetJob();
        [PreserveSig] int EnumJobs(uint flags, out IEnumBackgroundCopyJobs jobs);
        void GetErrorDescription();
    }

    [ComImport, Guid("1af4f612-3b71-466f-8f58-7b6f73ac57ad"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IEnumBackgroundCopyJobs
    {
        [PreserveSig] int Next(uint celt, out IBackgroundCopyJob2 job, out uint fetched);
        void Skip(); void Reset(); void Clone(); void GetCount();
    }

    [ComImport, Guid("54b50739-686f-45eb-9dff-d6a9a0faa9af"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IBackgroundCopyJob2
    {
        void AddFileSet(); void AddFile(); void EnumFiles(); void Suspend(); void Resume(); void Cancel(); void Complete();
        void GetId(out Guid id);
        void GetJobType(out uint type);
        void GetProgress(); void GetTimes(); void GetState(); void GetError();
        void GetOwner([MarshalAs(UnmanagedType.LPWStr)] out string owner);
        void SetDisplayName();
        void GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        void SetDescription(); void GetDescription(); void SetPriority();
        void GetPriority(out uint priority);
        void SetNotifyFlags(); void GetNotifyFlags(); void SetNotifyInterface(); void GetNotifyInterface();
        void SetMinimumRetryDelay(); void GetMinimumRetryDelay(); void SetNoProgressTimeout(); void GetNoProgressTimeout();
        void GetErrorCount(); void SetProxySettings();
        void GetProxySettings(out uint usage, [MarshalAs(UnmanagedType.LPWStr)] out string list, [MarshalAs(UnmanagedType.LPWStr)] out string bypass);
        void TakeOwnership(); void SetNotifyCmdLine();
        void GetNotifyCmdLine([MarshalAs(UnmanagedType.LPWStr)] out string program, [MarshalAs(UnmanagedType.LPWStr)] out string parameters);
    }

    public sealed class BitsJobInfo
    {
        public string JobId { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string TransferType { get; set; } = "";
        public string OwnerAccount { get; set; } = "";
        public string Priority { get; set; } = "";
        public string ProxyUsage { get; set; } = "";
        /// <summary>Program and parameters, both empty when no notify command is set.</summary>
        public string NotifyProgram { get; set; } = "";
        public string NotifyParameters { get; set; } = "";
    }

    /// <summary>BITS jobs (all users when the token allows it, else the caller's own), never bytes or state.</summary>
    public static class Bits
    {
        static readonly string[] Types = { "Download", "Upload", "UploadReply" };
        static readonly string[] Priorities = { "Foreground", "High", "Normal", "Low" };
        static readonly string[] Proxies = { "SystemDefault", "NoProxy", "Override", "AutoDetect" };
        static string Name(string[] names, uint v) => v < names.Length ? names[v] : v.ToString();

        public static List<BitsJobInfo> Jobs()
        {
            var rows = new List<BitsJobInfo>();
            var mgr = (IBackgroundCopyManager)new BackgroundCopyManager();
            try
            {
                if (mgr.EnumJobs(1, out var e) != 0 && mgr.EnumJobs(0, out e) != 0)
                    throw new UnauthorizedAccessException("BITS EnumJobs failed for all users and for the current user.");
                try
                {
                    while (e.Next(1, out var job, out var fetched) == 0 && fetched == 1)
                    {
                        try { rows.Add(Read(job)); }
                        finally { Marshal.ReleaseComObject(job); }
                    }
                }
                finally { Marshal.ReleaseComObject(e); }
            }
            finally { Marshal.ReleaseComObject(mgr); }
            return rows;
        }

        static BitsJobInfo Read(IBackgroundCopyJob2 job)
        {
            var r = new BitsJobInfo();
            job.GetId(out var id); r.JobId = id.ToString();
            try { job.GetDisplayName(out var n); r.DisplayName = n ?? ""; } catch (COMException) { }
            try { job.GetJobType(out var t); r.TransferType = Name(Types, t); } catch (COMException) { }
            try { job.GetOwner(out var sid); r.OwnerAccount = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
            catch (Exception ex) when (ex is COMException || ex is IdentityNotMappedException || ex is ArgumentException) { }
            try { job.GetPriority(out var p); r.Priority = Name(Priorities, p); } catch (COMException) { }
            try { job.GetProxySettings(out var u, out _, out _); r.ProxyUsage = Name(Proxies, u); } catch (COMException) { }
            try { job.GetNotifyCmdLine(out var prog, out var args); r.NotifyProgram = prog ?? ""; r.NotifyParameters = args ?? ""; } catch (COMException) { }
            return r;
        }
    }
}
