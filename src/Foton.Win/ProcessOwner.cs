using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Foton.Win
{
    /// <summary>
    /// The account a process runs as, read from its access token (the user SID, translated once per SID). Win32_Process
    /// GetOwner gave the same answer through WMI at about 2.5 seconds per process on the dev host, which made 1.38.x
    /// running_processes take a quarter of an hour. "" when the token cannot be opened with this token's rights.
    /// </summary>
    public sealed class ProcessOwner
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returned);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);

        const uint ProcessQueryLimitedInformation = 0x1000, TokenQuery = 0x0008;
        const int TokenUser = 1;

        readonly Dictionary<string, string> _names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>DOMAIN\user for a process, or "" when it cannot be read.</summary>
        public string Of(int pid)
        {
            var sid = Sid(pid);
            if (sid == null) return "";
            if (_names.TryGetValue(sid.Value, out var cached)) return cached;
            string name;
            try { name = ((NTAccount)sid.Translate(typeof(NTAccount))).Value; }
            catch (Exception ex) when (ex is IdentityNotMappedException || ex is SystemException) { name = sid.Value; }
            _names[sid.Value] = name;
            return name;
        }

        static SecurityIdentifier? Sid(int pid)
        {
            var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (process == IntPtr.Zero) return null;
            try
            {
                if (!OpenProcessToken(process, TokenQuery, out var token)) return null;
                try
                {
                    GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out var size);
                    if (size <= 0) return null;
                    var buffer = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (!GetTokenInformation(token, TokenUser, buffer, size, out _)) return null;
                        var user = (SidAndAttributes)Marshal.PtrToStructure(buffer, typeof(SidAndAttributes))!;
                        return user.Sid == IntPtr.Zero ? null : new SecurityIdentifier(user.Sid);
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(process); }
        }

        /// <summary>For struct-size tests: SID_AND_ATTRIBUTES (TOKEN_USER's only member).</summary>
        internal static int StructSize() => Marshal.SizeOf(typeof(SidAndAttributes));
    }
}
