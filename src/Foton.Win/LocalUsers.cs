using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Foton.Win
{
    /// <summary>One local account as Get-LocalUser described it. Times are UTC; null means never or not set.</summary>
    public sealed class LocalUser
    {
        public string Name { get; set; } = "";
        public bool Enabled { get; set; }
        public string Sid { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime? LastLogonUtc { get; set; }
        public DateTime? PasswordLastSetUtc { get; set; }
        public bool PasswordRequired { get; set; }
        public DateTime? PasswordExpiresUtc { get; set; }
        public bool UserMayChangePassword { get; set; }
        public DateTime? AccountExpiresUtc { get; set; }
        /// <summary>A local account linked to a Microsoft account (USER_INFO_24 internet identity).</summary>
        public bool MicrosoftAccount { get; set; }
    }

    /// <summary>
    /// Local accounts through netapi32 (the SAM data Get-LocalUser read). Read-only; runs with a standard token on a
    /// workstation or member server.
    /// </summary>
    public static class LocalUsers
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct UserInfo0 { public IntPtr Name; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct UserInfo4
        {
            public IntPtr Name, Password;
            public uint PasswordAge, Priv;
            public IntPtr HomeDir, Comment;
            public uint Flags;
            public IntPtr ScriptPath;
            public uint AuthFlags;
            public IntPtr FullName, UsrComment, Parms, Workstations;
            public uint LastLogon, LastLogoff, AcctExpires, MaxStorage, UnitsPerWeek;
            public IntPtr LogonHours;
            public uint BadPwCount, NumLogons;
            public IntPtr LogonServer;
            public uint CountryCode, CodePage;
            public IntPtr UserSid;
            public uint PrimaryGroupId;
            public IntPtr Profile, HomeDirDrive;
            public uint PasswordExpired;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct UserInfo24
        {
            public int InternetIdentity;
            public uint Flags;
            public IntPtr ProviderName, PrincipalName, UserSid;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UserModalsInfo0 { public uint MinPasswdLen, MaxPasswdAge, MinPasswdAge, ForceLogoff, PasswordHistLen; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserEnum(string? server, int level, int filter, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserGetInfo(string? server, string user, int level, out IntPtr buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetUserModalsGet(string? server, int level, out IntPtr buffer);

        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);

        const int FilterNormalAccount = 0x2, MaxPreferredLength = -1, MoreData = 234;
        const uint AccountDisable = 0x2, PasswdNotReqd = 0x20, PasswdCantChange = 0x40, DontExpirePasswd = 0x10000, Forever = 0xFFFFFFFF;
        static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static List<LocalUser> All()
        {
            var names = new List<string>();
            IntPtr resume = IntPtr.Zero;
            int rc;
            do
            {
                rc = NetUserEnum(null, 0, FilterNormalAccount, out var buf, MaxPreferredLength, out var read, out _, ref resume);
                if (rc != 0 && rc != MoreData) throw new InvalidOperationException("NetUserEnum failed: " + rc);
                try
                {
                    int size = Marshal.SizeOf(typeof(UserInfo0));
                    for (int i = 0; i < read; i++)
                        names.Add(Marshal.PtrToStringUni(((UserInfo0)Marshal.PtrToStructure(buf + i * size, typeof(UserInfo0))!).Name) ?? "");
                }
                finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            } while (rc == MoreData);

            uint maxAge = MaxPasswordAge();
            var now = DateTime.UtcNow;
            var list = new List<LocalUser>();
            foreach (var name in names)
            {
                if (NetUserGetInfo(null, name, 4, out var buf) != 0) continue;
                try
                {
                    var u = (UserInfo4)Marshal.PtrToStructure(buf, typeof(UserInfo4))!;
                    DateTime? lastSet = NeverSet(u.PasswordAge, now) ? (DateTime?)null : now.AddSeconds(-u.PasswordAge);
                    list.Add(new LocalUser
                    {
                        Name = name,
                        Enabled = (u.Flags & AccountDisable) == 0,
                        Sid = u.UserSid == IntPtr.Zero ? "" : new SecurityIdentifier(u.UserSid).Value,
                        Description = Marshal.PtrToStringUni(u.Comment) ?? "",
                        LastLogonUtc = u.LastLogon == 0 ? (DateTime?)null : Epoch.AddSeconds(u.LastLogon),
                        PasswordLastSetUtc = lastSet,
                        PasswordRequired = (u.Flags & PasswdNotReqd) == 0,
                        PasswordExpiresUtc = (u.Flags & DontExpirePasswd) != 0 || maxAge == Forever || lastSet == null ? (DateTime?)null : lastSet.Value.AddSeconds(maxAge),
                        UserMayChangePassword = (u.Flags & PasswdCantChange) == 0,
                        AccountExpiresUtc = u.AcctExpires == Forever ? (DateTime?)null : Epoch.AddSeconds(u.AcctExpires),
                        MicrosoftAccount = IsInternetIdentity(name),
                    });
                }
                finally { NetApiBufferFree(buf); }
            }
            return list;
        }

        /// <summary>
        /// netapi reports a password that was never set (built-in disabled accounts) as age 0, which Get-LocalUser showed
        /// as never set. An age older than 1970 is not a real timestamp either.
        /// </summary>
        internal static bool NeverSet(uint passwordAge, DateTime nowUtc) => passwordAge == 0 || passwordAge > (nowUtc - Epoch).TotalSeconds;

        static bool IsInternetIdentity(string name)
        {
            if (NetUserGetInfo(null, name, 24, out var buf) != 0) return false;
            try { return ((UserInfo24)Marshal.PtrToStructure(buf, typeof(UserInfo24))!).InternetIdentity != 0; }
            finally { NetApiBufferFree(buf); }
        }

        static uint MaxPasswordAge()
        {
            if (NetUserModalsGet(null, 0, out var buf) != 0) return Forever;
            try { return ((UserModalsInfo0)Marshal.PtrToStructure(buf, typeof(UserModalsInfo0))!).MaxPasswdAge; }
            finally { NetApiBufferFree(buf); }
        }

        /// <summary>For struct-size tests: USER_INFO_0, USER_INFO_4, USER_INFO_24, USER_MODALS_INFO_0.</summary>
        internal static int[] StructSizes() => new[]
        {
            Marshal.SizeOf(typeof(UserInfo0)), Marshal.SizeOf(typeof(UserInfo4)), Marshal.SizeOf(typeof(UserInfo24)), Marshal.SizeOf(typeof(UserModalsInfo0)),
        };
    }
}
