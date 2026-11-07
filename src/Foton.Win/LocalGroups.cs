using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Foton.Win
{
    public sealed class GroupMember
    {
        public string Group { get; set; } = "";
        public string Sid { get; set; } = "";
        /// <summary>DOMAIN\name, as Get-LocalGroupMember named members.</summary>
        public string Member { get; set; } = "";
    }

    /// <summary>
    /// Local groups and members through netapi32. Unlike Get-LocalGroupMember this does not fail a whole group
    /// with error 1789 when one member SID cannot be resolved (1.38.x baseline then silently lost the group,
    /// Administrators included); an unresolved member keeps its SID with an empty name.
    /// </summary>
    public static class LocalGroups
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LocalGroupInfo0 { public IntPtr Name; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LocalGroupMembersInfo2 { public IntPtr Sid; public int SidUsage; public IntPtr DomainAndName; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupEnum(string? server, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupGetMembers(string? server, string group, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead, out int totalEntries, ref IntPtr resumeHandle);

        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);

        const int MaxPreferredLength = -1;
        const int MoreData = 234;

        public static List<string> Groups()
        {
            var names = new List<string>();
            IntPtr resume = IntPtr.Zero;
            int rc;
            do
            {
                rc = NetLocalGroupEnum(null, 0, out var buf, MaxPreferredLength, out var read, out _, ref resume);
                if (rc != 0 && rc != MoreData) throw new InvalidOperationException("NetLocalGroupEnum failed: " + rc);
                try
                {
                    int size = Marshal.SizeOf(typeof(LocalGroupInfo0));
                    for (int i = 0; i < read; i++)
                    {
                        var info = (LocalGroupInfo0)Marshal.PtrToStructure(buf + i * size, typeof(LocalGroupInfo0))!;
                        names.Add(Marshal.PtrToStringUni(info.Name) ?? "");
                    }
                }
                finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            } while (rc == MoreData);
            return names;
        }

        public static List<GroupMember> Members(string group)
        {
            var list = new List<GroupMember>();
            IntPtr resume = IntPtr.Zero;
            int rc;
            do
            {
                rc = NetLocalGroupGetMembers(null, group, 2, out var buf, MaxPreferredLength, out var read, out _, ref resume);
                if (rc != 0 && rc != MoreData) throw new InvalidOperationException("NetLocalGroupGetMembers(" + group + ") failed: " + rc);
                try
                {
                    int size = Marshal.SizeOf(typeof(LocalGroupMembersInfo2));
                    for (int i = 0; i < read; i++)
                    {
                        var m = (LocalGroupMembersInfo2)Marshal.PtrToStructure(buf + i * size, typeof(LocalGroupMembersInfo2))!;
                        var sid = m.Sid == IntPtr.Zero ? "" : new SecurityIdentifier(m.Sid).Value;
                        list.Add(new GroupMember { Group = group, Sid = sid, Member = Marshal.PtrToStringUni(m.DomainAndName) ?? "" });
                    }
                }
                finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            } while (rc == MoreData);
            return list;
        }

        /// <summary>For struct-size tests: the native layouts are pointer-sized fields (and one 32-bit enum).</summary>
        internal static int[] StructSizes() => new[] { Marshal.SizeOf(typeof(LocalGroupInfo0)), Marshal.SizeOf(typeof(LocalGroupMembersInfo2)) };
    }
}
