using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using Foton.Core;

namespace Foton.Win
{
    /// <summary>
    /// The default output folders (C:\Foton\Cases, C:\Foton\Baselines on the Windows drive). A folder created under
    /// the drive root inherits Modify for every signed-in user, so case data there would be readable by other local
    /// accounts; Foton creates these folders private instead: SYSTEM, Administrators, and the collecting account.
    /// </summary>
    public static class OutputFolder
    {
        public static string Default(string leaf) =>
            Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Foton", leaf);

        /// <summary>
        /// Creates <paramref name="path"/> and any missing parent below the drive root with the private ACL. Folders
        /// that already exist are left as they are. Returns the principals other than SYSTEM, Administrators, and the
        /// current account that can read the final folder (empty when private), so the caller can warn.
        /// </summary>
        public static List<string> EnsurePrivate(string path)
        {
            var full = Path.GetFullPath(path).TrimEnd('\\');
            var root = Path.GetPathRoot(full) ?? "";
            var missing = new Stack<string>();
            for (var d = full; d.Length > root.Length && !Directory.Exists(d); d = Path.GetDirectoryName(d) ?? root)
                missing.Push(d);
            while (missing.Count > 0) Directory.CreateDirectory(missing.Pop(), PrivateAcl());
            return OtherReaders(full);
        }

        /// <summary>
        /// Prepares a default output folder for an endpoint run: false (after logging how to recover) when it cannot be
        /// created; a warning when it already existed and other accounts can read it.
        /// </summary>
        public static bool Prepare(string path, StatusLog log)
        {
            List<string> others;
            try { others = EnsurePrivate(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException || ex is ArgumentException)
            {
                log.Write($"Cannot create the default output folder {path}: {ex.Message}", StatusLevel.Error);
                log.WriteConsole("      Pass -OutputPath <folder> with a folder this account can write to.", ConsoleColor.Red);
                return false;
            }
            if (others.Count > 0)
                log.Write($"{path} already existed and is readable by {string.Join(", ", others)}. Output written there is readable by those accounts too; pass -OutputPath to use a private folder.", StatusLevel.Warn);
            return true;
        }

        static DirectorySecurity PrivateAcl()
        {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var sid in Owners())
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            return acl;
        }

        static IEnumerable<SecurityIdentifier> Owners()
        {
            yield return new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            yield return new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            using (var me = WindowsIdentity.GetCurrent())
                if (me.User != null) yield return me.User;
        }

        const FileSystemRights ReadRights = FileSystemRights.ReadData | FileSystemRights.ListDirectory;

        /// <summary>Allow rules granting read or list to anyone other than SYSTEM, Administrators, or the current account.</summary>
        public static List<string> OtherReaders(string path)
        {
            var mine = new HashSet<SecurityIdentifier>(Owners());
            var others = new List<string>();
            try
            {
                var rules = Directory.GetAccessControl(path, AccessControlSections.Access).GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule r in rules)
                {
                    if (r.AccessControlType != AccessControlType.Allow || (r.FileSystemRights & ReadRights) == 0) continue;
                    var sid = (SecurityIdentifier)r.IdentityReference;
                    if (mine.Contains(sid)) continue;
                    var name = Name(sid);
                    if (!others.Contains(name)) others.Add(name);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException || ex is InvalidOperationException) { }
            return others;
        }

        static string Name(SecurityIdentifier sid)
        {
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch (IdentityNotMappedException) { return sid.Value; }
            catch (SystemException) { return sid.Value; }
        }
    }
}
