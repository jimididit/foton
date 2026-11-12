using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Foton.Core;

namespace Foton.Win
{
    /// <summary>
    /// The default output folders (C:\Foton\Cases, C:\Foton\Baselines on the Windows drive). Any account may create a
    /// folder at the drive root, and a folder created there inherits Modify for every signed-in user. So Foton creates
    /// these folders private (SYSTEM, Administrators, the collecting account) and, before writing evidence into them,
    /// refuses any that another account owns, can access, or has turned into a junction: a standard user could
    /// otherwise pre-create C:\Foton and read what a later elevated collection writes.
    /// </summary>
    public static class OutputFolder
    {
        public static string Default(string leaf) => CaseTree.DefaultOutput(leaf);

        /// <summary>
        /// Creates any missing folder from below the drive root down to <paramref name="path"/> with the private ACL,
        /// then checks the whole chain (<see cref="Problem"/>). Checking after creating also covers a folder another
        /// account created in between: CreateDirectory leaves an existing folder's ACL as it is.
        /// Returns null when every folder is private, otherwise why not.
        /// </summary>
        public static string? EnsurePrivate(string path) => EnsurePrivate(path, null);

        /// <summary>As EnsurePrivate, for folders strictly below <paramref name="above"/> (the drive root when null).</summary>
        internal static string? EnsurePrivate(string path, string? above)
        {
            var mine = new HashSet<SecurityIdentifier>(Owners());
            foreach (var dir in Chain(path, above))
            {
                // Nothing is created inside a folder that is already not private.
                if (Directory.Exists(dir)) { var p = Check(dir, mine); if (p != null) return p; }
                else Directory.CreateDirectory(dir, PrivateAcl());
            }
            return Problem(path, above);
        }

        /// <summary>
        /// Null when every folder from below the drive root down to <paramref name="path"/> exists, is not a junction or
        /// link, is owned by SYSTEM, Administrators, or the current account, and grants access to no one else.
        /// Fails closed: permissions that cannot be read are a problem, not a pass.
        /// </summary>
        public static string? Problem(string path) => Problem(path, null);

        internal static string? Problem(string path, string? above)
        {
            var mine = new HashSet<SecurityIdentifier>(Owners());
            foreach (var dir in Chain(path, above))
            {
                var p = Check(dir, mine);
                if (p != null) return p;
            }
            return null;
        }

        static string? Check(string dir, HashSet<SecurityIdentifier> mine)
        {
            try
            {
                var info = new DirectoryInfo(dir);
                if (!info.Exists) return dir + " does not exist";
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) return dir + " is a junction or link";
                var acl = Directory.GetAccessControl(dir, AccessControlSections.Access | AccessControlSections.Owner);
                var owner = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                if (owner == null || !mine.Contains(owner)) return dir + " is owned by " + (owner == null ? "an unknown account" : Name(owner));
                foreach (FileSystemAccessRule r in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    if (r.AccessControlType == AccessControlType.Allow && !mine.Contains((SecurityIdentifier)r.IdentityReference))
                        return dir + " gives access to " + Name((SecurityIdentifier)r.IdentityReference);
                return null;
            }
            catch (SystemException ex)
            {
                return "cannot read the permissions of " + dir + " (" + ex.Message + ")";
            }
        }

        /// <summary>
        /// Prepares a default output folder for an endpoint run. False, after logging why and how to recover, when the
        /// folder cannot be created or is not private.
        /// </summary>
        public static bool Prepare(string path, StatusLog log)
        {
            string? problem;
            try { problem = EnsurePrivate(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException || ex is ArgumentException)
            {
                problem = "it could not be created (" + ex.Message + ")";
            }
            if (problem == null) return true;
            log.Write($"Not writing to the default output folder {path}: {problem}.", StatusLevel.Error);
            log.WriteConsole("      Evidence goes only into a folder that SYSTEM, Administrators, and this account alone can use.", ConsoleColor.Red);
            log.WriteConsole("      Pass -OutputPath <folder> to choose another folder, or remove the folder named above and run again.", ConsoleColor.Red);
            return false;
        }

        /// <summary>Folders strictly below <paramref name="above"/> (the drive root when null) down to <paramref name="path"/>, top first.</summary>
        static List<string> Chain(string path, string? above)
        {
            var full = Path.GetFullPath(path).TrimEnd('\\');
            var stop = (above == null ? Path.GetPathRoot(full) ?? "" : Path.GetFullPath(above)).TrimEnd('\\');
            if (!full.StartsWith(stop + "\\", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(path + " is not below " + stop);
            var chain = new List<string>();
            for (var d = full; !string.Equals(d, stop, StringComparison.OrdinalIgnoreCase); d = Path.GetDirectoryName(d)!.TrimEnd('\\'))
                chain.Insert(0, d);
            return chain;
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

        static string Name(SecurityIdentifier sid)
        {
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch (IdentityNotMappedException) { return sid.Value; }
            catch (SystemException) { return sid.Value; }
        }
    }
}
