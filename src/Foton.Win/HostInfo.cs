using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace Foton.Win
{
    public sealed class UserProfile
    {
        public string Sid { get; set; } = "";
        public string UserName { get; set; } = "";
        public string ProfilePath { get; set; } = "";
        public bool Exists { get; set; }
    }

    public sealed class UserHive
    {
        public string Sid { get; set; } = "";
        public string UserName { get; set; } = "";
        /// <summary>"Registry::HKEY_USERS\&lt;leaf&gt;", the form 1.38.x wrote into record Key fields.</summary>
        public string Root { get; set; } = "";
    }

    /// <summary>Process and host facts (Test-FotonElevated, Get-FotonUserProfile, Get-FotonUserHiveRoot).</summary>
    public static class HostInfo
    {
        /// <summary>
        /// The Windows directory from the known-folder API, not %SystemRoot%: the launching process controls the
        /// environment, and a redirected path would make an integrity baseline hash the wrong files.
        /// </summary>
        public static string WindowsDir => Known(Environment.SpecialFolder.Windows, @"C:\Windows");

        /// <summary>%ProgramData% from the known-folder API (same reason as WindowsDir).</summary>
        public static string ProgramDataDir => Known(Environment.SpecialFolder.CommonApplicationData, @"C:\ProgramData");

        static string Known(Environment.SpecialFolder folder, string fallback)
        {
            var p = Environment.GetFolderPath(folder);
            return string.IsNullOrEmpty(p) ? fallback : p;
        }

        /// <summary>True only for a token in the local Administrators role; any failure reads as not elevated.</summary>
        public static bool IsElevated()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch (Exception) { return false; }
        }

        public static string Account() => Environment.UserDomainName + "\\" + Environment.UserName;

        const string ProfileList = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

        /// <summary>
        /// Local profiles from ProfileList. A standard token sees only S-1-5-21 (interactive) profiles,
        /// as in 1.38.x; service profiles are an elevated-only view.
        /// </summary>
        public static List<UserProfile> Profiles(bool elevated)
        {
            var list = new List<UserProfile>();
            foreach (var sid in Reg.SubKeyNames(ProfileList))
            {
                var path = Foton.Core.BaselineDocument.PsString(Reg.Value(Reg.Join(ProfileList, sid), "ProfileImagePath"));
                if (path.Length == 0) continue;
                list.Add(new UserProfile { Sid = sid, UserName = Path.GetFileName(path.TrimEnd('\\')), ProfilePath = path, Exists = Accessible(path) });
            }
            if (!elevated) list = list.Where(p => p.Sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)).ToList();
            return list;
        }

        /// <summary>Loaded user hives under HKEY_USERS (S-1-5-21 SIDs and Foton_/WinFoton_ mounts), named from ProfileList.</summary>
        public static List<UserHive> HiveRoots(bool elevated)
        {
            var profiles = Profiles(elevated);
            var list = new List<UserHive>();
            foreach (var leaf in Reg.SubKeyNames("Registry::HKEY_USERS"))
            {
                if (leaf.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                bool sidLeaf = leaf.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase);
                bool mount = leaf.StartsWith("Foton_", StringComparison.OrdinalIgnoreCase) || leaf.StartsWith("WinFoton_", StringComparison.OrdinalIgnoreCase);
                if (!sidLeaf && !mount) continue;
                var sid = leaf;
                if (sid.StartsWith("Foton_", StringComparison.OrdinalIgnoreCase)) sid = sid.Substring("Foton_".Length);
                if (sid.StartsWith("WinFoton_", StringComparison.OrdinalIgnoreCase)) sid = sid.Substring("WinFoton_".Length);
                var match = profiles.FirstOrDefault(p => string.Equals(p.Sid, sid, StringComparison.OrdinalIgnoreCase));
                list.Add(new UserHive { Sid = sid, UserName = match?.UserName ?? sid, Root = "Registry::HKEY_USERS\\" + leaf });
            }
            return list;
        }

        /// <summary>Test-Path that reads access-denied as false (Test-FotonPathAccessible).</summary>
        public static bool Accessible(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try { return Directory.Exists(path) || File.Exists(path); }
            catch (Exception) { return false; }
        }
    }
}
