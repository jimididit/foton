using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect
{
    /// <summary>
    /// -LoadUserHives (Mount-FotonOfflineUserHive / Dismount-FotonOfflineUserHive): loads NTUSER.DAT for local
    /// profiles whose hive is not loaded, so per-user persistence keys can be read. This WRITES to the registry; the
    /// methodology disclosure says so, and Unload always runs in a finally block. reg.exe is used as in 1.38.x, so the
    /// footprint (an in-box process that enables its own restore privilege) is unchanged.
    /// </summary>
    public static class UserHives
    {
        public const string MountPrefix = "Foton";
        static readonly System.Text.RegularExpressions.Regex UserSid = new System.Text.RegularExpressions.Regex(@"^S-1-5-21(-\d+)+$");

        /// <summary>Mounts offline hives, adding each to <paramref name="mounted"/> the moment it loads, so a failure part way still unloads every one.</summary>
        public static void Load(FotonSession s, List<string> mounted)
        {
            foreach (var p in HostInfo.Profiles(s.IsElevated))
            {
                // ProfileList is host data: only a well-formed domain/local user SID becomes part of a reg.exe argument.
                if (!p.Exists || !UserSid.IsMatch(p.Sid)) continue;
                if (Reg.Exists(@"Registry::HKEY_USERS\" + p.Sid)) continue;
                var dat = Path.Combine(p.ProfilePath, "NTUSER.DAT");
                if (!File.Exists(dat)) continue;
                var name = MountPrefix + "_" + p.Sid;
                if (RegExe(new[] { "load", @"HKU\" + name, dat }) == 0)
                {
                    mounted.Add(name);
                    s.Status.Write("Loaded offline hive for " + p.UserName, StatusLevel.Info);
                }
                else s.Status.Write("Could not load hive for " + p.UserName, StatusLevel.Warn);
            }
        }

        /// <summary>Unloads what Load mounted. A failure is a warning: the key needs a manual reg unload.</summary>
        public static void Unload(FotonSession s, IEnumerable<string> mounted)
        {
            foreach (var name in mounted)
            {
                // Release any registry handles this process still holds into the hive.
                GC.Collect();
                GC.WaitForPendingFinalizers();
                bool ok = RegExe(new[] { "unload", @"HKU\" + name }) == 0;
                try
                {
                    if (ok) s.Status.Write("Unloaded hive " + name, StatusLevel.Info);
                    else s.Status.Write($"Failed to unload hive {name} - manual cleanup required (reg unload HKU\\{name})", StatusLevel.Warn);
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
        }

        /// <summary>reg.exe with each argument quoted; an argument holding a quote (a crafted profile path) is refused.</summary>
        static int RegExe(string[] args)
        {
            if (args.Any(a => a.IndexOf('"') >= 0)) return -1;
            var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "reg.exe");
            var psi = new ProcessStartInfo(exe, string.Join(" ", args.Select(a => "\"" + a + "\"")))
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            try
            {
                using (var p = Process.Start(psi)!)
                {
                    p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    return p.ExitCode;
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException) { return -1; }
        }
    }
}
