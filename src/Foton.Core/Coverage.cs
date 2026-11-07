using System.IO;
using System.Linq;

namespace Foton.Core
{
    /// <summary>
    /// collection_coverage.json: how privileged the run was, so an analyst does not read a thin package
    /// as a quiet host. Written after collection so the skipped and incomplete counts are final.
    /// </summary>
    public static class Coverage
    {
        public sealed class CollectionCoverage
        {
            public string CoverageProfile { get; set; } = "";
            public bool Elevated { get; set; }
            public string CollectionAccount { get; set; } = "";
            public bool RequireAdministrator { get; set; }
            public bool LoadUserHivesRequested { get; set; }
            public bool LoadUserHivesActive { get; set; }
            public int SkippedTaskCount { get; set; }
            public string[] SkippedTasks { get; set; } = new string[0];
            public int IncompleteTaskCount { get; set; }
            public string[] IncompleteTasks { get; set; } = new string[0];
            public string[] ExcludedEarlierPackages { get; set; } = new string[0];
            public string[] WorthCollectingWithoutAdmin { get; set; } = new string[0];
            public string[] NotCollectedWithoutAdmin { get; set; } = new string[0];
        }

        public static string Profile(bool elevated) => elevated ? "Elevated" : "StandardUser";

        public static CollectionCoverage Build(FotonSession s)
        {
            var skipped = s.Manifest.Where(m => m.Status == TaskStatus.SkippedNotElevated).ToArray();
            var incomplete = s.Manifest.Where(m => m.Status == TaskStatus.Partial || m.Status == TaskStatus.Failed).ToArray();
            return new CollectionCoverage
            {
                CoverageProfile = Profile(s.IsElevated),
                Elevated = s.IsElevated,
                CollectionAccount = s.Account,
                RequireAdministrator = s.Options.RequireAdministrator,
                LoadUserHivesRequested = s.Options.LoadUserHives,
                LoadUserHivesActive = s.LoadUserHivesActive,
                SkippedTaskCount = skipped.Length,
                SkippedTasks = skipped.Select(m => m.Task).ToArray(),
                IncompleteTaskCount = incomplete.Length,
                IncompleteTasks = incomplete.Select(m => m.Task + " (" + m.Status + ")").ToArray(),
                ExcludedEarlierPackages = s.ExcludedEarlierPackages.ToArray(),
                WorthCollectingWithoutAdmin = new[]
                {
                    "Current-user processes (image hash/signature only if the file is readable)",
                    "TCP connections and listeners the token can enumerate",
                    "HKCU autoruns, user Startup folder, PSReadLine history for accessible profiles",
                    "Readable HKLM software/uninstall, OS identity, environment, hosts file",
                    "Application / PowerShell / Defender operational logs when ACLs allow",
                    "Browser extensions and executables under the current profile",
                },
                NotCollectedWithoutAdmin = new[]
                {
                    "Security event log (parsed and EVTX export)",
                    "Prefetch listing and copied .pf files",
                    "Amcache hive copy",
                    "SRUM database copy",
                    "Volume shadow copy listing (vssadmin)",
                    "auditpol / secedit exports",
                    "Offline NTUSER.DAT for other users",
                    "Other users' AppData, recycle bins, and files the token cannot read",
                },
            };
        }

        public static CollectionCoverage Write(FotonSession s)
        {
            var c = Build(s);
            TextFile.Write(Path.Combine(s.Dir("Collection"), "collection_coverage.json"), Json.Indented(c));
            s.Data["collection_coverage"] = c;
            return c;
        }
    }
}
