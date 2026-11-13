using System;
using System.IO;
using Foton.Core;
using Foton.Tools;

namespace Foton.Cli
{
    /// <summary>
    /// foton bundle collect | baseline: writes a folder to carry to an endpoint with the collector this foton.exe
    /// carries (the one released with it), the profile if any, RUN.txt, and SHA256SUMS.txt. The console's bundle
    /// builders do the same. Nothing is run here.
    /// </summary>
    static class BundleCommand
    {
        public static int Run(string[] args)
        {
            CollectorKind kind;
            if (string.Equals(args[1], "collect", StringComparison.OrdinalIgnoreCase)) kind = CollectorKind.Collect;
            else if (string.Equals(args[1], "baseline", StringComparison.OrdinalIgnoreCase)) kind = CollectorKind.Baseline;
            else return Fail("foton bundle needs collect or baseline.");
            string? profilePath = null, output = null;
            bool loadUserHives = false;
            for (int i = 2; i < args.Length; i++)
            {
                var a = args[i];
                if (kind == CollectorKind.Baseline && string.Equals(a, "-LoadUserHives", StringComparison.OrdinalIgnoreCase)) { loadUserHives = true; continue; }
                var takesValue = string.Equals(a, "-OutputPath", StringComparison.OrdinalIgnoreCase) || (kind == CollectorKind.Collect && string.Equals(a, "-Profile", StringComparison.OrdinalIgnoreCase));
                if (!takesValue) return Fail("Unknown argument for foton bundle " + args[1].ToLowerInvariant() + ": " + a);
                if (i + 1 >= args.Length) return Fail(a + " needs a value.");
                if (string.Equals(a, "-Profile", StringComparison.OrdinalIgnoreCase)) profilePath = args[++i]; else output = args[++i];
            }

            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            try
            {
                // The same checks foton-collect -Profile applies: a profile it would refuse is refused here.
                var profile = profilePath != null ? CollectionProfile.Load(profilePath) : null;
                var parent = output ?? CaseTree.DefaultOutput("Bundles");
                var b = DeploymentBundle.Build(kind, EmbeddedCollectors.Read(kind), profile, loadUserHives, parent, DateTime.UtcNow);
                log.Write($"{EmbeddedCollectors.FileName(kind)} {b.CollectorVersion} SHA-256 {b.CollectorSha256} (the one released with this foton.exe)", StatusLevel.Info);
                if (kind == CollectorKind.Collect)
                    log.Write(profile != null ? "Profile: " + TextFile.OneLine(profile.Name) : "No profile: every category, the collector's defaults", StatusLevel.Info);
                log.Write("Bundle: " + b.Folder + " (" + DeploymentBundle.ReadmeFileName + " has the command to run)", StatusLevel.Good);
                return 0;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException || ex is NotSupportedException)
            {
                log.Write("Bundle not built: " + ex.Message, StatusLevel.Error);
                return 1;
            }
        }

        static int Fail(string message)
        {
            Console.Error.WriteLine(TextFile.OneLine(message));
            return 1;
        }
    }
}
