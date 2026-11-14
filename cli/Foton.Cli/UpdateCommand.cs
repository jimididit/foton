using System;
using System.IO;
using Foton.Core;
using Foton.Tools.Update;

namespace Foton.Cli
{
    /// <summary>
    /// foton update: checks GitHub for a newer release signed with the owner's offline key; with -Install, downloads it,
    /// proves every file against the signed statement, and installs it in a new Foton-version folder beside this one.
    /// Never replaces the running executables and never runs unasked. Every step goes to update.log (UTC).
    /// </summary>
    static class UpdateCommand
    {
        /// <summary>Exit 0 up to date, nothing installable, or installed; 2 a newer signed release is available (check only); 1 failed or cancelled.</summary>
        public static int Run(string[] args)
        {
            bool install = false, force = false;
            string? outputParent = null;
            for (int i = 1; i < args.Length; i++)
            {
                if (string.Equals(args[i], "-Install", StringComparison.OrdinalIgnoreCase)) install = true;
                else if (string.Equals(args[i], "-Force", StringComparison.OrdinalIgnoreCase)) force = true;
                else if (string.Equals(args[i], "-OutputPath", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) outputParent = args[++i];
                else { Console.Error.WriteLine("Usage: foton update [-Install [-Force] [-OutputPath <folder>]]"); return 1; }
            }
            if (!install && (force || outputParent != null)) { Console.Error.WriteLine("-Force and -OutputPath go with -Install."); return 1; }

            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            var updates = UpdateStage.Root();
            try { Directory.CreateDirectory(updates); log.LogFile = Path.Combine(updates, "update.log"); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { log.Write("update.log not written: " + ex.Message, StatusLevel.Warn); }

            var current = FotonVersion.Product;
            log.Write($"Checking https://github.com/{UpdateCheck.Repository}/releases for a signed release newer than {current}", StatusLevel.Step);
            var result = UpdateCheck.Run(new HttpUpdateSource(), current, DateTime.UtcNow, ReleaseKeys.All);
            switch (result.State)
            {
                case UpdateState.UpToDate:
                    log.Write(result.Message, StatusLevel.Good);
                    return 0;
                case UpdateState.NotYetSigned:
                    log.Write(result.Message, StatusLevel.Warn);
                    if (result.ReleaseUrl.Length > 0) log.Write("Release notes: " + result.ReleaseUrl);
                    return 0;
                case UpdateState.Failed:
                    log.Write(result.Message, StatusLevel.Error);
                    if (result.ReleaseUrl.Length > 0) log.Write("Release: " + result.ReleaseUrl);
                    return 1;
            }

            var statement = result.Statement!;
            log.Write(result.Message, StatusLevel.Good);
            log.Write("Release notes: " + result.ReleaseUrl);
            if (result.PendingVersion.Length > 0) log.Write($"Foton {result.PendingVersion} is also published but not signed yet.", StatusLevel.Warn);
            var exeDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
            if (UpdateInstall.IsScoop(exeDir))
            {
                log.Write("This Foton was installed with Scoop: run  scoop update foton", StatusLevel.Warn);
                return install ? 1 : 2;
            }
            if (!install)
            {
                log.WriteConsole("     Install it beside this copy (this folder is kept):  foton update -Install", ConsoleColor.DarkGray);
                return 2;
            }

            string target;
            try { target = outputParent != null ? Path.Combine(Path.GetFullPath(outputParent), "Foton-" + statement.Version) : UpdateInstall.DefaultTarget(exeDir, statement.Version); }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            {
                log.Write("Not a usable -OutputPath: " + ex.Message, StatusLevel.Error);
                return 1;
            }
            log.WriteConsole($"  Install: Foton {statement.Version} into {target}", ConsoleColor.White);
            log.WriteConsole($"  Kept:    this copy in {exeDir}", ConsoleColor.White);
            if (!force)
            {
                Console.Write($"  Download, verify, and install Foton {statement.Version}? [y/N] ");
                var answer = Console.ReadLine()?.Trim();
                if (!string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase) && !string.Equals(answer, "yes", StringComparison.OrdinalIgnoreCase))
                {
                    log.Write("Cancelled.", StatusLevel.Warn);
                    return 1;
                }
            }
            try
            {
                var staged = UpdateStage.Stage(statement, result.ZipUrl, new HttpUpdateSource(), updates, log);
                UpdateInstall.Install(staged, target, statement, log);
            }
            catch (Exception ex) when (ex is IOException || ex is InvalidDataException || ex is UnauthorizedAccessException
                || ex is ArgumentException || ex is NotSupportedException)
            {
                log.Write("Update not installed: " + ex.Message, StatusLevel.Error);
                log.Write("This copy is unchanged.", StatusLevel.Info);
                return 1;
            }
            // After a successful install: a staging folder left behind is only disk space, not a failed update.
            try { UpdateStage.Clean(updates, statement.Version); }
            catch (InvalidDataException ex) { log.Write("Staging folder not removed: " + ex.Message, StatusLevel.Warn); }
            log.Write($"This copy in {exeDir} is unchanged; cases can still be re-run with Foton {current}.", StatusLevel.Info);
            log.WriteConsole($"     Run the new version from {target}", ConsoleColor.DarkGray);
            return 0;
        }
    }
}
