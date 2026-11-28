using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Foton.Core;

namespace Foton.Tools
{
    sealed class Captured
    {
        public string StdOut { get; set; } = "";
        public string StdErr { get; set; } = "";
        public int ExitCode { get; set; }
    }

    /// <summary>Starting an external tool. Standard input is closed so a tool that prompts fails instead of waiting forever.</summary>
    static class ToolProcess
    {
        /// <summary>
        /// The longest executable path Windows will start a program from without the long-path opt-in. Foton.exe is not
        /// long-path aware, and a \\?\ prefix does not help: Process.Start fails with the prefix, a long working
        /// directory, or none (checked on net472). Compose refuses such a tool with a row instead of trying.
        /// </summary>
        public const int MaxStartPath = 259;

        /// <summary>True when the executable path, and the working folder when one is given, are short enough to start from.</summary>
        public static bool CanStart(string exe, string? workDir = null) =>
            Absolute(exe).Length <= MaxStartPath && (workDir == null || Absolute(workDir).Length <= MaxStartPath);

        /// <summary>A relative path is measured as Windows will see it, joined to the working folder; a rooted one as given.</summary>
        static string Absolute(string path) =>
            path.Length == 0 || Path.IsPathRooted(path) ? path : Path.Combine(Directory.GetCurrentDirectory(), path);

        static ProcessStartInfo Info(string exe, string arguments, string? workDir) => new ProcessStartInfo(exe, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
            WorkingDirectory = workDir ?? "",
        };

        /// <summary>Output of a short probe (version, help); null when it fails to start or outlives the timeout.</summary>
        public static Captured? Capture(string exe, string arguments, string? workDir, int timeoutMs)
        {
            // The same limit as compose enforces: a caller that forgot to check gets "did not run", not a launch that fails.
            if (!CanStart(exe, workDir)) return null;
            try
            {
                using (var p = Process.Start(Info(exe, arguments, workDir))!)
                {
                    p.StandardInput.Close();
                    // Drain both streams: an unread pipe that fills blocks the tool until the timeout.
                    var stdout = p.StandardOutput.ReadToEndAsync();
                    var stderr = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch (Exception) { }
                        return null;
                    }
                    p.WaitForExit();
                    return new Captured { StdOut = stdout.Result, StdErr = stderr.Result, ExitCode = p.ExitCode };
                }
            }
            catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException || ex is IOException) { return null; }
        }

        /// <summary>Runs a tool to completion with its stdout and stderr written byte-for-byte to files. Returns the exit code.</summary>
        public static int RunToFiles(string exe, string arguments, string workDir, string stdoutPath, string stderrPath)
        {
            if (!CanStart(exe, workDir))
                throw new IOException("The tool's executable or working folder is too long to start from; Windows starts a program only from paths under " + (MaxStartPath + 1) + " characters.");
            // The output files are opened first, with the long-path form (the case folder can be deep even when the tool path
            // is not). If either cannot be created the tool is never started, instead of running on after the error.
            FileStream so = File.Create(LongPath.For(stdoutPath));
            FileStream? se = null;
            Process p;
            try
            {
                se = File.Create(LongPath.For(stderrPath));
                p = Process.Start(Info(exe, arguments, workDir))!;
            }
            catch
            {
                // A tool that did not start wrote no log: compose reports the start error in stderr only, and an empty stdout
                // left here would look like a log this run wrote.
                so.Dispose();
                se?.Dispose();
                foreach (var path in new[] { stdoutPath, stderrPath })
                {
                    try { File.Delete(LongPath.For(path)); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
                throw;
            }
            using (so)
            using (se)
            using (p)
            {
                p.StandardInput.Close();
                var a = p.StandardOutput.BaseStream.CopyToAsync(so);
                var b = p.StandardError.BaseStream.CopyToAsync(se);
                p.WaitForExit();
                Task.WaitAll(a, b);
                return p.ExitCode;
            }
        }
    }
}
