using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

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
            using (var p = Process.Start(Info(exe, arguments, workDir))!)
            using (var so = File.Create(stdoutPath))
            using (var se = File.Create(stderrPath))
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
