using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace Foton.Win
{
    /// <summary>
    /// Runs an in-box System32 tool (w32tm, vssadmin, query, net, secedit, cmdkey, nltest, bcdedit) and returns what it
    /// printed, stdout and stderr together, as "&amp; tool 2&gt;&amp;1 | Out-String" did. The tool is always started from its
    /// System32 path, never through PATH, which a compromised host controls.
    /// </summary>
    public static class Exec
    {
        public static string System32(string exe, string arguments, int timeoutMs = 120000) => System32(exe, arguments, out _, timeoutMs);

        /// <summary>As System32, with the tool's exit code (-1 when it did not start or timed out).</summary>
        public static string System32(string exe, string arguments, out int exitCode, int timeoutMs = 120000)
        {
            exitCode = -1;
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exe);
            if (!File.Exists(path)) return $"{exe} not found at {path}.";
            // Redirected console tools write the OEM code page, which is how PowerShell decoded them.
            var oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            var psi = new ProcessStartInfo(path, arguments)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
                StandardOutputEncoding = oem, StandardErrorEncoding = oem,
            };
            try
            {
                using (var p = Process.Start(psi)!)
                {
                    p.StandardInput.Close();
                    var stdout = p.StandardOutput.ReadToEndAsync();
                    var stderr = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch (Exception) { }
                        return $"{exe} {arguments}: timed out after {timeoutMs / 1000} s.";
                    }
                    p.WaitForExit();
                    exitCode = p.ExitCode;
                    var text = stdout.Result + stderr.Result;
                    return text.EndsWith("\n", StringComparison.Ordinal) ? text : text + "\r\n";
                }
            }
            catch (Exception ex) when (ex is Win32Exception || ex is InvalidOperationException || ex is IOException)
            {
                return $"{exe} {arguments}: {ex.Message}";
            }
        }
    }
}
