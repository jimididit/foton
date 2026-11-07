using System;
using System.IO;

namespace Foton.Core
{
    public enum StatusLevel { Info, Good, Warn, Error, Step }

    /// <summary>
    /// Operator console line plus a UTC line in collection.log (Write-FotonStatus). Operational, not
    /// evidentiary: findings never go here. A log write failure never stops a run.
    /// </summary>
    public sealed class StatusLog
    {
        readonly object _gate = new object();
        readonly TextWriter _console;
        readonly bool _color;

        public string? LogFile { get; set; }

        /// <summary>Clock for log stamps; tests replace it.</summary>
        public Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

        public StatusLog(TextWriter? console = null)
        {
            _console = console ?? Console.Out;
            _color = console == null && !Console.IsOutputRedirected;
        }

        public void Write(string message, StatusLevel level = StatusLevel.Info)
        {
            lock (_gate)
            {
                string line;
                ConsoleColor color;
                switch (level)
                {
                    case StatusLevel.Step: line = Environment.NewLine + "[*] " + message; color = ConsoleColor.Cyan; break;
                    case StatusLevel.Good: line = "    [+] " + message; color = ConsoleColor.Green; break;
                    case StatusLevel.Warn: line = "    [!] " + message; color = ConsoleColor.Yellow; break;
                    case StatusLevel.Error: line = "    [x] " + message; color = ConsoleColor.Red; break;
                    default: line = "    [-] " + message; color = ConsoleColor.Gray; break;
                }
                WriteConsole(line, color);
                if (LogFile != null)
                {
                    try { TextFile.AppendLine(LogFile, FotonTime.Format(UtcNow()) + " UTC  [" + level + "] " + message); }
                    catch (Exception) { }
                }
            }
        }

        /// <summary>
        /// Writes a final log line and stops logging, so the log's entry in hashes.csv stays true.
        /// (1.38.x kept appending after hashing, so collection.log never matched its own hash.)
        /// </summary>
        public void Seal(string reason)
        {
            lock (_gate)
            {
                if (LogFile == null) return;
                try { TextFile.AppendLine(LogFile, FotonTime.Format(UtcNow()) + " UTC  [Info] " + reason); }
                catch (Exception) { }
                LogFile = null;
            }
        }

        /// <summary>Console-only line (banner, summaries); never logged.</summary>
        public void WriteConsole(string line, ConsoleColor color = ConsoleColor.Gray)
        {
            lock (_gate)
            {
                if (!_color) { _console.WriteLine(line); return; }
                var old = Console.ForegroundColor;
                try { Console.ForegroundColor = color; _console.WriteLine(line); }
                finally { Console.ForegroundColor = old; }
            }
        }
    }
}
