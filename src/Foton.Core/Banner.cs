using System;
using System.Text;

namespace Foton.Core
{
    /// <summary>
    /// Console banner. Cosmetic only: never logged, never in the package, and a render problem never
    /// stops a run. The block wordmark is used when the console encoding can carry it, else ASCII.
    /// </summary>
    public static class Banner
    {
        public enum Kind { Collect, Baseline, Analyze, Parse, Carve, Compare, Workstation }

        // Figlet ANSI Shadow "FOTON" (box-drawing / block glyphs).
        static readonly string[] Shadow =
        {
            "███████╗ ██████╗ ████████╗ ██████╗ ███╗   ██╗",
            "██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗████╗  ██║",
            "█████╗  ██║   ██║   ██║   ██║   ██║██╔██╗ ██║",
            "██╔══╝  ██║   ██║   ██║   ██║   ██║██║╚██╗██║",
            "██║     ╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║",
            "╚═╝      ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝",
        };

        // Figlet Standard: pure ASCII for consoles that cannot carry the block range.
        static readonly string[] Ascii =
        {
            @" _____ ___ _____ ___  _   _ ",
            @"|  ___/ _ \_   _/ _ \| \ | |",
            @"| |_ | | | || || | | |  \| |",
            @"|  _|| |_| || || |_| | |\  |",
            @"|_|   \___/ |_| \___/|_| \_|",
        };

        public static string ModeText(Kind k)
        {
            switch (k)
            {
                case Kind.Baseline: return "Baseline (stable config snapshot)";
                case Kind.Analyze: return "Analyze  (offline package)";
                case Kind.Parse: return "Parse    (offline artifacts)";
                case Kind.Carve: return "Carve    (signature scan, Tier 3)";
                case Kind.Compare: return "Compare  (offline baseline diff)";
                case Kind.Workstation: return "Workstation (offline package tools)";
                default: return "Collect  (live triage on this host)";
            }
        }

        public static void Write(StatusLog log, Kind kind)
        {
            try
            {
                var word = CanRenderBlocks() ? Shadow : Ascii;
                log.WriteConsole("");
                for (int i = 0; i < word.Length; i++)
                    log.WriteConsole("  " + word[i], i < word.Length / 2 ? ConsoleColor.Blue : ConsoleColor.Cyan);
            }
            catch (Exception)
            {
                log.WriteConsole("");
                log.WriteConsole("  FOTON");
            }
            log.WriteConsole("");
            log.WriteConsole("     Windows DFIR / baseline / audit", ConsoleColor.Gray);
            log.WriteConsole("     Author      jimididit", ConsoleColor.DarkGray);
            log.WriteConsole("     Version     " + FotonVersion.Product, ConsoleColor.DarkGray);
            log.WriteConsole("     Updated     " + FotonVersion.ReleaseDate, ConsoleColor.DarkGray);
            log.WriteConsole("     Mode        " + ModeText(kind), ConsoleColor.Gray);
            log.WriteConsole("     Opening a window...closes a door", ConsoleColor.DarkGray);
            log.WriteConsole("");
        }

        /// <summary>True when the console output encoding round-trips U+2588 (not a CP437/CP1252 console).</summary>
        static bool CanRenderBlocks()
        {
            try
            {
                if (Console.IsOutputRedirected) return false;
                var enc = Console.OutputEncoding;
                if (enc.CodePage == 65001) return true;
                var probe = "█╗";
                return enc.GetString(enc.GetBytes(probe)) == probe;
            }
            catch (Exception) { return false; }
        }
    }
}
