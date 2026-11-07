using System;
using Foton.Core;

namespace Foton.Collect.Cli
{
    static class Program
    {
        static int Main(string[] args)
        {
            foreach (var line in FotonVersion.Describe("foton-collect"))
                Console.WriteLine(line);
            if (args.Length == 1 && IsVersionSwitch(args[0]))
                return 0;
            Console.WriteLine();
            Console.WriteLine("Live triage collection is not implemented in this v2 pre-release.");
            Console.WriteLine("For casework use Foton 1.38.x (Foton-Collect_v1.38.1_schema1.13.0.ps1) from https://github.com/jimididit/foton/releases.");
            return 1;
        }

        static bool IsVersionSwitch(string arg) =>
            string.Equals(arg, "-Version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "version", StringComparison.OrdinalIgnoreCase);
    }
}
