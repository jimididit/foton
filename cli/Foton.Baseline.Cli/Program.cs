using System;
using Foton.Core;

namespace Foton.Baseline.Cli
{
    static class Program
    {
        static int Main(string[] args)
        {
            foreach (var line in FotonVersion.Describe("foton-baseline"))
                Console.WriteLine(line);
            if (args.Length == 1 && IsVersionSwitch(args[0]))
                return 0;
            Console.WriteLine();
            Console.WriteLine("Baseline capture is not implemented in this v2 pre-release.");
            Console.WriteLine("For casework use Foton 1.38.x (Foton-Baseline_v1.38.1_schema1.14.0.ps1) from https://github.com/jimididit/foton/releases.");
            return 1;
        }

        static bool IsVersionSwitch(string arg) =>
            string.Equals(arg, "-Version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "version", StringComparison.OrdinalIgnoreCase);
    }
}
