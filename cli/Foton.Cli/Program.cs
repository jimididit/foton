using System;
using Foton.Core;

namespace Foton.Cli
{
    static class Program
    {
        static int Main(string[] args)
        {
            foreach (var line in FotonVersion.Describe("foton"))
                Console.WriteLine(line);
            if (args.Length == 1 && IsVersionSwitch(args[0]))
                return 0;
            Console.WriteLine();
            Console.WriteLine("Workstation parse, compose, analyze, and compare is not implemented in this v2 pre-release.");
            Console.WriteLine("For casework use Foton 1.38.x (the Foton-Workstation_v1.38.1.zip module) from https://github.com/jimididit/foton/releases.");
            return 1;
        }

        static bool IsVersionSwitch(string arg) =>
            string.Equals(arg, "-Version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase)
            || string.Equals(arg, "version", StringComparison.OrdinalIgnoreCase);
    }
}
