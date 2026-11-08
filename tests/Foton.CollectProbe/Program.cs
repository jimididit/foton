using System;
using System.Linq;
using Foton.Collect;
using Foton.Core;

namespace Foton.CollectProbe
{
    /// <summary>Usage: Foton.CollectProbe -OutputPath &lt;folder&gt; [-Category System,Users,...] (no -Category: none).</summary>
    static class Program
    {
        static int Main(string[] args)
        {
            string? output = null;
            var categories = new string[0];
            for (int i = 0; i + 1 < args.Length; i += 2)
            {
                if (string.Equals(args[i], "-OutputPath", StringComparison.OrdinalIgnoreCase)) output = args[i + 1];
                else if (string.Equals(args[i], "-Category", StringComparison.OrdinalIgnoreCase))
                    categories = args[i + 1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(c => c.Trim()).ToArray();
                else { Console.Error.WriteLine("Unknown argument: " + args[i]); return 1; }
            }
            if (output == null) { Console.Error.WriteLine("Usage: Foton.CollectProbe -OutputPath <folder> [-Category a,b]"); return 1; }
            var s = CollectRun.NewSession(new SessionOptions { OutputPath = output, Examiner = Environment.UserName, NoZip = true }, new StatusLog());
            var r = CollectRun.Run(s, categories);
            Console.WriteLine(r.CaseRoot);
            return 0;
        }
    }
}
