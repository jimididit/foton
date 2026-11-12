using System.IO;
using Foton.Core;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class CaseStagesTests
    {
        [Fact]
        public void Each_step_is_done_once_its_output_exists()
        {
            using (var t = new TempDir())
            {
                var c = t.File("Foton_HOST_20261110-120000Z");
                Directory.CreateDirectory(Path.Combine(c, CaseTree.CollectionFolder));
                var none = CaseIndex.Stages(c);
                Assert.False(none.Parsed || none.Composed || none.Analyzed || none.Timeline);

                Directory.CreateDirectory(Path.Combine(c, @"analysis\external"));
                File.WriteAllText(Path.Combine(c, @"analysis\parsed_records.csv"), "x");
                File.WriteAllText(Path.Combine(c, @"analysis\external\external_parse_inventory.csv"), "x");
                File.WriteAllText(Path.Combine(c, @"analysis\findings.csv"), "x");
                File.WriteAllText(Path.Combine(c, @"analysis\timeline.csv"), "x");
                var all = CaseIndex.Stages(c);
                Assert.True(all.Parsed && all.Composed && all.Analyzed && all.Timeline);
            }
        }
    }
}
