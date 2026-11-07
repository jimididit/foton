using System.Text.RegularExpressions;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    public class FotonVersionTests
    {
        static readonly Regex SemVer = new Regex(@"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$");
        static readonly Regex Schema = new Regex(@"^\d+\.\d+\.\d+$");

        [Fact]
        public void Product_version_comes_from_build_props_not_a_literal()
        {
            Assert.Matches(SemVer, FotonVersion.Product);
            Assert.StartsWith("2.", FotonVersion.Product);
        }

        [Fact]
        public void Schema_versions_are_set()
        {
            Assert.Matches(Schema, FotonVersion.CollectSchema);
            Assert.Matches(Schema, FotonVersion.BaselineSchema);
            Assert.Matches(Schema, FotonVersion.FindingsSchema);
        }

        [Fact]
        public void Describe_names_the_executable_and_every_schema()
        {
            var lines = FotonVersion.Describe("foton-collect");
            Assert.Equal(4, lines.Length);
            Assert.StartsWith("foton-collect " + FotonVersion.Product, lines[0]);
            Assert.EndsWith(FotonVersion.CollectSchema, lines[1]);
            Assert.EndsWith(FotonVersion.BaselineSchema, lines[2]);
            Assert.EndsWith(FotonVersion.FindingsSchema, lines[3]);
        }
    }
}
