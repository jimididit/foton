using System;
using System.IO;
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

        [Fact]
        public void Changelog_has_a_dated_section_for_the_current_version()
        {
            // release-v2.yml publishes this section as the release's "What's new"; a tag without one fails there.
            var text = File.ReadAllText(Path.Combine(TestPaths.Root, "CHANGELOG.md"));
            var heading = "## [" + FotonVersion.Product + "] - " + FotonVersion.ReleaseDate;
            var start = text.IndexOf(heading + "\n", StringComparison.Ordinal);
            if (start < 0) start = text.IndexOf(heading + "\r\n", StringComparison.Ordinal);
            Assert.True(start >= 0, "CHANGELOG.md has no '" + heading + "' section.");
            var body = text.Substring(start + heading.Length);
            var next = body.IndexOf("\n## ", StringComparison.Ordinal);
            if (next >= 0) body = body.Substring(0, next);
            Assert.False(string.IsNullOrWhiteSpace(body), heading + " is empty.");
        }
    }
}
