using Foton.Report;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Report chrome and escaping are identical to 1.38.x (golden files).</summary>
    public class ReportTests
    {
        [Fact]
        public void Chrome_is_byte_identical_to_the_PowerShell_here_strings()
        {
            Assert.Equal(TestPaths.GoldenText("nav.css"), ReportChrome.NavCss);
            Assert.Equal(TestPaths.GoldenText("navbar.html"), ReportChrome.NavBarHtml);
            Assert.Equal(TestPaths.GoldenText("nav.js"), ReportChrome.NavScript);
            Assert.Equal(TestPaths.GoldenText("mark.svg"), ReportChrome.MarkSvg);
        }

        [Fact]
        public void Encode_matches_ConvertTo_FotonSafeHtml()
        {
            foreach (var line in TestPaths.GoldenText("safehtml.tsv").Split('\n'))
            {
                var parts = line.Split('\t');
                Assert.Equal(parts[1], Html.Encode(parts[0]));
            }
            Assert.Equal("", Html.Encode(null));
        }

        [Fact]
        public void SectionId_matches_Get_FotonReportSectionId()
        {
            foreach (var line in TestPaths.GoldenText("sectionid.tsv").Split('\n'))
            {
                var parts = line.Split('\t');
                Assert.Equal(parts[1], Html.SectionId(parts[0]));
            }
        }
    }
}
