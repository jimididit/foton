using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace Foton.Package
{
    /// <summary>
    /// XML from a package (gpresult /x, task XML) as the nested maps and lists the Viewer's tree shows: an element is a
    /// map (attributes as @name, text as #text, children by name; repeated names become a list), and an element with
    /// only text is that text. DTDs are refused and nothing external is resolved, so a crafted file cannot read local
    /// files or expand entities.
    /// </summary>
    public static class XmlTree
    {
        public const string More = "(more elements not shown)";

        public static object Read(string path, int maxNodes)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreComments = true, IgnoreProcessingInstructions = true,
                MaxCharactersInDocument = 64L * 1024 * 1024,
            };
            XDocument doc;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var reader = XmlReader.Create(fs, settings))
                    doc = XDocument.Load(reader);
            }
            catch (XmlException ex) { throw new InvalidDataException("Not readable XML: " + ex.Message, ex); }
            var root = doc.Root ?? throw new InvalidDataException("The XML has no root element.");
            var budget = maxNodes;
            return new Dictionary<string, object> { [root.Name.LocalName] = Convert(root, ref budget) };
        }

        static object Convert(XElement e, ref int budget)
        {
            budget--;
            if (!e.HasAttributes && !e.HasElements) return e.Value;
            var map = new Dictionary<string, object>();
            foreach (var a in e.Attributes()) map["@" + a.Name.LocalName] = a.Value;
            var text = string.Concat(e.Nodes().OfType<XText>().Select(t => t.Value)).Trim();
            if (text.Length > 0) map["#text"] = text;
            foreach (var group in e.Elements().GroupBy(c => c.Name.LocalName))
            {
                var items = new List<object>();
                foreach (var c in group)
                {
                    if (budget <= 0) { map[More] = "true"; break; }
                    items.Add(Convert(c, ref budget));
                }
                if (items.Count > 0) map[group.Key] = items.Count == 1 ? items[0] : items.ToArray();
                if (map.ContainsKey(More)) break;
            }
            return map;
        }
    }
}
