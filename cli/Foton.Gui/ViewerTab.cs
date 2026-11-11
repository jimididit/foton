using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Package;

namespace Foton.Gui
{
    /// <summary>
    /// The Viewer tab: the package's files on the left; the selected file on the right as a grid (CSV), a tree (JSON),
    /// or text, with its SHA-256 checked against hashes.csv. Read-only and capped, so a large artifact cannot exhaust
    /// memory. Binary artifacts show their size and hash only; parse and compose read those.
    /// </summary>
    sealed class ViewerTab
    {
        const int MaxCsvRows = 500000, PageRows = 1000, MaxTextChars = 5 * 1024 * 1024, MaxJsonNodes = 20000, MaxJsonValue = 500;

        readonly TreeView _files = new TreeView { Dock = DockStyle.Fill, HideSelection = false };
        readonly Label _header = new Label { Dock = DockStyle.Top, AutoSize = false, Height = 44, Padding = new Padding(4) };
        readonly TextBox _filter = new TextBox { Width = 260 };
        readonly Button _prev = new Button { Text = "< Previous", AutoSize = true };
        readonly Button _next = new Button { Text = "Next >", AutoSize = true };
        readonly Label _page = new Label { AutoSize = true, Padding = new Padding(6, 6, 0, 0) };
        readonly FlowLayoutPanel _csvBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(2) };
        readonly DataGridView _grid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
        };
        readonly TreeView _json = new TreeView { Dock = DockStyle.Fill };
        readonly TextBox _text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font(FontFamily.GenericMonospace, 9f) };
        readonly Panel _content = new Panel { Dock = DockStyle.Fill };

        string? _root;
        PackageHashes? _hashes;
        CsvTable? _table;
        List<int> _rows = new List<int>();
        int _pageIndex;
        int _loadVersion;
        /// <summary>Cancels the read for the previous selection, so quick clicks through large files do not pile up reads.</summary>
        System.Threading.CancellationTokenSource? _readCancel;

        public TabPage Page { get; }

        public ViewerTab()
        {
            Page = new TabPage("Viewer");
            _csvBar.Controls.Add(new Label { Text = "Find", AutoSize = true, Padding = new Padding(0, 6, 0, 0) });
            _csvBar.Controls.Add(_filter);
            _csvBar.Controls.Add(_prev);
            _csvBar.Controls.Add(_next);
            _csvBar.Controls.Add(_page);
            var right = new Panel { Dock = DockStyle.Fill };
            right.Controls.Add(_content);
            right.Controls.Add(_csvBar);
            right.Controls.Add(_header);
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
            split.Panel1.Controls.Add(_files);
            split.Panel2.Controls.Add(right);
            Page.Controls.Add(split);
            Page.Layout += (s, e) => { if (split.Width > 400 && split.SplitterDistance == 50) split.SplitterDistance = Math.Min(360, split.Width / 3); };

            _files.BeforeExpand += (s, e) => Expand(e.Node);
            _files.AfterSelect += async (s, e) => await Show(e.Node?.Tag as string);
            _filter.TextChanged += (s, e) => { if (_table != null) { _rows = _table.Filter(_filter.Text); _pageIndex = 0; ShowPage(); } };
            _prev.Click += (s, e) => { if (_pageIndex > 0) { _pageIndex--; ShowPage(); } };
            _next.Click += (s, e) => { if ((_pageIndex + 1) * PageRows < _rows.Count) { _pageIndex++; ShowPage(); } };
            Clear("Open a package on the Package tab.");
        }

        /// <summary>Shows a package's files. Reparse points (junctions, links) are listed but never followed.</summary>
        public void Load(string caseRoot)
        {
            _loadVersion++;   // a read still running for the previous package must not land here
            _readCancel?.Cancel();
            _root = Path.GetFullPath(caseRoot);
            _hashes = new PackageHashes(_root);
            _files.Nodes.Clear();
            var top = new TreeNode(Path.GetFileName(_root)) { Tag = null };
            _files.Nodes.Add(top);
            Fill(top, _root);
            top.Expand();
            Clear("Select a file.");
        }

        /// <summary>Selects a package file by its path relative to the case root (forward or back slashes); false when absent.</summary>
        public bool Select(string relativePath)
        {
            if (_root == null || _files.Nodes.Count == 0) return false;
            var node = _files.Nodes[0];
            foreach (var part in relativePath.Replace('/', '\\').Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                Expand(node);
                node.Expand();
                var next = node.Nodes.Cast<TreeNode>().FirstOrDefault(n => string.Equals(n.Text, part, StringComparison.OrdinalIgnoreCase));
                if (next == null) return false;
                node = next;
            }
            _files.SelectedNode = node;
            node.EnsureVisible();
            return true;
        }

        static void Fill(TreeNode node, string dir)
        {
            node.Nodes.Clear();
            DirectoryInfo[] dirs;
            FileInfo[] files;
            try
            {
                var info = new DirectoryInfo(dir);
                dirs = info.GetDirectories().OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToArray();
                files = info.GetFiles().OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { node.Nodes.Add(new TreeNode("(unreadable: " + TextFile.OneLine(ex.Message) + ")")); return; }
            foreach (var d in dirs)
            {
                var link = (d.Attributes & FileAttributes.ReparsePoint) != 0;
                var child = new TreeNode(d.Name + (link ? "  (link, not followed)" : "")) { Tag = link ? null : "dir:" + d.FullName };
                if (!link) child.Nodes.Add(new TreeNode("..."));   // filled on expand
                node.Nodes.Add(child);
            }
            foreach (var f in files)
            {
                // A file symlink can point outside the case folder: list it, never open or hash its target.
                var link = (f.Attributes & FileAttributes.ReparsePoint) != 0;
                node.Nodes.Add(new TreeNode(f.Name + (link ? "  (link, not followed)" : "")) { Tag = link ? null : f.FullName });
            }
        }

        static void Expand(TreeNode node)
        {
            if (node.Tag is string tag && tag.StartsWith("dir:", StringComparison.Ordinal) && node.Nodes.Count == 1 && node.Nodes[0].Text == "...")
                Fill(node, tag.Substring(4));
        }

        async Task Show(string? path)
        {
            // Any new selection, a folder included, makes a read still running for the previous one stale.
            var version = ++_loadVersion;
            _readCancel?.Cancel();
            if (path == null || path.StartsWith("dir:", StringComparison.Ordinal) || _root == null) return;
            _header.Text = Path.GetFileName(path) + Environment.NewLine + "Reading...";
            var hashes = _hashes;
            var cancel = _readCancel = new System.Threading.CancellationTokenSource();
            var loaded = await Task.Run(() => Read(path, hashes, cancel.Token));
            if (loaded == null || version != _loadVersion) return;   // cancelled, or a newer selection won
            _header.Text = loaded.Header;
            _table = loaded.Table;
            _csvBar.Visible = _table != null;
            _content.Controls.Clear();
            if (_table != null)
            {
                _filter.Text = "";
                _rows = _table.Filter("");
                _pageIndex = 0;
                _content.Controls.Add(_grid);
                ShowPage();
            }
            else if (loaded.Json != null)
            {
                _json.BeginUpdate();
                _json.Nodes.Clear();
                int budget = MaxJsonNodes;
                AddJson(_json.Nodes, "(root)", loaded.Json, ref budget);
                if (_json.Nodes.Count > 0) _json.Nodes[0].Expand();
                _json.EndUpdate();
                _content.Controls.Add(_json);
            }
            else
            {
                _text.Text = loaded.Text ?? "";
                _content.Controls.Add(_text);
            }
        }

        sealed class Loaded
        {
            public string Header = "";
            public CsvTable? Table;
            public object? Json;
            public string? Text;
        }

        /// <summary>
        /// Worker thread: reads, shapes, and hashes one file. Every failure becomes a message, never a throw; null when a
        /// newer selection cancelled it.
        /// </summary>
        static Loaded? Read(string path, PackageHashes? hashes, System.Threading.CancellationToken cancel)
        {
            var l = new Loaded();
            try
            {
                var info = new FileInfo(path);
                var sha = ArtifactReader.Sha256Hex(path, cancel);
                var status = hashes?.Status(path, sha) ?? "";
                var shape = ArtifactReader.ShapeOf(path);
                l.Header = $"{info.Name}  -  {info.Length.ToString("N0", CultureInfo.InvariantCulture)} bytes  -  {shape}{Environment.NewLine}SHA-256 {sha}  -  {status}";
                // A task with no data leaves a one-line "Foton: ..." note in place of its CSV or JSON: show it as text.
                var head = ArtifactReader.ReadText(path, 200, out _);
                if (head.StartsWith("Foton:", StringComparison.Ordinal) || head.StartsWith("WinFoton:", StringComparison.Ordinal)) shape = ArtifactShape.Text;
                switch (shape)
                {
                    case ArtifactShape.Csv:
                        l.Table = ArtifactReader.ReadCsv(path, MaxCsvRows, cancel);
                        break;
                    case ArtifactShape.Json:
                        var raw = ArtifactReader.ReadText(path, MaxTextChars, out var jsonCut);
                        if (jsonCut) { l.Text = raw + Environment.NewLine + "[Shown as text: larger than " + MaxTextChars.ToString("N0", CultureInfo.InvariantCulture) + " characters.]"; break; }
                        try { l.Json = Json.Parse(raw.TrimStart('\uFEFF')); }
                        catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException) { l.Text = "[Not valid JSON: " + ex.Message + "]" + Environment.NewLine + raw; }
                        break;
                    case ArtifactShape.Text:
                        l.Text = ArtifactReader.ReadText(path, MaxTextChars, out var cut);
                        if (cut) l.Text += Environment.NewLine + "[Truncated: showing the first " + MaxTextChars.ToString("N0", CultureInfo.InvariantCulture) + " characters.]";
                        break;
                    default:
                        l.Text = "Binary artifact: not shown here. Parse and compose read these files; the size and SHA-256 above identify it.";
                        break;
                }
            }
            catch (OperationCanceledException) { return null; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException || ex is ArgumentException)
            {
                l.Header = Path.GetFileName(path) + Environment.NewLine + "Could not read: " + TextFile.OneLine(ex.Message);
                l.Text = "";
            }
            return l;
        }

        void ShowPage()
        {
            if (_table == null) return;
            var dt = new DataTable();
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in _table.Columns)
            {
                var name = c.Length == 0 ? "(blank)" : c;
                while (!names.Add(name)) name += " ";   // duplicate headers stay visible as separate columns
                dt.Columns.Add(name);
            }
            foreach (var i in _rows.Skip(_pageIndex * PageRows).Take(PageRows))
            {
                // Shorter rows are padded; ReadCsv never yields a row wider than the columns.
                var cells = new object[_table.Columns.Count];
                var row = _table.Rows[i];
                for (int c = 0; c < cells.Length; c++) cells[c] = c < row.Length ? row[c] : "";
                dt.Rows.Add(cells);
            }
            _grid.DataSource = dt;
            _grid.AutoResizeColumns(DataGridViewAutoSizeColumnsMode.DisplayedCells);
            foreach (DataGridViewColumn c in _grid.Columns) if (c.Width > 400) c.Width = 400;
            int pages = Math.Max(1, (_rows.Count + PageRows - 1) / PageRows);
            _page.Text = string.Format(CultureInfo.InvariantCulture, "Page {0} of {1}  -  {2:N0} of {3:N0} rows{4}", _pageIndex + 1, pages, _rows.Count, _table.Rows.Count,
                _table.Truncated ? $" (first {MaxCsvRows:N0} rows of a larger file)" : "");
            _prev.Enabled = _pageIndex > 0;
            _next.Enabled = (_pageIndex + 1) * PageRows < _rows.Count;
        }

        static void AddJson(TreeNodeCollection into, string name, object? value, ref int budget)
        {
            if (budget-- <= 0) { if (budget == -1) into.Add(new TreeNode("[More nodes not shown]")); return; }
            switch (value)
            {
                case IDictionary<string, object> map:
                    var obj = into.Add(name + "  {" + map.Count + "}");
                    foreach (var kv in map) AddJson(obj.Nodes, kv.Key, kv.Value, ref budget);
                    break;
                case IEnumerable list when !(value is string):
                    var items = list.Cast<object?>().ToList();
                    var arr = into.Add(name + "  [" + items.Count + "]");
                    for (int i = 0; i < items.Count; i++) AddJson(arr.Nodes, "[" + i.ToString(CultureInfo.InvariantCulture) + "]", items[i], ref budget);
                    break;
                default:
                    var text = JsonValue(value);
                    into.Add(name + " = " + (text.Length > MaxJsonValue ? text.Substring(0, MaxJsonValue) + "..." : text));
                    break;
            }
        }

        static string JsonValue(object? v) => TextFile.OneLine(v switch
        {
            null => "null",
            bool b => b ? "true" : "false",
            string s => "\"" + s + "\"",
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => v.ToString() ?? "",
        });

        void Clear(string message)
        {
            _header.Text = message;
            _table = null;
            _csvBar.Visible = false;
            _content.Controls.Clear();
        }
    }
}
