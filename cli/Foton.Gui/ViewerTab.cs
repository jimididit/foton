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
        readonly TextBox _text = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = Theme.MonoFont(9f) };
        readonly Panel _content = new Panel { Dock = DockStyle.Fill };
        readonly CheckBox _source = new CheckBox { Text = "Show source (the file's markup, as text)", AutoSize = true, Padding = new Padding(4, 2, 0, 2) };
        readonly Button _toTimeline = new Button { Text = "Show in timeline", AutoSize = true };
        Loaded? _loaded;
        /// <summary>A file and data row (1-based) to show once that file has loaded (Select with a row).</summary>
        string? _pendingPath;
        int _pendingRow;

        /// <summary>Show in timeline on a row: its artifact (relative to the case root), its data row, and its time.</summary>
        public event Action<string, int, DateTime>? ShowInTimeline;
        /// <summary>A one-line note for the status bar.</summary>
        public event Action<string>? Message;
        /// <summary>Note on row: the artifact (relative to the case root) and data row (1-based).</summary>
        public event Action<string, int>? NoteOnRow;
        readonly Button _noteRow = new Button { Text = "Note on row...", AutoSize = true };

        string? _root;
        PackageHashes? _hashes;
        string _hashesNote = "";
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
            _csvBar.Controls.Add(_toTimeline);
            _toTimeline.Click += (s, e) => TimelineJump();
            _csvBar.Controls.Add(_noteRow);
            _noteRow.Click += (s, e) => NoteRow();
            var right = new Panel { Dock = DockStyle.Fill };
            right.Controls.Add(_content);
            right.Controls.Add(_csvBar);
            right.Controls.Add(_source);
            right.Controls.Add(_header);
            _source.Dock = DockStyle.Top;
            _source.Visible = false;
            _source.CheckedChanged += (s, e) => Display();
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
            // Clear first, so a failure below never leaves the previous package's files on screen.
            _root = null;
            _hashes = null;
            _files.Nodes.Clear();
            Clear("Loading...");
            var root = Path.GetFullPath(caseRoot);
            // An unreadable hash list is a stated limitation of this view, not a reason to hide the files.
            try { _hashes = new PackageHashes(root); _hashesNote = ""; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException)
            {
                _hashesNote = "hashes.csv could not be read (" + TextFile.OneLine(ex.Message) + "): integrity not checked.";
            }
            _root = root;
            var top = new TreeNode(Path.GetFileName(_root)) { Tag = null };
            _files.Nodes.Add(top);
            Fill(top, _root);
            top.Expand();
            Clear("Select a file.");
        }

        /// <summary>Ctrl+F: the Find box of a CSV on screen.</summary>
        public void FocusFind()
        {
            if (_csvBar.Visible) _filter.Focus();
        }

        /// <summary>Selects a package file by its path relative to the case root (forward or back slashes); false when absent.</summary>
        public bool Select(string relativePath) => Select(relativePath, 0);

        /// <summary>Selects a package file and, for a CSV, shows its data row <paramref name="row"/> (1 is the first after the header; 0 for none).</summary>
        public bool Select(string relativePath, int row)
        {
            _pendingPath = null;
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
            if (row > 0 && node.Tag is string file && !file.StartsWith("dir:", StringComparison.Ordinal))
            {
                // Already shown: go to the row now. Otherwise Display goes there once the file has loaded.
                if (_files.SelectedNode == node && _loaded?.Path == file)
                {
                    if (_table != null) GoToRow(row);
                    else Message?.Invoke("That file is not shown as a table here, so its row cannot be selected.");
                }
                else { _pendingPath = file; _pendingRow = row; }
            }
            _files.SelectedNode = node;
            node.EnsureVisible();
            return true;
        }

        /// <summary>UI thread: shows data row <paramref name="row"/> (1-based) of the CSV on screen, clearing Find.</summary>
        void GoToRow(int row)
        {
            if (_table == null) return;
            var index = row - 1;
            if (index < 0 || index >= _table.Rows.Count)
            {
                Message?.Invoke($"Row {row} is not among the {_table.Rows.Count:N0} rows read here" + (_table.Truncated ? $" (the first {MaxCsvRows:N0} of the file)." : "."));
                return;
            }
            if (_filter.Text.Length > 0) _filter.Text = "";   // raises TextChanged: every row, first page
            _pageIndex = index / PageRows;
            ShowPage();
            // Found by its data row, not its position, so a sort the grid applies cannot select a different row.
            if (!(_grid.DataSource is DataTable dt) || index % PageRows >= dt.Rows.Count) return;
            var wanted = dt.Rows[index % PageRows];
            var target = _grid.Rows.Cast<DataGridViewRow>().FirstOrDefault(g => g.DataBoundItem is DataRowView v && ReferenceEquals(v.Row, wanted));
            if (target == null) return;
            var first = _grid.Columns.Cast<DataGridViewColumn>().FirstOrDefault(c => c.Visible);
            if (first != null) _grid.CurrentCell = target.Cells[first.Index];
            target.Selected = true;
            _grid.FirstDisplayedScrollingRowIndex = target.Index;
        }

        /// <summary>The selected CSV row: its file relative to the case root and its index in the table (0 is data row 1).</summary>
        bool SelectedRow(out string relative, out int index)
        {
            relative = "";
            index = -1;
            var loaded = _loaded;
            if (_table == null || loaded == null || _root == null) return false;
            if (!(_grid.CurrentRow?.DataBoundItem is DataRowView view) || !(_grid.DataSource is DataTable dt)) { Message?.Invoke("Select a row first."); return false; }
            var position = _pageIndex * PageRows + dt.Rows.IndexOf(view.Row);   // the page's own order, whatever the grid is sorted by
            if (position < 0 || position >= _rows.Count) return false;
            var rel = Relative(loaded.Path);
            if (rel == null) return false;
            relative = rel;
            index = _rows[position];
            return true;
        }

        void NoteRow()
        {
            if (SelectedRow(out var relative, out var index)) NoteOnRow?.Invoke(relative, index + 1);
        }

        /// <summary>The selected CSV row's time, handed to the Timeline tab with its artifact and row.</summary>
        void TimelineJump()
        {
            if (_table == null || !SelectedRow(out var relative, out var index)) return;
            if (!Foton.Analyze.Timeline.TimelineReader.TimeOfRow(relative, _table.Columns, _table.Rows[index], out var utc))
            {
                Message?.Invoke("This row has no time the timeline reads.");
                return;
            }
            ShowInTimeline?.Invoke(relative, index + 1, utc);
        }

        /// <summary>A file under the loaded case root, relative to it; null for anything else.</summary>
        string? Relative(string path)
        {
            if (_root == null) return null;
            var root = _root.TrimEnd('\\') + "\\";
            return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? path.Substring(root.Length) : null;
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
            if (!string.Equals(_pendingPath, path, StringComparison.OrdinalIgnoreCase)) _pendingPath = null;   // a row asked for in another file
            if (path == null || path.StartsWith("dir:", StringComparison.Ordinal) || _root == null) return;
            _header.Text = Path.GetFileName(path) + Environment.NewLine + "Reading...";
            var hashes = _hashes;
            var note = _hashesNote;
            var cancel = _readCancel = new System.Threading.CancellationTokenSource();
            var loaded = await Task.Run(() => Read(path, hashes, note, cancel.Token));
            if (loaded == null || version != _loadVersion) return;   // cancelled, or a newer selection won
            _header.Text = loaded.Header;
            _loaded = loaded;
            _source.Visible = loaded.Source != null;
            if (_source.Checked) _source.Checked = false;   // raises Display
            else Display();
        }

        /// <summary>UI thread: shows the loaded file, or its markup when Show source is on (HTML and XML only).</summary>
        void Display()
        {
            var loaded = _loaded;
            if (loaded == null) return;
            _table = loaded.Table;
            _csvBar.Visible = _table != null;
            var relative = Relative(loaded.Path);
            _toTimeline.Visible = _table != null && relative != null && Foton.Analyze.Timeline.TimelineReader.ReadsFile(relative);
            _content.Controls.Clear();
            if (_source.Checked && loaded.Source != null)
            {
                _text.Text = loaded.Source;
                _content.Controls.Add(_text);
            }
            else if (_table != null)
            {
                _filter.Text = "";
                _rows = _table.Filter("");
                _pageIndex = 0;
                _content.Controls.Add(_grid);
                ShowPage();
                if (_pendingPath != null && string.Equals(_pendingPath, loaded.Path, StringComparison.OrdinalIgnoreCase))
                {
                    _pendingPath = null;
                    GoToRow(_pendingRow);
                }
            }
            else if (loaded.Json != null)
            {
                _json.BeginUpdate();
                _json.Nodes.Clear();
                int budget = MaxJsonNodes;
                AddJson(_json.Nodes, "(root)", loaded.Json, ref budget);
                if (_json.Nodes.Count > 0)
                {
                    _json.Nodes[0].Expand();
                    if (_json.Nodes[0].Nodes.Count == 1) _json.Nodes[0].Nodes[0].Expand();   // XML: open the document element too
                }
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
            public string Path = "";
            public string Header = "";
            public CsvTable? Table;
            public object? Json;
            public string? Text;
            /// <summary>The raw markup of an HTML or XML file, for Show source.</summary>
            public string? Source;
        }

        /// <summary>
        /// Worker thread: reads, shapes, and hashes one file. Every failure becomes a message, never a throw; null when a
        /// newer selection cancelled it.
        /// </summary>
        static Loaded? Read(string path, PackageHashes? hashes, string hashesNote, System.Threading.CancellationToken cancel)
        {
            var l = new Loaded { Path = path };
            try
            {
                var info = new FileInfo(path);
                var sha = ArtifactReader.Sha256Hex(path, cancel);
                var status = hashes != null ? hashes.Status(path, sha) : hashesNote;
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
                    case ArtifactShape.Html:
                        // Never rendered: HTML written on an endpoint can contain anything, and the in-box browser control is
                        // not a sandbox. Reports this console builds open in the browser from the Package or Compare tab.
                        var html = ArtifactReader.ReadText(path, MaxTextChars, out var htmlCut);
                        var htmlNote = htmlCut ? Environment.NewLine + "[Truncated: the first " + MaxTextChars.ToString("N0", CultureInfo.InvariantCulture) + " characters.]" : "";
                        l.Source = html + htmlNote;
                        l.Text = "[HTML from the package, shown as text. It is not rendered: HTML written on an endpoint can contain anything.]"
                            + Environment.NewLine + Environment.NewLine + HtmlText.ToText(html) + htmlNote;
                        break;
                    case ArtifactShape.Xml:
                        l.Source = ArtifactReader.ReadText(path, MaxTextChars, out var xmlCut)
                            + (xmlCut ? Environment.NewLine + "[Truncated: the first " + MaxTextChars.ToString("N0", CultureInfo.InvariantCulture) + " characters.]" : "");
                        try { l.Json = XmlTree.Read(path, MaxJsonNodes); }
                        catch (Exception ex) when (ex is InvalidDataException || ex is System.Xml.XmlException || ex is InvalidOperationException)
                        {
                            l.Text = "[Not shown as a tree: " + TextFile.OneLine(ex.Message) + "]" + Environment.NewLine + l.Source;
                        }
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
            Tidy.FillLastColumn(_grid);
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
            _loaded = null;
            _source.Visible = false;
            _csvBar.Visible = false;
            _content.Controls.Clear();
        }
    }
}
