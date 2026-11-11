using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools;

namespace Foton.Gui
{
    /// <summary>
    /// The Profile tab: build a collection profile for foton-collect -Profile, checked after every change by the same
    /// CollectionProfile parser the collector uses, and package it with foton-collect.exe as a bundle for an endpoint.
    /// A category is collected while any of its tasks is checked; its unchecked tasks become ExcludeTasks.
    /// </summary>
    sealed partial class MainForm
    {
        static readonly string[] BoolOptions =
        {
            "LoadUserHives", "Deep", "IncludeFileTimeline", "IncludeUsnJournal", "SkipEvtxExport", "SkipHashing", "NoZip", "RequireAdministrator",
        };

        readonly TextBox _profileName = new TextBox { Width = 220 };
        readonly TextBox _profileDescription = new TextBox { Width = 420 };
        readonly TreeView _profileTasks = new TreeView { Dock = DockStyle.Fill, CheckBoxes = true, HideSelection = false };
        readonly Dictionary<string, CheckBox> _boolOptions = new Dictionary<string, CheckBox>(StringComparer.Ordinal);
        readonly Dictionary<string, KeyValuePair<CheckBox, NumericUpDown>> _intOptions = new Dictionary<string, KeyValuePair<CheckBox, NumericUpDown>>(StringComparer.Ordinal);
        readonly Label _profileStatus = new Label { Dock = DockStyle.Top, AutoSize = false, Height = 40, Padding = new Padding(4) };
        readonly TextBox _profileJson = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font(FontFamily.GenericMonospace, 9f) };
        readonly List<Button> _needsValidProfile = new List<Button>();
        /// <summary>The profile the controls describe, when it validates; null otherwise.</summary>
        CollectionProfile? _profile;
        bool _filling;

        TabPage ProfileTab()
        {
            var page = new TabPage("Profile");
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            bar.Controls.Add(AddButton("New", () => FillProfile(null)));
            bar.Controls.Add(AddButton("Load profile...", LoadProfile));
            var save = AddButton("Save profile...", SaveProfile);
            var bundle = AddButton("Build bundle...", BuildBundle);
            _needsValidProfile.Add(save);
            _needsValidProfile.Add(bundle);
            bar.Controls.Add(save);
            bar.Controls.Add(bundle);
            bar.Controls.Add(new Label { Text = "Name", AutoSize = true, Padding = new Padding(12, 6, 0, 0) });
            bar.Controls.Add(_profileName);
            bar.Controls.Add(new Label { Text = "Description", AutoSize = true, Padding = new Padding(6, 6, 0, 0) });
            bar.Controls.Add(_profileDescription);

            var options = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(6) };
            options.Controls.Add(new Label { Text = "Options (shaded: not set, the collector default applies)", AutoSize = true });
            foreach (var name in BoolOptions)
            {
                var box = new CheckBox { Text = name, ThreeState = true, CheckState = CheckState.Indeterminate, AutoSize = true };
                box.CheckStateChanged += (s, e) => ProfileChanged();
                _boolOptions[name] = box;
                options.Controls.Add(box);
            }
            foreach (var name in new[] { "EventLogDays", "MaxEventsPerLog" })
            {
                var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
                var set = new CheckBox { Text = name, AutoSize = true };
                var value = new NumericUpDown { Minimum = 0, Maximum = 1000000, Width = 90, Enabled = false };
                set.CheckedChanged += (s, e) => { value.Enabled = set.Checked; ProfileChanged(); };
                value.ValueChanged += (s, e) => ProfileChanged();
                row.Controls.Add(set);
                row.Controls.Add(value);
                _intOptions[name] = new KeyValuePair<CheckBox, NumericUpDown>(set, value);
                options.Controls.Add(row);
            }

            var right = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            right.Panel1.Controls.Add(options);
            right.Panel2.Controls.Add(_profileJson);
            right.Panel2.Controls.Add(_profileStatus);
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
            split.Panel1.Controls.Add(_profileTasks);
            split.Panel2.Controls.Add(right);
            Load += (s, e) => { SetSplit(split, 0.4); SetSplit(right, 0.45); };

            _profileTasks.AfterCheck += (s, e) => TaskChecked(e);
            _profileName.TextChanged += (s, e) => ProfileChanged();
            _profileDescription.TextChanged += (s, e) => ProfileChanged();

            page.Controls.Add(split);
            page.Controls.Add(bar);
            FillProfile(null);
            return page;
        }

        /// <summary>Shows a profile in the controls; null is a new profile that collects everything.</summary>
        void FillProfile(CollectionProfile? p)
        {
            _filling = true;
            try
            {
                _profileName.Text = p?.Name ?? "New profile";
                _profileDescription.Text = p?.Description ?? "";
                _profileTasks.BeginUpdate();
                _profileTasks.Nodes.Clear();
                foreach (var category in CollectionProfile.AllCategories)
                {
                    bool selected = p == null || p.Categories.Contains(category, StringComparer.OrdinalIgnoreCase);
                    var node = new TreeNode(category) { Tag = category, Checked = selected };
                    foreach (var task in CollectTasks.ByCategory[category])
                        node.Nodes.Add(new TreeNode(task) { Tag = task, Checked = selected && (p == null || !p.ExcludeTasks.Contains(task, StringComparer.OrdinalIgnoreCase)) });
                    _profileTasks.Nodes.Add(node);
                }
                _profileTasks.EndUpdate();
                foreach (var kv in _boolOptions)
                    kv.Value.CheckState = p != null && p.Options.TryGetValue(kv.Key, out var v) && v is bool b ? (b ? CheckState.Checked : CheckState.Unchecked) : CheckState.Indeterminate;
                foreach (var kv in _intOptions)
                {
                    bool set = p != null && p.Options.TryGetValue(kv.Key, out var v) && v is int;
                    kv.Value.Key.Checked = set;
                    kv.Value.Value.Value = set ? Math.Min(kv.Value.Value.Maximum, (int)p!.Options[kv.Key]) : 0;
                }
            }
            finally { _filling = false; }
            ProfileChanged();
        }

        /// <summary>A category box sets all its tasks; a task box sets its category (checked while any task is).</summary>
        void TaskChecked(TreeViewEventArgs e)
        {
            if (e.Action == TreeViewAction.Unknown || _filling) return;   // set below, not by the operator
            _filling = true;
            try
            {
                if (e.Node.Parent == null)
                    foreach (TreeNode child in e.Node.Nodes) child.Checked = e.Node.Checked;
                else
                    e.Node.Parent.Checked = e.Node.Parent.Nodes.Cast<TreeNode>().Any(n => n.Checked);
            }
            finally { _filling = false; }
            ProfileChanged();
        }

        /// <summary>Rebuilds the profile JSON from the controls and validates it as foton-collect -Profile would.</summary>
        void ProfileChanged()
        {
            if (_filling) return;
            var categories = new List<string>();
            var exclude = new List<string>();
            foreach (TreeNode node in _profileTasks.Nodes)
            {
                var tasks = node.Nodes.Cast<TreeNode>().ToList();
                var label = $"{node.Tag} ({tasks.Count(t => t.Checked)} of {tasks.Count})";
                if (node.Text != label) node.Text = label;
                if (!tasks.Any(t => t.Checked)) continue;
                categories.Add((string)node.Tag);
                exclude.AddRange(tasks.Where(t => !t.Checked).Select(t => (string)t.Tag));
            }
            var options = new SortedDictionary<string, object?>(StringComparer.Ordinal);
            foreach (var kv in _boolOptions)
                if (kv.Value.CheckState != CheckState.Indeterminate) options[kv.Key] = kv.Value.CheckState == CheckState.Checked;
            foreach (var kv in _intOptions)
                if (kv.Value.Key.Checked) options[kv.Key] = (int)kv.Value.Value.Value;

            var json = Json.Indented(new Dictionary<string, object?>
            {
                ["Name"] = _profileName.Text.Trim(),
                ["Description"] = _profileDescription.Text.Trim(),
                ["Categories"] = categories,
                ["ExcludeTasks"] = exclude,
                ["Options"] = options,
            });
            _profileJson.Text = json;
            _profile = null;
            try
            {
                if (_profileName.Text.Trim().Length == 0) throw new InvalidDataException("Give the profile a name; the bundle folder and the chain of custody use it.");
                var p = CollectionProfile.FromJson(json, "profile");
                var unknown = CollectTasks.Unknown(p.ExcludeTasks);
                if (unknown.Length > 0) throw new InvalidDataException("ExcludeTasks names no Collect task: " + string.Join(", ", unknown));
                _profile = p;
                _profileStatus.ForeColor = Color.DarkGreen;
                _profileStatus.Text = $"Valid: {p.Categories.Count} of {CollectionProfile.AllCategories.Count} categories, {p.ExcludeTasks.Count} task(s) excluded, {p.Options.Count} option(s) set. SHA-256 {p.Sha256}";
            }
            catch (InvalidDataException ex)
            {
                _profileStatus.ForeColor = Color.DarkRed;
                _profileStatus.Text = "Not valid: " + ex.Message;
            }
            UpdateButtons();
        }

        async Task LoadProfile()
        {
            string path;
            using (var d = new OpenFileDialog { Title = "Choose a collection profile", Filter = "Collection profile (*.json)|*.json", CheckFileExists = true })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                path = d.FileName;
            }
            CollectionProfile? loaded = null;
            await Run("Load profile", log =>
            {
                var p = CollectionProfile.Load(path);
                var unknown = CollectTasks.Unknown(p.ExcludeTasks);
                if (unknown.Length > 0) throw new InvalidDataException("ExcludeTasks names no Collect task: " + string.Join(", ", unknown));
                log.Write($"Loaded profile {TextFile.OneLine(p.Name)} ({p.Categories.Count} categories, {p.ExcludeTasks.Count} task(s) excluded)", StatusLevel.Good);
                loaded = p;
                return null;
            });
            if (loaded != null) FillProfile(loaded);
        }

        void SaveProfile()
        {
            if (_profile == null) return;
            using (var d = new SaveFileDialog { Title = "Save collection profile", Filter = "Collection profile (*.json)|*.json", FileName = DeploymentBundle.SafeName(_profile.Name) + ".json" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllBytes(d.FileName, _profile.Bytes);
                _status.Text = "Profile saved: " + d.FileName;
            }
        }

        async Task BuildBundle()
        {
            var profile = _profile;
            if (profile == null) return;
            string exe, parent;
            using (var d = new OpenFileDialog
            {
                Title = "Choose foton-collect.exe (a SHA256SUMS.txt beside it is checked)",
                Filter = "foton-collect.exe|foton-collect.exe|Programs (*.exe)|*.exe",
                CheckFileExists = true,
                InitialDirectory = AppDomain.CurrentDomain.BaseDirectory,
            })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                exe = d.FileName;
            }
            using (var d = new FolderBrowserDialog { Description = "Choose where to create the bundle folder", ShowNewFolderButton = true, SelectedPath = Path.GetDirectoryName(exe) })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                parent = d.SelectedPath;
            }
            await Run("Build bundle", log =>
            {
                var b = DeploymentBundle.Build(exe, profile, parent, DateTime.UtcNow);
                log.Write($"foton-collect {b.CollectVersion} SHA-256 {b.CollectSha256}", StatusLevel.Info);
                if (b.CollectVerified) log.Write("foton-collect.exe matches the SHA256SUMS.txt beside it.", StatusLevel.Good);
                else log.Write("foton-collect.exe NOT verified: no SHA256SUMS.txt beside it. Compare the hash with the release list before use.", StatusLevel.Warn);
                log.Write("Bundle: " + b.Folder + " (" + DeploymentBundle.ReadmeFileName + " has the command to run)", StatusLevel.Good);
                return null;
            });
        }
    }
}
