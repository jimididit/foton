using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools;

namespace Foton.Gui
{
    /// <summary>
    /// The Tools tab: what compose can find on this workstation, installing the catalog-pinned releases, registering an
    /// existing install (EZ Tools), and which tools the next compose runs. Workstation setup only; nothing here touches a
    /// case package. Install and register call the same ToolInstaller / ToolRegistry foton tools uses.
    /// </summary>
    sealed partial class MainForm
    {
        readonly DataGridView _toolGrid = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        };
        readonly CheckedListBox _composeTools = new CheckedListBox { Dock = DockStyle.Fill, CheckOnClick = true, IntegralHeight = false };
        readonly ComboBox _registerName = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 170 };

        TabPage ToolsTab()
        {
            var page = new TabPage("Tools");
            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(4) };
            bar.Controls.Add(AddButton("Refresh", RefreshTools));
            foreach (var entry in ToolCatalog.Load())
            {
                var e = entry;
                bar.Controls.Add(AddButton("Install " + e.Name + "...", () => Install(e)));
            }
            bar.Controls.Add(new Label { Text = "Register existing", AutoSize = true, Padding = new Padding(12, 6, 0, 0) });
            _registerName.Items.Add("EZTools");
            foreach (var t in ComposeTools.All) _registerName.Items.Add(t.Name);
            _registerName.SelectedIndex = 0;
            bar.Controls.Add(_registerName);
            bar.Controls.Add(AddButton("Folder...", RegisterFolder));
            bar.Controls.Add(new Label
            {
                Text = "Tool root: " + ToolManifest.Root(null) + "   (PATH is never changed)",
                AutoSize = true, Padding = new Padding(12, 6, 0, 0),
            });

            foreach (var t in ComposeTools.All) _composeTools.Items.Add(t.Name, true);
            var picker = new GroupBox { Text = "Compose runs", Dock = DockStyle.Right, Width = 220, Padding = new Padding(6) };
            picker.Controls.Add(_composeTools);

            _toolGrid.DataBindingComplete += (s, e) => SizeToolColumns();
            page.Controls.Add(_toolGrid);
            page.Controls.Add(picker);
            page.Controls.Add(bar);
            RefreshTools();
            return page;
        }

        void RefreshTools()
        {
            var table = new System.Data.DataTable();
            foreach (var c in new[] { "Name", "Version", "Source", "Verified", "Location", "Notes" }) table.Columns.Add(c);
            foreach (var r in ToolInstaller.List(null))
                table.Rows.Add(r.Name, r.Version, r.Source, r.Verified ? "Yes" : "No", r.Location, r.Notes);
            _toolGrid.DataSource = table;
        }

        /// <summary>Columns exist only once the grid is bound on a shown form, so widths are set when binding completes.</summary>
        void SizeToolColumns()
        {
            var weights = new Dictionary<string, float> { ["Name"] = 12, ["Version"] = 10, ["Source"] = 9, ["Verified"] = 7, ["Location"] = 40, ["Notes"] = 40 };
            foreach (DataGridViewColumn c in _toolGrid.Columns)
                if (weights.TryGetValue(c.Name, out var w)) c.FillWeight = w;
        }

        /// <summary>
        /// Install a pinned release: download it, or take an archive already downloaded (an air-gapped workstation). The
        /// archive is refused unless its SHA-256 matches the catalog pin either way.
        /// </summary>
        async Task Install(CatalogTool entry)
        {
            var dest = ToolInstaller.Destination(entry, null);
            var answer = MessageBox.Show(this,
                $"Install {entry.Name} {entry.Version} into {dest}?\r\n\r\nLicense: {entry.License}  {entry.ProjectUrl}\r\nPinned SHA-256: {entry.ExpectedSha256}\r\n{entry.Notes}\r\n\r\n" +
                $"Yes downloads {entry.DownloadUrl}.\r\nNo picks an archive you already downloaded. Either way it is installed only if its SHA-256 matches the pin.",
                "Install " + entry.Name, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (answer == DialogResult.Cancel) return;
            string? archive = null;
            if (answer == DialogResult.No)
            {
                using (var d = new OpenFileDialog { Title = "Choose the downloaded " + entry.AssetName, Filter = "ZIP archive (*.zip)|*.zip", CheckFileExists = true })
                {
                    if (d.ShowDialog(this) != DialogResult.OK) return;
                    archive = d.FileName;
                }
            }
            await Run("Install " + entry.Name, log =>
            {
                ToolInstaller.Install(entry, archive, null, log);
                log.Write("PATH was not changed. Compose resolves this tool via tools.json.", StatusLevel.Good);
                return null;
            });
            RefreshTools();
        }

        async Task RegisterFolder()
        {
            var name = (string)_registerName.SelectedItem;
            string folder;
            using (var d = new FolderBrowserDialog { Description = $"Choose the folder that holds {name} (searched two levels deep)", ShowNewFolderButton = false })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                folder = d.SelectedPath;
            }
            await Run("Register " + name, log =>
            {
                foreach (var r in ToolRegistry.Register(name, folder, null))
                    log.WriteConsole($"   {r.Name,-20} {r.Status,-11} {r.Version,-16} {r.ExecutablePath}");
                log.Write("SHA-256 values in tools.json are observed on disk, not verified against an upstream hash.", StatusLevel.Warn);
                return null;
            });
            RefreshTools();
        }

        /// <summary>UI thread: the tools compose runs, or null when every tool is checked (the foton compose default).</summary>
        IReadOnlyCollection<string>? SelectedComposeTools()
        {
            if (_composeTools.CheckedItems.Count == _composeTools.Items.Count) return null;
            return _composeTools.CheckedItems.Cast<string>().ToList();
        }

        /// <summary>A compose step over the tools checked now (read on the UI thread, when the button is pressed).</summary>
        Func<StatusLog, string, object?> ComposeStep()
        {
            var only = SelectedComposeTools();
            return (log, path) =>
            {
                if (only != null) log.Write($"Compose runs {only.Count} of {ComposeTools.All.Count} tools (picked on the Tools tab).", StatusLevel.Info);
                return Compose(log, path, only);
            };
        }
    }
}
