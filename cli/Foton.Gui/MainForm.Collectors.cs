using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools;

namespace Foton.Gui
{
    /// <summary>
    /// The Collectors tab: builds the folder an analyst carries to an endpoint (copy, RMM, or run on any machine, this
    /// one included), with the foton-collect.exe or foton-baseline.exe this console carries (the one released with it),
    /// the profile, RUN.txt, and SHA256SUMS.txt. The console never runs a collector and never asks for elevation: the
    /// collector runs on the endpoint, and its package comes back to the Cases tab. Same builder as foton bundle.
    /// </summary>
    sealed partial class MainForm
    {
        TabPage? _collectorsPage;
        readonly CheckBox _bundleUseProfile = new CheckBox { Text = "Use the profile on the Profile tab (otherwise every category, the collector's defaults)", AutoSize = true };
        readonly Label _bundleProfileName = new Label { AutoSize = true, Padding = new Padding(18, 0, 0, 4), ForeColor = SystemColors.GrayText };
        readonly TextBox _collectBundleOut = new TextBox { Width = 420 };
        readonly CheckBox _bundleUserHives = new CheckBox { Text = "Include users who are not signed in (-LoadUserHives)", AutoSize = true };
        readonly TextBox _baselineBundleOut = new TextBox { Width = 420 };
        readonly Button _showBundle = new Button { Text = "Show the last bundle", AutoSize = true, Enabled = false };
        string? _lastBundle;

        TabPage CollectorsTab()
        {
            var page = new TabPage("Collectors");
            var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
            layout.Controls.Add(new Label
            {
                Text = "Build a collector to run on an endpoint: copy the folder to it or push it with your RMM tool, run the command in its RUN.txt (an elevated " +
                       "prompt collects the most), and bring the package back here to open it on the Cases tab. The collector is the one released with this console. " +
                       "To collect this PC, build a bundle and run it here the same way.",
                AutoSize = true, MaximumSize = new Size(900, 0), Padding = new Padding(0, 0, 0, 8),
            });

            var collect = Group("Collection bundle (triage package)");
            collect.Controls.Add(_bundleUseProfile);
            collect.Controls.Add(_bundleProfileName);
            collect.Controls.Add(Row("Create it in", _collectBundleOut, BrowseButton(_collectBundleOut)));
            collect.Controls.Add(AddButton("Build collection bundle", () => BuildBundle(CollectorKind.Collect)));
            layout.Controls.Add(collect);

            var baseline = Group("Baseline bundle (known-state snapshot to compare later)");
            baseline.Controls.Add(_bundleUserHives);
            baseline.Controls.Add(Row("Create it in", _baselineBundleOut, BrowseButton(_baselineBundleOut)));
            baseline.Controls.Add(AddButton("Build baseline bundle", () => BuildBundle(CollectorKind.Baseline)));
            layout.Controls.Add(baseline);

            _showBundle.Click += (s, e) => { if (_lastBundle != null && Directory.Exists(_lastBundle)) Process.Start(new ProcessStartInfo(_lastBundle) { UseShellExecute = true }); };
            layout.Controls.Add(_showBundle);
            _bundleUseProfile.CheckedChanged += (s, e) => ShowBundleProfile();
            _tabs.Selected += (s, e) => { if (e.TabPage == _collectorsPage) ShowBundleProfile(); };
            page.Controls.Add(layout);
            return page;
        }

        static FlowLayoutPanel Group(string title)
        {
            var g = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Padding = new Padding(8), Margin = new Padding(0, 0, 0, 12), BorderStyle = BorderStyle.FixedSingle };
            g.Controls.Add(new Label { Text = title, AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 0, 0, 4) });
            return g;
        }

        static FlowLayoutPanel Row(string label, params Control[] inputs)
        {
            var r = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            r.Controls.Add(new Label { Text = label, Width = 110, Padding = new Padding(0, 6, 0, 0) });
            foreach (var i in inputs) r.Controls.Add(i);
            return r;
        }

        Button BrowseButton(TextBox box)
        {
            var b = new Button { Text = "Browse...", AutoSize = true };
            b.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog { Description = "Choose where to create the bundle folder", ShowNewFolderButton = true })
                {
                    if (Directory.Exists(box.Text)) d.SelectedPath = box.Text;
                    if (d.ShowDialog(this) == DialogResult.OK) box.Text = d.SelectedPath;
                }
            };
            return b;
        }

        /// <summary>Which profile a collection bundle would carry, said next to the choice.</summary>
        void ShowBundleProfile()
        {
            _bundleProfileName.Text = !_bundleUseProfile.Checked ? "No profile: every category, the collector's defaults."
                : _profile != null ? "Profile: " + TextFile.OneLine(_profile.Name) + " (edit it on the Profile tab)"
                : "The Profile tab's profile is not valid; fix it there first.";
        }

        /// <summary>Profile tab's Build bundle: the Collectors tab with its profile chosen.</summary>
        void BundleFromProfileTab()
        {
            _bundleUseProfile.Checked = true;
            if (_collectorsPage != null) _tabs.SelectedTab = _collectorsPage;
            ShowBundleProfile();
            _status.Text = "Collectors: choose where to create it and press Build collection bundle.";
        }

        async Task BuildBundle(CollectorKind kind)
        {
            var collect = kind == CollectorKind.Collect;
            if (collect && _bundleUseProfile.Checked && _profile == null) { _status.Text = "Not built: the Profile tab's profile is not valid."; return; }
            var parent = (collect ? _collectBundleOut : _baselineBundleOut).Text.Trim().Trim('"');
            if (ConsoleSettings.FullPath(parent) == null)
            {
                _status.Text = "Not built: the folder must be a full path, such as D:\\Bundles.";
                return;
            }
            // Read on the UI thread.
            var profile = collect && _bundleUseProfile.Checked ? _profile : null;
            var userHives = !collect && _bundleUserHives.Checked;
            DeploymentBundle? built = null;
            await Run(collect ? "Build collection bundle" : "Build baseline bundle", log =>
            {
                built = DeploymentBundle.Build(kind, EmbeddedCollectors.Read(kind), profile, userHives, parent, DateTime.UtcNow);
                log.Write($"{EmbeddedCollectors.FileName(kind)} {built.CollectorVersion} SHA-256 {built.CollectorSha256} (released with this console)", StatusLevel.Info);
                if (collect) log.Write(profile != null ? "Profile: " + TextFile.OneLine(profile.Name) : "No profile: every category, the collector's defaults", StatusLevel.Info);
                log.Write("Bundle: " + built.Folder + " (" + DeploymentBundle.ReadmeFileName + " has the command to run)", StatusLevel.Good);
                return null;
            });
            if (built == null) return;
            _lastBundle = built.Folder;
            _showBundle.Enabled = true;
            _status.Text = "Bundle built: " + built.Folder;
        }
    }
}
