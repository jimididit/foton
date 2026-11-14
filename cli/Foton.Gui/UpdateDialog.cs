using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools.Update;

namespace Foton.Gui
{
    /// <summary>
    /// Help > Check for updates, when a newer signed release is found: what it is, who signed it, where it will go, and
    /// that this copy stays. Install is the operator's choice; the dialog itself downloads nothing.
    /// </summary>
    sealed class UpdateDialog : Form
    {
        // Read-only and out of the tab order: focus starts on Download and install, not on a selected path.
        readonly TextBox _target = new TextBox { ReadOnly = true, Width = 430, TabStop = false };
        readonly string _version;

        /// <summary>The Foton-version folder the operator chose to install into.</summary>
        public string Target => _target.Text;

        public UpdateDialog(UpdateCheckResult result, string currentDir)
        {
            var s = result.Statement!;
            var key = result.SignedBy!;
            _version = s.Version;
            Text = "Update Foton";
            Font = new Font("Segoe UI", 9f);
            Size = new Size(660, 380);
            MinimumSize = new Size(560, 340);
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            ShowIcon = false;
            MinimizeBox = MaximizeBox = false;

            var body = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(14, 12, 14, 6) };
            Label Para(string text, bool muted = false)
            {
                var l = new Label { Text = text, AutoSize = true, MaximumSize = new Size(600, 0), Margin = new Padding(0, 0, 0, 8) };
                if (muted) l.ForeColor = SystemColors.GrayText;
                return l;
            }
            body.Controls.Add(Para($"Foton {s.Version} is available (released {s.ReleasedText}). You have Foton {FotonVersion.Product}."));
            body.Controls.Add(Para($"Signed by the Foton release key ({key.Role}), fingerprint {key.Fingerprint}. The download is checked against the signed hashes before anything is installed."));
            if (result.PendingVersion.Length > 0) body.Controls.Add(Para($"Foton {result.PendingVersion} is also published but not signed yet.", muted: true));

            _target.Text = UpdateInstall.DefaultTarget(currentDir, s.Version);
            var change = new Button { Text = "Change...", AutoSize = true };
            change.Click += (o, e) =>
            {
                using (var d = new FolderBrowserDialog { Description = $"Choose where to put the Foton-{_version} folder", ShowNewFolderButton = true })
                    if (d.ShowDialog(this) == DialogResult.OK) _target.Text = Path.Combine(d.SelectedPath, "Foton-" + _version);
            };
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 8) };
            row.Controls.Add(new Label { Text = "Install in", AutoSize = true, Padding = new Padding(0, 6, 8, 0) });
            row.Controls.Add(_target);
            row.Controls.Add(change);
            body.Controls.Add(row);
            body.Controls.Add(Para($"This copy stays in {currentDir}, so a case can be re-run with the version that produced it. Settings, recent cases, and registered tools carry over.", muted: true));

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
            var install = new Button { Text = "Download and install", AutoSize = true, DialogResult = DialogResult.OK };
            buttons.Controls.Add(close);
            buttons.Controls.Add(install);
            if (result.ReleaseUrl.Length > 0)
            {
                // A button, not a link: themed like the rest, readable in every palette.
                var notes = new Button { Text = "Release notes", AutoSize = true };
                notes.Margin = new Padding(notes.Margin.Left, notes.Margin.Top, 18, notes.Margin.Bottom);
                // ReleaseUrl is accepted only as this repository's https://github.com/.../releases/ page (GitHubRelease).
                notes.Click += (o, e) =>
                {
                    try { Process.Start(new ProcessStartInfo(result.ReleaseUrl) { UseShellExecute = true }); }
                    catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException)
                    {
                        MessageBox.Show(this, "No browser opened the release notes: " + TextFile.OneLine(ex.Message) + "\r\n\r\n" + result.ReleaseUrl,
                            "Release notes", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                };
                buttons.Controls.Add(notes);
            }
            AcceptButton = install;
            CancelButton = close;
            Controls.Add(body);
            Controls.Add(buttons);
            Theme.MarkPrimary(install);
            Theme.Adopt(this);
            ActiveControl = install;
        }
    }
}
