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
    /// The Acquire tab: collect or baseline this PC without a command prompt. The console never collects in process: it
    /// runs the foton-collect.exe / foton-baseline.exe beside it (checked against SHA256SUMS.txt) as its own process,
    /// through the Windows administrator prompt when asked, and follows the collector's own log. The console itself
    /// stays a standard process.
    /// </summary>
    sealed partial class MainForm
    {
        const string StandardUserNote =
            "Without administrator rights Foton cannot read the Security event log, Prefetch, Amcache, SRUM, other users' files, " +
            "or registry hives that are not loaded. Those gaps are recorded in the package.";

        TabPage? _comparePage;
        readonly CheckBox _useProfile = new CheckBox { Text = "Use the profile on the Profile tab (otherwise every category, collector defaults)", AutoSize = true };
        readonly TextBox _caseNumber = new TextBox { Width = 220 };
        readonly TextBox _examiner = new TextBox { Width = 220, Text = Environment.UserName };
        readonly TextBox _caseOutput = new TextBox { Width = 420, Text = CollectorLauncher.DefaultOutput(CollectorKind.Collect) };
        readonly CheckBox _collectAdmin = new CheckBox { Text = "Run as administrator (Windows will ask)", AutoSize = true, Checked = true };
        readonly TextBox _baselineOutput = new TextBox { Width = 420, Text = CollectorLauncher.DefaultOutput(CollectorKind.Baseline) };
        readonly CheckBox _loadUserHives = new CheckBox { Text = "Include users who are not signed in (-LoadUserHives)", AutoSize = true };
        readonly CheckBox _baselineAdmin = new CheckBox { Text = "Run as administrator (Windows will ask)", AutoSize = true, Checked = true };

        TabPage AcquireTab()
        {
            var page = new TabPage("Acquire");
            var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(8) };
            layout.Controls.Add(new Label
            {
                Text = "Collect or baseline THIS PC. Foton runs foton-collect.exe or foton-baseline.exe from the folder this console is in, after checking it against SHA256SUMS.txt. " +
                       "It runs in its own minimized window; close that window to stop it.",
                AutoSize = true, MaximumSize = new Size(900, 0), Padding = new Padding(0, 0, 0, 8),
            });

            var collect = Group("Collect this PC (triage package)");
            collect.Controls.Add(_useProfile);
            collect.Controls.Add(Row("Case number", _caseNumber));
            collect.Controls.Add(Row("Examiner", _examiner));
            collect.Controls.Add(Row("Output folder", _caseOutput));
            collect.Controls.Add(_collectAdmin);
            collect.Controls.Add(Note(_collectAdmin));
            collect.Controls.Add(AddButton("Start collection", () => StartAcquire(CollectorKind.Collect)));
            layout.Controls.Add(collect);

            var baseline = Group("Baseline this PC (known-state snapshot)");
            baseline.Controls.Add(Row("Output folder", _baselineOutput));
            baseline.Controls.Add(_loadUserHives);
            baseline.Controls.Add(_baselineAdmin);
            baseline.Controls.Add(Note(_baselineAdmin));
            baseline.Controls.Add(AddButton("Start baseline", () => StartAcquire(CollectorKind.Baseline)));
            layout.Controls.Add(baseline);

            page.Controls.Add(layout);
            return page;
        }

        static FlowLayoutPanel Group(string title)
        {
            var g = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Padding = new Padding(8), Margin = new Padding(0, 0, 0, 12), BorderStyle = BorderStyle.FixedSingle };
            g.Controls.Add(new Label { Text = title, AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont, FontStyle.Bold), Padding = new Padding(0, 0, 0, 4) });
            return g;
        }

        static FlowLayoutPanel Row(string label, Control input)
        {
            var r = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            r.Controls.Add(new Label { Text = label, Width = 110, Padding = new Padding(0, 6, 0, 0) });
            r.Controls.Add(input);
            return r;
        }

        /// <summary>The standard-user note, shown while the administrator box is cleared.</summary>
        static Label Note(CheckBox admin)
        {
            var note = new Label { Text = StandardUserNote, AutoSize = true, MaximumSize = new Size(760, 0), ForeColor = Color.DarkRed, Visible = !admin.Checked };
            admin.CheckedChanged += (s, e) => note.Visible = !admin.Checked;
            return note;
        }

        async Task StartAcquire(CollectorKind kind)
        {
            var exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, CollectorLauncher.FileName(kind));
            CollectorCheck check;
            try { check = CollectorLauncher.Check(exe, kind); }
            catch (Exception ex) when (ex is IOException || ex is InvalidDataException || ex is UnauthorizedAccessException)
            {
                _status.Text = "Not started: " + TextFile.OneLine(ex.Message);
                MessageBox.Show(this, ex.Message, "Not started", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            // The check holds the file until the collector has started (released there, or here on any other way out).
            using (check) await RunCollector(kind, check);
        }

        async Task RunCollector(CollectorKind kind, CollectorCheck check)
        {
            var collect = kind == CollectorKind.Collect;
            if (!check.Verified && MessageBox.Show(this,
                    $"There is no {DeploymentBundle.SumsFileName} beside {Path.GetFileName(check.Path)}, so it cannot be checked against a release.\r\n\r\nSHA-256 {check.Sha256}\r\n\r\nRun it anyway?",
                    "Unverified collector", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;
            if (collect && _useProfile.Checked && _profile == null)
            {
                _status.Text = "Not started: the Profile tab's profile is not valid.";
                return;
            }
            // The collector and the console start in different folders, so a relative path would name two places.
            var typedOut = (collect ? _caseOutput : _baselineOutput).Text.Trim().Trim('"');
            if (typedOut.Length > 0 && !CollectorLauncher.IsFullPath(typedOut))
            {
                _status.Text = "Not started: the output folder must be a full path, such as D:\\Cases.";
                MessageBox.Show(this, "The output folder must be a full path, such as D:\\Cases or \\\\server\\share\\Cases.", "Not started", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Everything the worker needs is read here, on the UI thread.
            var defaultOut = CollectorLauncher.DefaultOutput(kind);
            var outText = typedOut;
            var request = new AcquireRequest
            {
                Kind = kind,
                OutputPath = outText.Length == 0 || string.Equals(outText.TrimEnd('\\'), defaultOut, StringComparison.OrdinalIgnoreCase) ? null : outText,
                CaseNumber = _caseNumber.Text, Examiner = _examiner.Text, LoadUserHives = _loadUserHives.Checked,
            };
            var profileBytes = collect && _useProfile.Checked ? _profile!.Bytes : null;
            var elevated = (collect ? _collectAdmin : _baselineAdmin).Checked;
            var consoleVersion = FotonVersion.Product.Split('-')[0];
            string? root = null;
            int? exit = null;
            bool started = false;

            await Run(collect ? "Collect this PC" : "Baseline this PC", log =>
            {
                string? profileFile = null;
                try
                {
                    if (profileBytes != null)
                    {
                        profileFile = Path.Combine(Path.GetTempPath(), "foton-profile-" + Guid.NewGuid().ToString("N") + ".json");
                        File.WriteAllBytes(profileFile, profileBytes);
                        request.ProfilePath = profileFile;
                    }
                    var args = CollectorLauncher.Arguments(request);
                    log.Write($"{Path.GetFileName(check.Path)} {check.Version} SHA-256 {check.Sha256} ({(check.Verified ? "matches " + DeploymentBundle.SumsFileName : "NOT verified")})",
                        check.Verified ? StatusLevel.Good : StatusLevel.Warn);
                    if (!string.Equals(check.Version, consoleVersion, StringComparison.Ordinal))
                        log.Write($"{Path.GetFileName(check.Path)} is {check.Version}; this console is {consoleVersion}.", StatusLevel.Warn);
                    if (!elevated) log.Write(StandardUserNote, StatusLevel.Warn);
                    log.Write((elevated ? "Starting as administrator (Windows asks first): " : "Starting: ") + Path.GetFileName(check.Path) + (args.Length > 0 ? " " + args : ""), StatusLevel.Info);

                    var startedUtc = DateTime.UtcNow;
                    var psi = new ProcessStartInfo(check.Path, args)
                    {
                        UseShellExecute = true, WindowStyle = ProcessWindowStyle.Minimized, WorkingDirectory = Path.GetDirectoryName(check.Path)!,
                    };
                    if (elevated) psi.Verb = "runas";
                    Process? p;
                    try { p = Process.Start(psi); }
                    catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
                    {
                        log.Write("Not started: the administrator prompt was cancelled.", StatusLevel.Warn);
                        return null;
                    }
                    if (p == null) { log.Write("Not started: Windows did not return the process.", StatusLevel.Error); return null; }
                    started = true;
                    check.Dispose();   // Windows has the image now; the file no longer needs holding
                    log.Write("Running in its own minimized window; close that window to stop it.", StatusLevel.Info);

                    var parent = request.OutputPath ?? defaultOut;
                    LogTail? tail = null;
                    using (p)
                    {
                        while (true)
                        {
                            bool done = p.WaitForExit(500);
                            if (tail == null && (root = CollectorLauncher.FindNewRun(parent, kind, startedUtc)) != null)
                            {
                                tail = new LogTail(CollectorLauncher.LogPath(kind, root));
                                log.Write("Writing to " + root, StatusLevel.Info);
                            }
                            if (tail != null) foreach (var line in tail.ReadNewLines()) log.WriteConsole("   " + line);
                            if (done) break;
                        }
                        try { exit = p.ExitCode; }
                        catch (Exception ex) when (ex is InvalidOperationException || ex is System.ComponentModel.Win32Exception) { }
                    }
                    log.Write(exit == 0 ? "Finished." : exit == null ? "Finished (exit code not available)." : "Finished with exit code " + exit + ".",
                        exit == 0 ? StatusLevel.Good : StatusLevel.Warn);
                    if (root == null)
                        log.Write("No new package folder could be read under " + parent + ". If Windows asked for another account's password, the collector ran as that account " +
                            "and its output is private to that account and Administrators: open it while signed in as that account.", StatusLevel.Warn);
                    return null;
                }
                finally
                {
                    if (profileFile != null)
                        try { File.Delete(profileFile); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                }
            });

            if (!started || root == null) return;
            if (collect)
            {
                if (exit != 0 && MessageBox.Show(this, "The collector did not report success. Open what it wrote?", "Collect this PC",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    return;
                _tabs.SelectedIndex = 0;
                await Open(root);
                if (_caseRoot != null) await Run("Verify", Verify);
            }
            else if (exit == 0 || exit == null)
            {
                _difference.Text = Path.Combine(root, "baseline.json");
                var earlier = CollectorLauncher.EarlierBaseline(Path.GetDirectoryName(root.TrimEnd('\\'))!, root);
                _reference.Text = earlier != null ? Path.Combine(earlier, "baseline.json") : "";
                if (_comparePage != null) _tabs.SelectedTab = _comparePage;
                _status.Text = earlier != null
                    ? "Baseline captured: Compare is set to it and this host's previous baseline. Press Compare."
                    : "Baseline captured: it is the difference baseline in Compare; choose a reference (an earlier or golden baseline).";
            }
        }
    }
}
