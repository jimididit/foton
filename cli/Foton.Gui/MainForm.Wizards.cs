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
    /// The three wizards (Start here, Tools > Wizards): work a case, build a collector, compare baselines. Each step calls
    /// the same method as the tab it stands for (Open, Verify, Parse, Compose, Analyze, Export handoff, BuildBundleAt,
    /// Compare), so a wizard never does anything the tabs cannot. To add a wizard, build its steps here and add it to
    /// the Tools > Wizards menu and, if it is a first step for newcomers, to Start here.
    /// </summary>
    sealed partial class MainForm
    {
        static Label Says(string text) => new Label { Text = text, AutoSize = true, MaximumSize = new Size(620, 0), Padding = new Padding(0, 4, 0, 8) };

        static FlowLayoutPanel Column() => new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };

        void RunWizard(string title, List<WizardStep> steps)
        {
            if (_busy) { _status.Text = "Wait for the current action to finish."; return; }
            using (var d = new WizardDialog(title, steps)) d.ShowDialog(this);
        }

        /// <summary>The case and baseline list, read once if the Cases tab has not listed them yet.</summary>
        async Task EnsureCaseList()
        {
            if (_caseList == null) await RefreshCases();
        }

        static string Severities(IEnumerable<string> severities)
        {
            var list = severities.ToList();
            return string.Join(", ", SeverityOrder.Select(s => $"{list.Count(x => x == s)} {s}"));
        }

        // ----- Work a case -----

        async Task WorkCaseWizard()
        {
            await EnsureCaseList();
            string? chosen = _caseRoot != null ? _path.Text : null;
            bool parse = true, compose = true, analyze = true;
            var steps = new List<WizardStep>
            {
                new WizardStep
                {
                    Name = "Choose the case",
                    Text = "Pick the case package to work on: a case in the listed folders, a recent one, or a folder or ZIP you browse to. A ZIP is extracted beside itself, as with foton.exe.",
                    Build = () =>
                    {
                        var col = Column();
                        var list = new ListBox { Width = 620, Height = 170, HorizontalScrollbar = true };
                        var paths = (_caseList?.Cases.Select(c => c.Path) ?? Enumerable.Empty<string>()).Concat(_settings.RecentCases)
                            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                        foreach (var p in paths) list.Items.Add(p);
                        if (chosen != null && !paths.Contains(chosen, StringComparer.OrdinalIgnoreCase)) list.Items.Insert(0, chosen);
                        if (chosen != null) list.SelectedItem = list.Items.Cast<string>().First(p => string.Equals(p, chosen, StringComparison.OrdinalIgnoreCase));
                        list.SelectedIndexChanged += (s, e) => chosen = list.SelectedItem as string;
                        var browse = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
                        var folder = new Button { Text = "Folder...", AutoSize = true };
                        folder.Click += (s, e) => { var p = PickFolder(); if (p != null) { list.Items.Insert(0, p); list.SelectedIndex = 0; } };
                        var zip = new Button { Text = "ZIP...", AutoSize = true };
                        zip.Click += (s, e) => { var p = PickZip(); if (p != null) { list.Items.Insert(0, p); list.SelectedIndex = 0; } };
                        browse.Controls.Add(folder);
                        browse.Controls.Add(zip);
                        col.Controls.Add(list);
                        col.Controls.Add(browse);
                        if (list.Items.Count == 0) col.Controls.Add(Says("No cases in the listed folders yet: browse to a case folder or ZIP."));
                        return col;
                    },
                    NextText = "Open",
                    Next = async () =>
                    {
                        if (chosen == null) return StepResult.Stay("Not opened: choose a case first.");
                        if (_packagePage != null) _tabs.SelectedTab = _packagePage;
                        await Open(chosen);
                        return _caseRoot == null ? StepResult.Stay("Not opened: see the log.") : StepResult.Next($"Opened {Path.GetFileName(_caseRoot)}: {_allFindings.Count} finding(s) so far.");
                    },
                },
                new WizardStep
                {
                    Name = "Verify",
                    Text = "Check every file against the package's hashes.csv, so you know the copy you analyze is the one collected. A package that does not verify can still be analyzed: record it in your case notes.",
                    Build = () => Says("Verify reads every file listed in 00_Collection\\hashes.csv and compares its SHA-256. It changes nothing."),
                    NextText = "Verify",
                    Skippable = true,
                    Next = async () =>
                    {
                        var path = _path.Text;
                        await VerifyOpenPackage();
                        if (!_packageVerified.TryGetValue(path, out var ok)) return StepResult.Stay("Not verified: see the log.");
                        return StepResult.Next(ok ? "Every file matches hashes.csv." : "The package does not verify (see the log); record it in your case notes. The next steps still work on it as it is.");
                    },
                },
                new WizardStep
                {
                    Name = "Parse, compose, analyze",
                    Text = "Turn the copied artifacts into findings. Parse reads Prefetch, shortcuts, jump lists, event logs, and Amcache; Compose runs EZ Tools, Hayabusa, and Chainsaw if installed (Tools tab; a missing tool is listed, not an error); Analyze builds the findings and the report from all of it.",
                    Build = () =>
                    {
                        var col = Column();
                        var p = new CheckBox { Text = "Parse", Checked = parse, AutoSize = true };
                        var c = new CheckBox { Text = "Compose (EZ Tools, Hayabusa, Chainsaw)", Checked = compose, AutoSize = true };
                        var a = new CheckBox { Text = "Analyze", Checked = analyze, AutoSize = true };
                        p.CheckedChanged += (s, e) => parse = p.Checked;
                        c.CheckedChanged += (s, e) => compose = c.Checked;
                        a.CheckedChanged += (s, e) => analyze = a.Checked;
                        col.Controls.Add(p);
                        col.Controls.Add(c);
                        col.Controls.Add(a);
                        col.Controls.Add(Says("A large case can take several minutes; the log under the window follows each step."));
                        return col;
                    },
                    NextText = "Run",
                    Skippable = true,
                    Next = async () =>
                    {
                        if (!parse && !compose && !analyze) return StepResult.Stay("Not run: check at least one step.");
                        var composeStep = compose ? ComposeStep() : null;
                        var label = string.Join(", ", new[] { parse ? "parse" : null, compose ? "compose" : null, analyze ? "analyze" : null }.Where(x => x != null));
                        await Run(char.ToUpperInvariant(label[0]) + label.Substring(1), (log, path) =>
                        {
                            if (parse) Parse(log, path);
                            composeStep?.Invoke(log, path);
                            return analyze ? Analyze(log, path) : null;
                        });
                        return StepResult.Next(analyze ? $"Done: {_allFindings.Count} finding(s) ({Severities(_allFindings.Select(f => f.TryGetValue("Severity", out var s) ? s ?? "" : ""))})." : "Done: run Analyze to turn the results into findings.");
                    },
                },
                new WizardStep
                {
                    Name = "Review",
                    Text = "Give each finding a status (Relevant, Not relevant, Follow up, Reviewed) and a note. Findings are observations, not conclusions: each says why it matters and names a benign explanation.",
                    Build = () =>
                    {
                        var col = Column();
                        var open = _allFindings.Count(f => !HasStatus(f));
                        col.Controls.Add(Says($"{_allFindings.Count} finding(s): {Severities(_allFindings.Select(f => f.TryGetValue("Severity", out var s) ? s ?? "" : ""))}. {open} without a status yet."));
                        var review = new Button { Text = "Review them on the Package tab", AutoSize = true };
                        review.Click += (s, e) => { ReviewNextFinding(); review.FindForm()?.Close(); };
                        col.Controls.Add(review);
                        col.Controls.Add(Says("That closes the wizard and shows the findings without a status; start it again for the handoff."));
                        return col;
                    },
                    Skippable = true,
                },
                new WizardStep
                {
                    Name = "Hand off",
                    Text = "Write the review for another examiner: findings, your notes, a handoff page, and copies of the custody record and hash list, with SHA256SUMS.txt. The package itself is named by its hashes, not copied.",
                    Build = () => Says("The handoff goes under " + _settings.HandoffsFolder + " (Settings > Folders changes it)."),
                    NextText = "Export handoff",
                    Next = async () =>
                    {
                        var root = _caseRoot;
                        await ExportHandoff(_settings.HandoffsFolder);
                        return root != null && _handedOff.Contains(root) ? StepResult.Next(_status.Text) : StepResult.Stay("Not exported: see the log.");
                    },
                },
            };
            RunWizard("Work a case", steps);
        }

        // ----- Build a collector -----

        void CollectorWizard()
        {
            var kind = CollectorKind.Collect;
            string scope = "all";   // all | tab | file
            CollectionProfile? fileProfile = null;
            var userHives = false;
            var parent = _settings.BundlesFolder;
            DeploymentBundle? built = null;
            var steps = new List<WizardStep>
            {
                new WizardStep
                {
                    Name = "What to collect",
                    Text = "A collection bundle runs foton-collect.exe: live triage into a case package with a first-pass report. A baseline bundle runs foton-baseline.exe: a snapshot of stable configuration to compare later. Both carry the collector released with this console.",
                    Build = () =>
                    {
                        var col = Column();
                        var c = new RadioButton { Text = "Collection bundle (triage package)", AutoSize = true, Checked = kind == CollectorKind.Collect };
                        var b = new RadioButton { Text = "Baseline bundle (known-state snapshot)", AutoSize = true, Checked = kind == CollectorKind.Baseline };
                        c.CheckedChanged += (s, e) => { if (c.Checked) kind = CollectorKind.Collect; };
                        b.CheckedChanged += (s, e) => { if (b.Checked) kind = CollectorKind.Baseline; };
                        col.Controls.Add(c);
                        col.Controls.Add(b);
                        return col;
                    },
                },
                new WizardStep
                {
                    Name = "Scope",
                    Text = "What the collector covers. A collection can take a profile that limits it to some categories and sets its options; without one it collects every category. A baseline can include users who are not signed in, by loading their registry hives for the capture.",
                    Build = () =>
                    {
                        var col = Column();
                        if (kind == CollectorKind.Baseline)
                        {
                            var hives = new CheckBox { Text = "Include users who are not signed in (-LoadUserHives)", Checked = userHives, AutoSize = true };
                            hives.CheckedChanged += (s, e) => userHives = hives.Checked;
                            col.Controls.Add(hives);
                            col.Controls.Add(Says("Use the same choice for every baseline you plan to compare: Compare warns when only one side loaded them."));
                            return col;
                        }
                        var all = new RadioButton { Text = "Every category, the collector's defaults", AutoSize = true, Checked = scope == "all" };
                        var tab = new RadioButton { Text = _profile != null ? "The Profile tab's profile: " + TextFile.OneLine(_profile.Name) : "The Profile tab's profile (not valid now)", AutoSize = true, Enabled = _profile != null, Checked = scope == "tab" && _profile != null };
                        var file = new RadioButton { Text = "A saved profile file...", AutoSize = true, Checked = scope == "file" };
                        var fileName = Says(fileProfile != null ? "Profile: " + TextFile.OneLine(fileProfile.Name) : "");
                        all.CheckedChanged += (s, e) => { if (all.Checked) scope = "all"; };
                        tab.CheckedChanged += (s, e) => { if (tab.Checked) scope = "tab"; };
                        file.Click += (s, e) =>
                        {
                            using (var d = new OpenFileDialog { Title = "Choose a collection profile", Filter = "Collection profile (*.json)|*.json", CheckFileExists = true })
                            {
                                if (d.ShowDialog(file.FindForm()) != DialogResult.OK) { if (fileProfile == null) all.Checked = true; return; }
                                try
                                {
                                    // The same checks foton-collect -Profile applies.
                                    fileProfile = CollectionProfile.Load(d.FileName);
                                    scope = "file";
                                    fileName.Text = "Profile: " + TextFile.OneLine(fileProfile.Name);
                                }
                                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException)
                                {
                                    fileName.Text = "Not used: " + TextFile.OneLine(ex.Message);
                                    if (fileProfile == null) all.Checked = true;
                                }
                            }
                        };
                        col.Controls.Add(all);
                        col.Controls.Add(tab);
                        col.Controls.Add(file);
                        col.Controls.Add(fileName);
                        col.Controls.Add(Says("Build or edit a profile on the Profile tab."));
                        return col;
                    },
                },
                new WizardStep
                {
                    Name = "Build",
                    Text = "Where to create the bundle folder. It holds the collector, the profile if any, SHA256SUMS.txt, and RUN.txt with the command to run on the endpoint. Nothing runs on this computer.",
                    Build = () =>
                    {
                        var col = Column();
                        var box = new TextBox { Text = parent, Width = 520 };
                        box.TextChanged += (s, e) => parent = box.Text.Trim().Trim('"');
                        var browse = new Button { Text = "Browse...", AutoSize = true };
                        browse.Click += (s, e) =>
                        {
                            using (var d = new FolderBrowserDialog { Description = "Choose where to create the bundle folder", ShowNewFolderButton = true })
                            {
                                if (Directory.Exists(box.Text)) d.SelectedPath = box.Text;
                                if (d.ShowDialog(browse.FindForm()) == DialogResult.OK) box.Text = d.SelectedPath;
                            }
                        };
                        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
                        row.Controls.Add(box);
                        row.Controls.Add(browse);
                        col.Controls.Add(row);
                        return col;
                    },
                    NextText = "Build bundle",
                    Next = async () =>
                    {
                        if (ConsoleSettings.FullPath(parent) == null) return StepResult.Stay("Not built: the folder must be a full path, such as D:\\Bundles.");
                        var profile = kind == CollectorKind.Baseline ? null : scope == "tab" ? _profile : scope == "file" ? fileProfile : null;
                        if (kind == CollectorKind.Collect && scope != "all" && profile == null) return StepResult.Stay("Not built: the chosen profile is not valid.");
                        built = await BuildBundleAt(kind, profile, kind == CollectorKind.Baseline && userHives, parent);
                        return built == null ? StepResult.Stay("Not built: see the log.") : StepResult.Next("Bundle built: " + built.Folder);
                    },
                },
                new WizardStep
                {
                    Name = "Send it",
                    Text = "Copy the folder to the endpoint or push it with your RMM tool. On the endpoint, check the collector against SHA256SUMS.txt, then run the command in RUN.txt from that folder (an elevated prompt collects the most; a standard user is supported). Bring the package back and open it with Work a case.",
                    Build = () =>
                    {
                        var col = Column();
                        if (built == null) { col.Controls.Add(Says("Build the bundle first.")); return col; }
                        col.Controls.Add(Says(built.Folder));
                        var command = Says("Command: " + built.RunCommand);
                        command.Font = Theme.MonoFont(Font.Size);
                        col.Controls.Add(command);
                        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
                        var open = new Button { Text = "Open the folder", AutoSize = true };
                        open.Click += (s, e) => { if (Directory.Exists(built.Folder)) System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(built.Folder) { UseShellExecute = true }); };
                        var copy = new Button { Text = "Copy the command", AutoSize = true };
                        copy.Click += (s, e) => Clipboard.SetText(built.RunCommand);
                        row.Controls.Add(open);
                        row.Controls.Add(copy);
                        col.Controls.Add(row);
                        return col;
                    },
                    NextText = "Done",
                    Final = true,
                },
            };
            RunWizard("Build a collector", steps);
        }

        // ----- Compare baselines -----

        async Task CompareWizard()
        {
            await EnsureCaseList();
            string? reference = _reference.Text.Trim().Length > 0 ? _reference.Text.Trim() : null;
            string? difference = _difference.Text.Trim().Length > 0 ? _difference.Text.Trim() : null;
            var baselines = (_caseList?.Baselines ?? new List<Foton.Package.BaselineEntry>()).OrderBy(b => b.CapturedUtc, StringComparer.Ordinal).ToList();

            Control Picker(Func<string?> get, Action<string> set, string hint)
            {
                var col = Column();
                var list = new ListBox { Width = 620, Height = 170, HorizontalScrollbar = true };
                foreach (var b in baselines) list.Items.Add($"{b.CapturedUtc}  {b.Host}  {b.JsonPath}");
                var current = get();
                if (current != null)
                {
                    var i = baselines.FindIndex(b => string.Equals(b.JsonPath, current, StringComparison.OrdinalIgnoreCase));
                    if (i >= 0) list.SelectedIndex = i; else { list.Items.Insert(0, current); list.SelectedIndex = 0; }
                }
                list.SelectedIndexChanged += (s, e) =>
                {
                    var text = list.SelectedItem as string ?? "";
                    var match = baselines.FirstOrDefault(b => text.EndsWith(b.JsonPath, StringComparison.OrdinalIgnoreCase));
                    set(match?.JsonPath ?? text);
                };
                var browse = new Button { Text = "Browse...", AutoSize = true };
                browse.Click += (s, e) =>
                {
                    using (var d = new OpenFileDialog { Title = "Choose a baseline.json", Filter = "Baseline (baseline.json)|baseline.json|JSON (*.json)|*.json", CheckFileExists = true })
                        if (d.ShowDialog(col.FindForm()) == DialogResult.OK) { list.Items.Insert(0, d.FileName); list.SelectedIndex = 0; }
                };
                col.Controls.Add(list);
                col.Controls.Add(browse);
                col.Controls.Add(Says(baselines.Count == 0 ? "No baselines in the listed folders yet: browse to a baseline.json, or build a baseline collector first." : hint));
                return col;
            }

            var steps = new List<WizardStep>
            {
                new WizardStep
                {
                    Name = "Reference",
                    Text = "The earlier baseline (a known-good moment, such as provisioning) or the golden image of the host's role.",
                    Build = () => Picker(() => reference, p => reference = p, "Same host: temporal compare. Another host: fleet compare against it."),
                    Next = () => Task.FromResult(reference == null ? StepResult.Stay("Choose the reference baseline first.") : StepResult.Next("")),
                },
                new WizardStep
                {
                    Name = "Difference",
                    Text = "The later baseline of the same host, or the host you compare against the golden image.",
                    Build = () => Picker(() => difference, p => difference = p, "Use baselines taken with the same choice for users not signed in."),
                    NextText = "Compare",
                    Next = async () =>
                    {
                        if (difference == null) return StepResult.Stay("Choose the difference baseline first.");
                        if (string.Equals(reference, difference, StringComparison.OrdinalIgnoreCase)) return StepResult.Stay("Choose two different baselines.");
                        _reference.Text = reference!;
                        _difference.Text = difference;
                        if (_comparePage != null) _tabs.SelectedTab = _comparePage;
                        return await Compare() ? StepResult.Next("Compared.") : StepResult.Stay("Not compared: see the log.");
                    },
                },
                new WizardStep
                {
                    Name = "Result",
                    Text = "A diff records change between two observations. It does not show when, who, or that the host is compromised; High-attention changes cite their usual benign causes.",
                    Build = () =>
                    {
                        var col = Column();
                        col.Controls.Add(Says(_compareSummary.Text));
                        var findings = _compareFindings.Rows.Cast<DataGridViewRow>().Select(r => Convert.ToString(r.Cells["Severity"].Value, System.Globalization.CultureInfo.InvariantCulture) ?? "");
                        col.Controls.Add(Says("Findings: " + Severities(findings) + "."));
                        var report = new Button { Text = "Open compare report", AutoSize = true };
                        report.Click += (s, e) => OpenCompareReport();
                        col.Controls.Add(report);
                        col.Controls.Add(Says("Every change is on the Compare tab and in baseline_diff.csv beside the difference baseline."));
                        return col;
                    },
                    NextText = "Done",
                    Final = true,
                },
            };
            RunWizard("Compare baselines", steps);
        }
    }
}
