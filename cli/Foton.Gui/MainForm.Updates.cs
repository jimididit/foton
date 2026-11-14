using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;
using Foton.Core;
using Foton.Tools.Update;

namespace Foton.Gui
{
    /// <summary>
    /// Updates: Help > Check for updates (the same check, download, and side-by-side install as foton update), and the
    /// opt-in check at start (Settings, at most once a day), which only says an update exists. Nothing downloads or
    /// installs unless the operator chooses Download and install; this copy is never replaced.
    /// </summary>
    sealed partial class MainForm
    {
        /// <summary>The check at start while it runs: a check asked for meanwhile waits, so one writer at a time appends to update.log.</summary>
        Task? _startupCheck;

        /// <summary>Help > Check for updates. Started from the menu without being awaited, so nothing may escape it.</summary>
        async Task CheckForUpdates()
        {
            try { await CheckForUpdatesCore(); }
            catch (Exception ex)
            {
                var message = "Update stopped: " + TextFile.OneLine(ex.Message);
                new StatusLog(_logWriter).Write(message, StatusLevel.Error);
                if (IsDisposed) return;
                _status.Text = message;
                MessageBox.Show(this, message + "\r\n\r\nThis copy is unchanged.", "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        async Task CheckForUpdatesCore()
        {
            if (_busy) { _status.Text = "Wait for the current action to finish."; return; }
            if (_startupCheck != null && !_startupCheck.IsCompleted)
            {
                _status.Text = "Waiting for the update check at start to finish...";
                try { await _startupCheck; } catch (Exception) { }   // its own continuation reports it
            }
            UpdateCheckResult? result = null;
            if (!await Run("Check for updates", log => { result = CheckUpdates(log); return null; }) || result == null) return;
            RememberUpdateCheck(result);
            switch (result.State)
            {
                case UpdateState.UpToDate:
                    MessageBox.Show(this, result.Message, "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                case UpdateState.NotYetSigned:
                    MessageBox.Show(this, result.Message, "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                case UpdateState.Failed:
                    MessageBox.Show(this, result.Message + "\r\n\r\nThis copy is unchanged.", "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
            }
            await OfferUpdate(result);
        }

        /// <summary>Worker thread: one check against GitHub, written to the log pane and update.log.</summary>
        static UpdateCheckResult CheckUpdates(StatusLog log)
        {
            UseUpdateLog(log);
            log.Write($"Checking https://github.com/{UpdateCheck.Repository}/releases for a signed release newer than {FotonVersion.Product}", StatusLevel.Step);
            var result = UpdateCheck.Run(new HttpUpdateSource(), FotonVersion.Product, DateTime.UtcNow, ReleaseKeys.All);
            log.Write(result.Message, result.State == UpdateState.Failed ? StatusLevel.Error
                : result.State == UpdateState.NotYetSigned ? StatusLevel.Warn : StatusLevel.Good);
            if (result.State == UpdateState.Available && result.PendingVersion.Length > 0)
                log.Write($"Foton {result.PendingVersion} is also published but not signed yet.", StatusLevel.Warn);
            return result;
        }

        /// <summary>Every update step also goes to %LOCALAPPDATA%\Foton\updates\update.log (UTC), as foton update writes it.</summary>
        static void UseUpdateLog(StatusLog log)
        {
            try
            {
                var updates = UpdateStage.Root();
                Directory.CreateDirectory(updates);
                log.LogFile = Path.Combine(updates, "update.log");
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { log.Write("update.log not written: " + ex.Message, StatusLevel.Warn); }
        }

        /// <summary>A check that reached GitHub counts toward the once-a-day limit of the check at start.</summary>
        void RememberUpdateCheck(UpdateCheckResult result)
        {
            if (result.State == UpdateState.Failed) return;
            _settings.LastUpdateCheckUtc = FotonTime.Format(DateTime.UtcNow);
            SaveSettings();
        }

        async Task OfferUpdate(UpdateCheckResult result)
        {
            var exeDir = Path.GetFullPath(Application.StartupPath);
            var s = result.Statement!;
            if (UpdateInstall.IsScoop(exeDir))
            {
                MessageBox.Show(this, result.Message + "\r\n\r\nThis console was installed with Scoop, which keeps its own versions: run  scoop update foton  in PowerShell.",
                    "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string target;
            using (var d = new UpdateDialog(result, exeDir))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                target = d.Target;
            }

            string? installed = null;
            var done = await Run("Install Foton " + s.Version, log =>
            {
                UseUpdateLog(log);
                log.Write(result.Message, StatusLevel.Info);
                var updates = UpdateStage.Root();
                var staged = UpdateStage.Stage(s, result.ZipUrl, new HttpUpdateSource(), updates, log);
                installed = UpdateInstall.Install(staged, target, s, log);
                // After a successful install: a staging folder left behind is only disk space, not a failed update.
                try { UpdateStage.Clean(updates, s.Version); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException
                    || ex is ArgumentException || ex is NotSupportedException)
                {
                    log.Write("Staging folder not removed: " + ex.Message, StatusLevel.Warn);
                }
                log.Write($"This copy in {exeDir} is unchanged; cases can still be re-run with Foton {FotonVersion.Product}.", StatusLevel.Info);
                return null;
            });
            if (!done || installed == null)
            {
                MessageBox.Show(this, $"Foton {s.Version} was not installed; the log says which check or step failed.\r\n\r\nThis copy is unchanged.",
                    "Update Foton", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var console = Path.Combine(installed, "foton-console.exe");
            var open = MessageBox.Show(this,
                $"Foton {s.Version} is installed in {installed}.\r\n\r\nThis copy stays in {exeDir}.\r\n\r\nOpen Foton {s.Version} now? This window closes.",
                "Update Foton", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (open != DialogResult.Yes || !File.Exists(console)) return;
            try { Process.Start(new ProcessStartInfo(console) { UseShellExecute = true, WorkingDirectory = installed }); }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException)
            {
                // The install itself succeeded; only starting it failed (an application control policy, for one).
                MessageBox.Show(this, $"Foton {s.Version} is installed, but Windows did not start it: {TextFile.OneLine(ex.Message)}\r\n\r\nStart foton-console.exe from {installed}.",
                    "Update Foton", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            Close();
        }

        /// <summary>
        /// The opt-in check at start: in the background, at most once a day, never a dialog. An available update is named in
        /// the status bar and the log; anything else only in the log.
        /// </summary>
        void StartupUpdateCheck()
        {
            if (!_settings.UpdateCheckDue(DateTime.UtcNow)) return;
            // It runs beside whatever the window starts with (opening a case, listing cases): its lines are collected and
            // shown as one block when it ends, so they never interleave with that action's. update.log gets them as they come.
            var lines = new StringWriter();
            var log = new StatusLog(lines);
            log.WriteConsole("");
            log.WriteConsole("== Update check at start (" + FotonTime.Format(DateTime.UtcNow) + " UTC; Settings turns it off)");
            _startupCheck = Task.Run(() => CheckUpdates(log)).ContinueWith(t =>
            {
                if (IsDisposed) return;
                if (t.IsFaulted) log.Write("Update check stopped: " + (t.Exception?.GetBaseException().Message ?? "unknown error"), StatusLevel.Warn);
                _logWriter.Write(lines.ToString());
                if (t.IsFaulted || t.IsCanceled) return;
                RememberUpdateCheck(t.Result);
                if (t.Result.State == UpdateState.Available && !_busy)
                    _status.Text = $"Foton {t.Result.Statement!.Version} is available: Help > Check for updates.";
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }
    }
}
