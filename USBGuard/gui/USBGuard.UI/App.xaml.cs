using System;
using System.Diagnostics;
using System.IO;
using System.Windows;

namespace USBGuard.UI
{
    public partial class App : Application
    {
        private Process? _backend;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            if (!StartBackend())
                return;   // StartBackend already called Shutdown()

            new MainWindow().Show();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try { _backend?.Kill(entireProcessTree: true); } catch { }
            base.OnExit(e);
        }

        // ── Backend launcher ──────────────────────────────────────────────

        private bool StartBackend()
        {
            // Locate backend/main.py by walking up from the exe directory.
            // Works for both dev builds (..\bin\Debug\net8.0-windows\) and
            // published deployments where the exe sits next to backend\.
            var script = FindFile("backend", "main.py");
            if (script == null)
            {
                MessageBox.Show(
                    "backend\\main.py was not found.\n\n" +
                    "Make sure USBGuard.exe is placed in the same folder as the backend\\ directory.",
                    "USB Guard — Setup Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
                return false;
            }

            var python = FindPython();
            if (python == null)
            {
                MessageBox.Show(
                    "Python 3 was not found on PATH.\n\n" +
                    "Install Python 3 from https://python.org, making sure to tick\n" +
                    "\"Add Python to PATH\", then re-run USB Guard.\n\n" +
                    "Also run:  pip install -r requirements.txt",
                    "USB Guard — Python Not Found",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
                return false;
            }

            var psi = new ProcessStartInfo
            {
                FileName         = python,
                Arguments        = $"\"{script}\"",
                WorkingDirectory = Path.GetDirectoryName(script)!,
                CreateNoWindow   = true,
                UseShellExecute  = false,
            };

            _backend = Process.Start(psi);
            if (_backend == null)
            {
                MessageBox.Show(
                    "Failed to start the Python backend process.",
                    "USB Guard — Launch Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
                return false;
            }

            return true;
        }

        // Search upward from the exe directory for <folder>\<file>
        private static string? FindFile(string folder, string file)
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                var path = Path.Combine(dir.FullName, folder, file);
                if (File.Exists(path)) return path;
                dir = dir.Parent;
            }
            return null;
        }

        // Try common Python launcher names; return the first one that responds
        private static string? FindPython()
        {
            foreach (var cmd in new[] { "python", "py", "python3" })
            {
                try
                {
                    using var p = Process.Start(new ProcessStartInfo
                    {
                        FileName               = cmd,
                        Arguments              = "--version",
                        CreateNoWindow         = true,
                        UseShellExecute        = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                    });
                    if (p != null && p.WaitForExit(2000) && p.ExitCode == 0)
                        return cmd;
                }
                catch { }
            }
            return null;
        }
    }
}
