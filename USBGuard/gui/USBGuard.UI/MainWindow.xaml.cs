using System;
using System.Windows;
using System.Windows.Media;
using Newtonsoft.Json.Linq;
using USBGuard.UI.Pages;
using Microsoft.Toolkit.Uwp.Notifications;

namespace USBGuard.UI
{
    public partial class MainWindow : Window
    {
        public  readonly IpcClient     Ipc;
        private readonly DashboardPage _dashboard;
        private readonly WhitelistPage _whitelist;
        private readonly AuditLogPage  _auditLog;
        private bool _backendConnected = false;

        public MainWindow()
        {
            InitializeComponent();
            Ipc        = new IpcClient();
            _dashboard = new DashboardPage(Ipc);
            _whitelist = new WhitelistPage(Ipc);
            _auditLog  = new AuditLogPage(Ipc);
            Ipc.MessageReceived += OnMessage;
            ToastNotificationManagerCompat.OnActivated += OnToastActivated; // Feature 1
            Ipc.Start();
            NavigateTo("dashboard");
            CheckBackendConnection();
        }

        private async void CheckBackendConnection()
        {
            bool alive = await Ipc.IsBackendAliveAsync();
            Dispatcher.Invoke(() =>
            {
                if (alive)
                {
                    ConnectionBar.Visibility = Visibility.Collapsed;
                    _backendConnected = true;
                }
                else
                {
                    ConnectionText.Text = "Backend not connected. Start the Python backend first.";
                }
            });
        }

        private void OnMessage(string type, JObject payload)
        {
            Dispatcher.Invoke(() =>
            {
                if (!_backendConnected)
                {
                    ConnectionBar.Visibility = Visibility.Collapsed;
                    _backendConnected = true;
                }

                switch (type)
                {
                    case "device_connected":
                        _dashboard.OnDeviceConnected(payload);
                        break;

                    case "device_allowed":
                        _dashboard.OnDeviceAllowed(payload);
                        SetSafeState();
                        var aName  = payload["descriptor"]?["iProduct"]?.ToString() ?? "Device";
                        var aScore = payload["ml_result"]?["score"]?.Value<double>() ?? 0;
                        var aReason= payload["reason"]?.ToString() ?? "";
                        FireToast("Device allowed",
                            $"{aName}  ·  Score {aScore:F2}  ·  {aReason}",
                            false);
                        break;

                    case "threat_detected":
                        _dashboard.OnThreatDetected(payload);
                        _auditLog.AddLiveEntry(payload);
                        var tCount = payload["blocked_count"]?.Value<int>() ?? 1;
                        SetThreatState(tCount);
                        var tName  = payload["descriptor"]?["iProduct"]?.ToString() ?? "HID Keyboard";
                        var tScore = payload["ml_result"]?["score"]?.Value<double>() ?? 0;
                        FireToast("Threat blocked!",
                            $"{tName}  ·  Score {tScore:F2}  ·  Port disabled",
                            true);
                        break;

                    case "pipeline_update":
                        _dashboard.OnPipelineUpdate(payload);
                        break;

                    // Feature 2 — whitelist tamper alert
                    case "whitelist_tampered":
                        var wMsg = payload["message"]?.ToString()
                                   ?? "Whitelist database was modified externally.";
                        MessageBox.Show(
                            $"Security Alert\n\n{wMsg}\n\n" +
                            "Verify your trusted device entries on the Whitelist page.",
                            "Whitelist Integrity Alert",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        break;

                    // Feature 3 — behavioral drift alert
                    case "baseline_drift":
                        var dName    = payload["descriptor"]?["iProduct"]?.ToString()
                                       ?? "Unknown device";
                        var dScore   = payload["drift"]?["drift_score"]?.Value<double>() ?? 0;
                        var dSamples = payload["drift"]?["sample_count"]?.Value<int>()  ?? 0;
                        FireToast(
                            "Behavioral drift detected",
                            $"{dName}  ·  Drift {dScore:F1}σ  ·  Baseline: {dSamples} samples",
                            false);
                        break;
                }
            });
        }

        private void FireToast(string title, string body, bool isThreat)
        {
            try
            {
                var builder = new ToastContentBuilder()
                    .AddText(title)
                    .AddText(body);
                // Feature 1 — action buttons on threat toasts
                if (isThreat)
                    builder
                        .AddButton(new ToastButton("Export Report", "action=report_threat"))
                        .AddButton(new ToastButton("Allow Once",    "action=allow_once"));
                builder.Show();
            }
            catch { /* Toast may not be available in all environments */ }
        }

        // Feature 1 — handle toast button activations
        private void OnToastActivated(ToastNotificationActivatedEventArgsCompat e)
        {
            try
            {
                var args = ToastArguments.Parse(e.Argument);
                if (!args.Contains("action")) return;
                var action = args["action"];

                Application.Current.Dispatcher.Invoke(async () =>
                {
                    if (action == "report_threat")
                    {
                        await Ipc.ExportThreatAsync();
                        MessageBox.Show(
                            "Threat report saved to backend/data/threat_reports/",
                            "Report Exported",
                            MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else if (action == "allow_once")
                    {
                        var confirm = MessageBox.Show(
                            "Allow this device to connect once this session?\n" +
                            "It will be fully analysed on the next connection after that.",
                            "Allow Once — Confirm",
                            MessageBoxButton.YesNo, MessageBoxImage.Question);
                        if (confirm == MessageBoxResult.Yes)
                        {
                            await Ipc.AllowOnceAsync();
                            SetSafeState();
                        }
                    }
                });
            }
            catch { }
        }

        public void SetSafeState()
        {
            SidebarSubtitle.Text       = "Ducky Detection";
            SidebarSubtitle.Foreground = Brush(0x5D, 0xCA, 0xA5);
            StatusDot.Fill             = Brush(0x5D, 0xCA, 0xA5);
            StatusText.Text            = "Protected";
            StatusText.Foreground      = Brush(0x5D, 0xCA, 0xA5);
            StatusPill.Background      = new SolidColorBrush(Color.FromRgb(0x0D, 0x2A, 0x1F));
            TopbarText.Text            = "All clear";
            TopbarText.Foreground      = Brush(0x3B, 0x6D, 0x11);
            TopbarStatus.Background    = Brush(0xEA, 0xF3, 0xDE);
            TopbarDot.Fill             = Brush(0x1D, 0x9E, 0x75);
        }

        public void SetThreatState(int blockedCount = 1)
        {
            SidebarSubtitle.Text       = "Threat blocked";
            SidebarSubtitle.Foreground = Brush(0xF0, 0x95, 0x95);
            StatusDot.Fill             = Brush(0xE2, 0x4B, 0x4A);
            StatusText.Text            = "Threat detected";
            StatusText.Foreground      = Brush(0xF0, 0x95, 0x95);
            StatusPill.Background      = new SolidColorBrush(Color.FromRgb(0x2A, 0x0D, 0x0D));
            TopbarText.Text            = blockedCount == 1 ? "1 threat blocked"
                                                           : $"{blockedCount} threats blocked";
            TopbarText.Foreground      = Brush(0xA3, 0x2D, 0x2D);
            TopbarStatus.Background    = Brush(0xFC, 0xEB, 0xEB);
            TopbarDot.Fill             = Brush(0xE2, 0x4B, 0x4A);
        }

        private void NavigateTo(string page)
        {
            PageTitle.Text = page switch
            {
                "dashboard" => "Dashboard",
                "whitelist" => "Whitelist management",
                "audit"     => "Audit log",
                _           => "Dashboard"
            };
            MainFrame.Navigate(page switch
            {
                "dashboard" => (object)_dashboard,
                "whitelist" => _whitelist,
                "audit"     => _auditLog,
                _           => _dashboard
            });

            // Update active nav button colour
            foreach (var btn in new[] { NavDashboard, NavWhitelist, NavAudit })
                btn.Foreground = new SolidColorBrush(Color.FromRgb(0x7A, 0x9B, 0xAE));

            var active = page switch
            {
                "dashboard" => NavDashboard,
                "whitelist" => NavWhitelist,
                "audit"     => NavAudit,
                _           => NavDashboard
            };
            active.Foreground = Brush(0x5D, 0xCA, 0xA5);
        }

        private void NavDashboard_Click(object s, RoutedEventArgs e)
            => NavigateTo("dashboard");

        private void NavWhitelist_Click(object s, RoutedEventArgs e)
        {
            NavigateTo("whitelist");
            _whitelist.Refresh();
        }

        private void NavAudit_Click(object s, RoutedEventArgs e)
        {
            NavigateTo("audit");
            _auditLog.Refresh();
        }

        protected override void OnClosed(EventArgs e)
        {
            Ipc.Stop();
            base.OnClosed(e);
        }

        private static SolidColorBrush Brush(byte r, byte g, byte b)
            => new(Color.FromRgb(r, g, b));
    }
}
