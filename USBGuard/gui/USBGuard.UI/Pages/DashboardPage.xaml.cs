using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Newtonsoft.Json.Linq;
using USBGuard.UI.Models;

namespace USBGuard.UI.Pages
{
    public partial class DashboardPage : Page
    {
        private readonly IpcClient _ipc;
        private readonly ObservableCollection<DeviceListItem> _devices = new();
        private int _monitored, _blocked, _whitelisted;
        private readonly DateTime _startTime = DateTime.Now;

        public DashboardPage(IpcClient ipc)
        {
            InitializeComponent();
            _ipc = ipc;
            DeviceList.ItemsSource = _devices;
            StartUptimeTimer();
        }

        public void OnDeviceConnected(JObject p)
        {
            var d = p["descriptor"];
            _devices.Add(new DeviceListItem
            {
                Name     = d?["iProduct"]?.ToString() ?? "Unknown",
                VendorId = d?["idVendor"]?.ToString()  ?? "",
                Status   = "Scanning…",
                Score    = "—"
            });
            _monitored++;
            MetricMonitored.Text = _monitored.ToString();
        }

        public void OnDeviceAllowed(JObject p)
        {
            var d      = p["descriptor"];
            var name   = d?["iProduct"]?.ToString() ?? "Unknown";
            var score  = p["ml_result"]?["score"]?.Value<double>() ?? 0;
            var reason = p["reason"]?.ToString() ?? "";

            UpdateStatus(name, reason == "whitelisted" ? "Trusted" : "Allowed",
                         $"{score:F2}");

            if (reason == "whitelisted") _whitelisted++;
            MetricWhitelisted.Text = _whitelisted.ToString();

            ShowAlert($"Device allowed — {name}  ·  Score {score:F2}", false);
            UpdateScoreBar(score, false);
            SetStepsGreen();
        }

        public void OnThreatDetected(JObject p)
        {
            var d     = p["descriptor"];
            var name  = d?["iProduct"]?.ToString() ?? "HID Keyboard";
            var score = p["ml_result"]?["score"]?.Value<double>() ?? 0;

            _blocked++;
            MetricBlocked.Text       = _blocked.ToString();
            MetricBlocked.Foreground = Brush(0xA3, 0x2D, 0x2D);

            UpdateStatus(name, "BLOCKED", $"{score:F2}");
            ShowAlert(
                $"Threat blocked — {name}  ·  ML score {score:F2}  ·  Port disabled",
                true);
            UpdateScoreBar(score, true);
            SetStepsRed();
        }

        public void OnPipelineUpdate(JObject p)
        {
            var ml = p["ml_result"];
            if (ml == null) return;
            var score    = ml["score"]?.Value<double>() ?? 0;
            var decision = ml["decision"]?.ToString() ?? "";
            UpdateScoreBar(score, decision == "BLOCK");
        }

        private void UpdateStatus(string name, string status, string score)
        {
            // First pass: prefer exact name match to avoid updating wrong device
            // when multiple devices are being scanned simultaneously.
            DeviceListItem? fallback = null;
            foreach (var item in _devices)
            {
                if (item.Name == name)
                {
                    item.Status = status;
                    item.Score  = score;
                    DeviceList.Items.Refresh();
                    return;
                }
                if (fallback == null && item.Status == "Scanning…")
                    fallback = item;
            }
            // Second pass: if no name matched, update the first scanning entry
            if (fallback != null)
            {
                fallback.Status = status;
                fallback.Score  = score;
            }
            DeviceList.Items.Refresh();
        }

        private void UpdateScoreBar(double score, bool isThreat)
        {
            var pct = Math.Clamp(score, 0, 1);
            ScoreBar.Width      = Math.Max(0, DeviceList.ActualWidth * pct * 0.95);
            ScoreBar.Background = isThreat
                ? Brush(0xE2, 0x4B, 0x4A)
                : Brush(0x1D, 0x9E, 0x75);
            ScoreLabel.Text =
                $"Score: {score:F2}  ·  Threshold: 0.50  ·  " +
                (isThreat ? "BLOCKED" : "ALLOWED");
        }

        private void ShowAlert(string msg, bool isThreat)
        {
            AlertText.Text          = msg;
            AlertText.Foreground    = isThreat ? Brush(0x50, 0x13, 0x13)
                                               : Brush(0x27, 0x50, 0x0A);
            AlertDot.Fill           = isThreat ? Brush(0xE2, 0x4B, 0x4A)
                                               : Brush(0x1D, 0x9E, 0x75);
            AlertBanner.Background  = isThreat
                ? new SolidColorBrush(Color.FromRgb(0xFC, 0xEB, 0xEB))
                : new SolidColorBrush(Color.FromRgb(0xEA, 0xF3, 0xDE));
            AlertBanner.BorderBrush = isThreat
                ? new SolidColorBrush(Color.FromRgb(0xF0, 0x95, 0x95))
                : new SolidColorBrush(Color.FromRgb(0x9F, 0xE1, 0xCB));
            AlertBanner.BorderThickness = new Thickness(0.5);
            AlertBanner.Visibility  = Visibility.Visible;
        }

        private void SetStepsGreen()
        {
            var c = Brush(0x3B, 0x6D, 0x11);
            foreach (var tb in new[] { Step1, Step2, Step3, Step4, Step5 })
                tb.Foreground = c;
        }

        private void SetStepsRed()
        {
            var c = Brush(0xA3, 0x2D, 0x2D);
            foreach (var tb in new[] { Step1, Step2, Step3, Step4, Step5 })
                tb.Foreground = c;
        }

        private void DismissAlert_Click(object s, RoutedEventArgs e)
            => AlertBanner.Visibility = Visibility.Collapsed;

        private void StartUptimeTimer()
        {
            var t = new System.Windows.Threading.DispatcherTimer
            { Interval = TimeSpan.FromSeconds(30) };
            t.Tick += (_, _) =>
            {
                var e = DateTime.Now - _startTime;
                MetricUptime.Text = e.TotalHours >= 1
                    ? $"{(int)e.TotalHours}h {e.Minutes}m"
                    : $"{e.Minutes}m";
            };
            t.Start();
        }

        private static SolidColorBrush Brush(byte r, byte g, byte b)
            => new(Color.FromRgb(r, g, b));
    }
}
