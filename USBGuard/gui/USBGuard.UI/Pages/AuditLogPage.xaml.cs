using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using USBGuard.UI.Models;

namespace USBGuard.UI.Pages
{
    public partial class AuditLogPage : Page
    {
        private readonly IpcClient _ipc;
        private readonly ObservableCollection<AuditItem> _all      = new();
        private readonly ObservableCollection<AuditItem> _filtered = new();

        public AuditLogPage(IpcClient ipc)
        {
            InitializeComponent();
            _ipc = ipc;
            LogView.ItemsSource = _filtered;
        }

        public async void Refresh()
        {
            var data = await _ipc.GetAuditLogAsync();
            _all.Clear();
            foreach (var row in data)
            {
                _all.Add(new AuditItem
                {
                    Timestamp = row["timestamp"]?.ToString() ?? "",
                    Device    = row["device"]?.ToString()    ?? "",
                    Score     = row["score"]?.ToString()     ?? "—",
                    Decision  = row["decision"]?.ToString()  ?? "",
                    Hash      = row["hash"]?.ToString()      ?? ""
                });
            }
            ApplyFilter();
        }

        public void AddLiveEntry(JObject payload)
        {
            var desc = payload["descriptor"];
            var ml   = payload["ml_result"];
            _all.Insert(0, new AuditItem
            {
                Timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
                Device    = $"{desc?["iProduct"]}  ·  {desc?["idVendor"]}",
                Score     = ml?["score"]?.Value<double>().ToString("F2") ?? "—",
                Decision  = "BLOCK",
                Hash      = "pending…"
            });
            ApplyFilter();
        }

        private void ApplyFilter()
        {
            var q      = LogSearch?.Text?.ToLower() ?? "";
            var filter = (FilterBox?.SelectedItem as ComboBoxItem)
                             ?.Content?.ToString() ?? "All events";
            _filtered.Clear();
            foreach (var item in _all)
            {
                if (filter != "All events" &&
                    !item.Decision.ToLower().Contains(filter.ToLower()))
                    continue;
                if (!string.IsNullOrWhiteSpace(q) &&
                    !item.Device.ToLower().Contains(q) &&
                    !item.Decision.ToLower().Contains(q))
                    continue;
                _filtered.Add(item);
            }
        }

        private static string CsvField(string v)
        {
            if (v.Contains(',') || v.Contains('"') || v.Contains('\n'))
                return $"\"{v.Replace("\"", "\"\"")}\"";
            return v;
        }

        private void FilterBox_Changed(object s, SelectionChangedEventArgs e)
            => ApplyFilter();
        private void LogSearch_Changed(object s, TextChangedEventArgs e)
            => ApplyFilter();

        private void ExportCsv_Click(object s, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter   = "CSV files|*.csv",
                FileName = $"usb_guard_audit_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };
            if (dlg.ShowDialog() != true) return;
            var sb = new StringBuilder("Timestamp,Device,Score,Decision,Hash\r\n");
            foreach (var item in _all)
                sb.AppendLine(
                    $"{CsvField(item.Timestamp)},{CsvField(item.Device)}," +
                    $"{CsvField(item.Score)},{CsvField(item.Decision)},{CsvField(item.Hash)}");
            File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
            MessageBox.Show("Audit log exported to CSV.",
                "Export complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ExportJson_Click(object s, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter   = "JSON files|*.json",
                FileName = $"usb_guard_audit_{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };
            if (dlg.ShowDialog() != true) return;
            var json = JsonConvert.SerializeObject(_all, Formatting.Indented);
            File.WriteAllText(dlg.FileName, json, Encoding.UTF8);
            MessageBox.Show("Audit log exported to JSON.",
                "Export complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
