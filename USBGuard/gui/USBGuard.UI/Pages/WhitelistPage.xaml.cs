using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Newtonsoft.Json.Linq;
using USBGuard.UI.Models;

namespace USBGuard.UI.Pages
{
    public partial class WhitelistPage : Page
    {
        private readonly IpcClient _ipc;
        private readonly ObservableCollection<WhitelistItem> _all      = new();
        private readonly ObservableCollection<WhitelistItem> _filtered = new();

        public WhitelistPage(IpcClient ipc)
        {
            InitializeComponent();
            _ipc = ipc;
            WhitelistView.ItemsSource = _filtered;
        }

        public async void Refresh()
        {
            var data = await _ipc.GetWhitelistAsync();
            _all.Clear();
            foreach (var item in data)
            {
                _all.Add(new WhitelistItem
                {
                    Hash      = item["hash"]?.ToString()    ?? "",
                    Name      = item["name"]?.ToString()    ?? "",
                    VendorId  = item["vendor"]?.ToString()  ?? "",
                    ProductId = item["product"]?.ToString() ?? "",
                    DateAdded = item["date"]?.ToString()    ?? ""
                });
            }
            ApplyFilter();
            Footer.Text = $"{_all.Count} trusted devices  ·  SHA-256 hashed  ·  AES-256 encrypted";
        }

        private async void AddDevice_Click(object s, RoutedEventArgs e)
        {
            var ok = await _ipc.AddCurrentDeviceAsync();
            if (ok)
            {
                Refresh();
                MessageBox.Show("Device added to whitelist successfully.",
                    "Whitelist updated", MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(
                    "Could not add device. Make sure a device was recently connected.",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private async void RemoveDevice_Click(object s, RoutedEventArgs e)
        {
            if (s is Button btn && btn.Tag is string hash)
            {
                var r = MessageBox.Show(
                    "Remove this device from the whitelist?\nIt will be analysed on next connection.",
                    "Confirm removal",
                    MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (r == MessageBoxResult.Yes)
                {
                    var ok = await _ipc.RemoveDeviceAsync(hash);
                    if (ok)
                    {
                        Refresh();
                    }
                    else
                    {
                        MessageBox.Show(
                            "Could not remove device. The backend may be unavailable.",
                            "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
        }

        private void SearchBox_Changed(object s, TextChangedEventArgs e)
            => ApplyFilter();

        private void TypeFilter_Changed(object s, SelectionChangedEventArgs e)
            => ApplyFilter();

        private void ApplyFilter()
        {
            var q = SearchBox?.Text?.ToLower() ?? "";
            _filtered.Clear();
            foreach (var item in _all)
            {
                if (!string.IsNullOrWhiteSpace(q) &&
                    !item.Name.ToLower().Contains(q) &&
                    !item.VendorId.ToLower().Contains(q))
                    continue;
                _filtered.Add(item);
            }
        }
    }
}
