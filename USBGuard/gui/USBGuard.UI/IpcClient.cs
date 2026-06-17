using System;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace USBGuard.UI
{
    public class IpcClient
    {
        private const string PipeName   = "USBGuardIPC";
        private const string ApiBase    = "http://localhost:8765";
        private const int    RetryMs    = 2000;
        private const int    MaxRetries = 20;

        public event Action<string, JObject>? MessageReceived;

        private readonly HttpClient              _http = new();
        private readonly CancellationTokenSource _cts  = new();

        public void Start()
        {
            Task.Run(() => PipeLoop(_cts.Token));
        }

        public void Stop() => _cts.Cancel();

        // ── Named pipe reader ──────────────────────────────────────────────
        private async Task PipeLoop(CancellationToken token)
        {
            int retries = 0;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    using var pipe = new NamedPipeClientStream(
                        ".", PipeName,
                        PipeDirection.In,
                        PipeOptions.Asynchronous);

                    await pipe.ConnectAsync(3000, token);
                    retries = 0;

                    using var reader = new StreamReader(pipe, Encoding.UTF8);
                    while (!token.IsCancellationRequested && pipe.IsConnected)
                    {
                        var line = await reader.ReadLineAsync();
                        if (line == null) break;
                        try
                        {
                            var obj     = JObject.Parse(line);
                            var type    = obj["type"]?.ToString() ?? "";
                            var payload = (obj["payload"] as JObject) ?? new JObject();
                            MessageReceived?.Invoke(type, payload);
                        }
                        catch (JsonException) { }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch
                {
                    if (++retries >= MaxRetries) break;
                    try { await Task.Delay(RetryMs, token); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        // ── HTTP API helpers ───────────────────────────────────────────────
        public async Task<JArray> GetWhitelistAsync()
        {
            try
            {
                var json = await _http.GetStringAsync($"{ApiBase}/whitelist/list");
                return JArray.Parse(json);
            }
            catch { return new JArray(); }
        }

        public async Task<JArray> GetAuditLogAsync()
        {
            try
            {
                var json = await _http.GetStringAsync($"{ApiBase}/audit/list");
                return JArray.Parse(json);
            }
            catch { return new JArray(); }
        }

        public async Task<bool> AddCurrentDeviceAsync()
        {
            try
            {
                var r = await _http.PostAsync(
                    $"{ApiBase}/whitelist/add_current",
                    new StringContent("{}", Encoding.UTF8, "application/json"));
                return r.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        public async Task<bool> RemoveDeviceAsync(string hash)
        {
            try
            {
                var r = await _http.PostAsync(
                    $"{ApiBase}/whitelist/remove/{hash}",
                    new StringContent(""));
                return r.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        public async Task<bool> IsBackendAliveAsync()
        {
            try
            {
                var r = await _http.GetAsync($"{ApiBase}/status");
                return r.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        // ── Feature 1: Export last blocked device to a threat report file ─
        public async Task<bool> ExportThreatAsync()
        {
            try
            {
                var r = await _http.PostAsync(
                    $"{ApiBase}/audit/export_threat",
                    new StringContent("{}", Encoding.UTF8, "application/json"));
                return r.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        // ── Feature 1: Grant session allow-once for the last blocked device
        public async Task<bool> AllowOnceAsync()
        {
            try
            {
                var r = await _http.PostAsync(
                    $"{ApiBase}/whitelist/allow_once",
                    new StringContent("{}", Encoding.UTF8, "application/json"));
                return r.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        // ── Feature 2: Whitelist integrity audit status ────────────────────
        public async Task<JObject> GetWhitelistAuditAsync()
        {
            try
            {
                var json = await _http.GetStringAsync($"{ApiBase}/whitelist/audit");
                return JObject.Parse(json);
            }
            catch { return new JObject(); }
        }

        // ── Feature 3: Device behavioral baseline list ─────────────────────
        public async Task<JArray> GetBaselineListAsync()
        {
            try
            {
                var json = await _http.GetStringAsync($"{ApiBase}/baseline/list");
                return JArray.Parse(json);
            }
            catch { return new JArray(); }
        }
    }
}
