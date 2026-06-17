using System.Collections.Generic;
using Newtonsoft.Json;

namespace USBGuard.UI.Models
{
    public class DeviceDescriptor
    {
        [JsonProperty("idVendor")]       public string IdVendor       { get; set; } = "";
        [JsonProperty("idProduct")]      public string IdProduct      { get; set; } = "";
        [JsonProperty("iManufacturer")]  public string IManufacturer  { get; set; } = "";
        [JsonProperty("iProduct")]       public string IProduct       { get; set; } = "";
        [JsonProperty("bDeviceClass")]   public int    BDeviceClass   { get; set; }
        [JsonProperty("bDeviceProtocol")]public int    BDeviceProtocol{ get; set; }
        [JsonProperty("device_id")]      public string DeviceId       { get; set; } = "";
    }

    public class MlResult
    {
        [JsonProperty("score")]    public double Score    { get; set; }
        [JsonProperty("anomaly")]  public bool   Anomaly  { get; set; }
        [JsonProperty("decision")] public string Decision { get; set; } = "";
        [JsonProperty("features")] public Dictionary<string, double> Features { get; set; } = new();
    }

    public class DeviceEvent
    {
        [JsonProperty("type")]       public string           Type       { get; set; } = "";
        [JsonProperty("descriptor")] public DeviceDescriptor Descriptor { get; set; } = new();
        [JsonProperty("ml_result")]  public MlResult?        MlResult   { get; set; }
        [JsonProperty("reason")]     public string           Reason     { get; set; } = "";
    }

    public class DeviceListItem
    {
        public string Name      { get; set; } = "";
        public string VendorId  { get; set; } = "";
        public string Status    { get; set; } = "";
        public string Score     { get; set; } = "—";
        public string Port      { get; set; } = "—";
    }

    public class WhitelistItem
    {
        [JsonProperty("hash")]    public string Hash        { get; set; } = "";
        [JsonProperty("name")]    public string Name        { get; set; } = "";
        [JsonProperty("vendor")]  public string VendorId    { get; set; } = "";
        [JsonProperty("product")] public string ProductId   { get; set; } = "";
        [JsonProperty("date")]    public string DateAdded   { get; set; } = "";
        // Truncated for display only — full hash is used for removal
        public string HashDisplay => Hash.Length > 12 ? Hash[..12] + "…" : Hash;
    }

    public class AuditItem
    {
        [JsonProperty("timestamp")] public string Timestamp { get; set; } = "";
        [JsonProperty("device")]    public string Device    { get; set; } = "";
        [JsonProperty("score")]     public string Score     { get; set; } = "";
        [JsonProperty("decision")]  public string Decision  { get; set; } = "";
        [JsonProperty("hash")]      public string Hash      { get; set; } = "";
    }
}
