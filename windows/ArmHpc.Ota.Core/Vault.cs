// SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;

namespace ArmHpc.Ota.Core;

public sealed class Vault
{
    private readonly string directory;
    private static readonly byte[] Entropy = "ARMHPC OTA credentials v1"u8.ToArray();
    public Vault(string? path = null)
    {
        directory = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ARMHPC", "OTA");
        Directory.CreateDirectory(directory);
    }
    private string FileFor(string id) => Path.Combine(directory, Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(id))) + ".credentials");
    public void Save(string deviceId, Credentials credentials)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Linux 不保存登录密码；使用 SSH 私钥或每次输入凭据。既有设备和任务记录仍可保存。");
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(credentials);
        try
        {
            byte[] encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
            Atomic(FileFor(deviceId), encrypted);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    public Credentials? Load(string deviceId)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (!File.Exists(FileFor(deviceId))) return null;
        byte[] plaintext = ProtectedData.Unprotect(File.ReadAllBytes(FileFor(deviceId)), Entropy, DataProtectionScope.CurrentUser);
        try { return JsonSerializer.Deserialize<Credentials>(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    public void SaveConnection(Device device,Credentials credentials)=>Save(device.DeviceId+"/"+device.Transport,credentials);
    public Credentials? LoadConnection(Device device)
    {
        var value=Load(device.DeviceId+"/"+device.Transport);if(value is not null)return value;
        var legacy=Load(device.DeviceId);return device.Transport=="serial" && legacy?.PrivateKeyPath is not null?null:legacy;
    }
    public void SaveDefault(Credentials credentials)=>Save("controller/default-login",credentials);
    public Credentials? LoadDefault()=>Load("controller/default-login");
    public void ClearDefault()=>File.Delete(FileFor("controller/default-login"));
    public void SaveDevices(IEnumerable<Device> devices) => Atomic(Path.Combine(directory, "devices.json"), JsonSerializer.SerializeToUtf8Bytes(devices.Where(d => d.Managed)));
    public IReadOnlyList<Device> LoadDevices() => File.Exists(Path.Combine(directory, "devices.json")) ? JsonSerializer.Deserialize<List<Device>>(File.ReadAllBytes(Path.Combine(directory, "devices.json"))) ?? [] : [];
    public void SaveTasks(IEnumerable<PendingTask> tasks) => Atomic(Path.Combine(directory, "tasks.json"), JsonSerializer.SerializeToUtf8Bytes(tasks));
    public IReadOnlyList<PendingTask> LoadTasks() => File.Exists(Path.Combine(directory, "tasks.json")) ? JsonSerializer.Deserialize<List<PendingTask>>(File.ReadAllBytes(Path.Combine(directory, "tasks.json"))) ?? [] : [];
    public void SaveMaintenance(IEnumerable<MaintenanceTask> tasks)=>Atomic(Path.Combine(directory,"maintenance.json"),JsonSerializer.SerializeToUtf8Bytes(tasks));
    public IReadOnlyList<MaintenanceTask> LoadMaintenance()=>File.Exists(Path.Combine(directory,"maintenance.json"))?JsonSerializer.Deserialize<List<MaintenanceTask>>(File.ReadAllBytes(Path.Combine(directory,"maintenance.json")))??[]:[];
    public void SaveAutomatic(IEnumerable<AutomaticTask> tasks)=>Atomic(Path.Combine(directory,"automatic.json"),JsonSerializer.SerializeToUtf8Bytes(tasks));
    public IReadOnlyList<AutomaticTask> LoadAutomatic()=>File.Exists(Path.Combine(directory,"automatic.json"))?JsonSerializer.Deserialize<List<AutomaticTask>>(File.ReadAllBytes(Path.Combine(directory,"automatic.json")))??[]:[];
    private static void Atomic(string path, byte[] contents)
    {
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None)) { stream.Write(contents); stream.Flush(true); }
        File.Move(temporary, path, true);
    }
}
