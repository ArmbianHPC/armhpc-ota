// SPDX-License-Identifier: GPL-3.0-only
namespace ArmHpc.Ota.Core;

public sealed class BatchQueue
{
    public const int MaxConcurrency=8;
    public static void ValidateConcurrency(int value){if(value is <1 or >MaxConcurrency)throw new ArgumentException("并发必须为 1–8。");}
    private int stopped;
    public bool Stopped => Volatile.Read(ref stopped) != 0;
    public void Stop() => Interlocked.Exchange(ref stopped, 1);
    public async Task Run(IReadOnlyList<Device> devices, int concurrency, Func<Device, Task<bool>> execute, Action<Device>? skipped = null, bool pilot=true, bool stopOnFailure=true)
    {
        ValidateConcurrency(concurrency);
        Interlocked.Exchange(ref stopped, 0);
        if (devices.Count == 0) return;
        int next=0;
        if(pilot)
        {
            bool success;try{success=await execute(devices[0]);}catch{success=false;}next=1;
            if(!success && stopOnFailure){Stop();foreach(var item in devices.Skip(1))skipped?.Invoke(item);return;}
        }
        object sync = new();
        var workers = Enumerable.Range(0, concurrency).Select(async _ =>
        {
            while (true)
            {
                Device? device;
                lock (sync) { device = Stopped || next >= devices.Count ? null : devices[next++]; }
                if (device is null) return;
                bool success;
                try { success = await execute(device); }
                catch { success = false; }
                if (!success && stopOnFailure) Stop();
            }
        }).ToArray();
        await Task.WhenAll(workers);
        foreach (var item in devices.Skip(next)) skipped?.Invoke(item);
    }
}
