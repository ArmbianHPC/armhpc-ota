using System.Diagnostics;
// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;

namespace ArmHpc.Ota.Core;

public sealed class RemoteRejectedException(string code, string message) : Exception(code + ": " + message)
{
    public string Code { get; } = code;
}

public sealed class TransientConnectionException(string message, Exception? inner = null) : IOException(message, inner);

public sealed record PendingTask(string DeviceId, string JobId, string Release, string Target,
    string Operation = "apply", string Stage = "submitting", int? Percent = null, string[]? Ranges = null)
{
    public bool Terminal => Stage is "succeeded" or "failed-recoverable" or "cancelled" or "refused";
}

/// <summary>Only coordinates the same public CLI; all deployment decisions stay on the device.</summary>
public static class JobMonitor
{
    public static int? Progress(JsonElement job)
    {
        if (!job.TryGetProperty("progress", out var progress) ||
            !progress.TryGetProperty("bytes", out var bytes) || !progress.TryGetProperty("total", out var total)) return null;
        long count = bytes.GetInt64(), length = total.GetInt64();
        return length > 0 ? (int)Math.Clamp((double)count * 100 / length, 0, 100) : null;
    }

    public static async Task<bool> Run(PendingTask task, Func<Task<JsonElement>> query,
        Func<Task<JsonElement>> submit, Func<Task> reconnect, Action<string, int?> changed,
        CancellationToken cancellation = default, int polls = 4800,
        Func<CancellationToken, Task>? delay = null,TimeSpan? reconnectTimeout=null)
    {
        if (Guid.Parse(task.JobId).ToString("D") != task.JobId) throw new ArgumentException("Invalid persistent task ID.");
        delay ??= token => Task.Delay(3000, token);
        bool submitted = false;Stopwatch? offline=null;reconnectTimeout??=TimeSpan.FromMinutes(5);
        for (int poll = 0; poll < polls; poll++)
        {
            cancellation.ThrowIfCancellationRequested();
            try
            {
                JsonElement status;
                try { status = await query(); }
                catch (RemoteRejectedException error) when (error.Code == "job_missing" && !submitted)
                {
                    // The user already approved this exact persistent ID and release. Retrying it cannot create a second task.
                    changed("submitting", null);
                    JsonElement created = await submit();
                    if (Protocol.Text(created, "job_id") != task.JobId) throw new InvalidOperationException("设备返回了另一个任务 ID。");
                    submitted = true;
                    await delay(cancellation);
                    continue;
                }
                if (Protocol.Text(status, "device_id") != task.DeviceId ||
                    !status.TryGetProperty("job", out var job) || job.ValueKind != JsonValueKind.Object ||
                    Protocol.Text(job, "job_id") != task.JobId)
                    throw new InvalidOperationException("任务或设备身份不匹配。");
                submitted = true;offline=null;
                string stage = Protocol.Text(job, "stage");
                if (stage.Length == 0) throw new InvalidOperationException("任务状态缺失。");
                changed(stage, Progress(job));
                if (stage == "succeeded") return true;
                if (stage is "failed-recoverable" or "cancelled") return false;
            }
            catch (TransientConnectionException)
            {
                offline??=Stopwatch.StartNew();
                if(offline.Elapsed>=reconnectTimeout)throw new TimeoutException("设备重启后尚未重连；原 OTA 任务结果待核对，可继续原任务。");
                changed("reconnecting", null);
                try{await reconnect();}catch(TransientConnectionException){}
            }
            catch (RemoteRejectedException)
            {
                changed("refused", null);
                throw;
            }
            await delay(cancellation);
        }
        changed("observation-timeout", null);
        throw new TimeoutException("观察超时；原 OTA 任务仍需核对，不会重新创建任务。");
    }
}
