// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using System.Text.Json.Nodes;
using ArmHpc.Ota.Core;

public static class PausedTaskCancellationChecks
{
    public static async Task Run(Action<bool, string> check)
    {
        var original = new AutomaticTask(Guid.NewGuid().ToString("D"), "cancel-device",
            new UpgradeOptions("https://example.invalid/index.json"), Guid.NewGuid().ToString("D"),
            Guid.NewGuid().ToString("D"), Stage: "paused", Release: "retained-release", Error: "boot_agent",
            Phase: "uploading-package", Kind: "firmware-update", FirmwareBundle: "/cache/paired.tar.xz",
            FirmwareSha256: new string('a', 64), BackupDirectory: "private-backup");
        var legacy = JsonNode.Parse(JsonSerializer.Serialize(original))!.AsObject();
        legacy.Remove("CancelledAt");
        var restored = JsonSerializer.Deserialize<AutomaticTask>(legacy.ToJsonString())!;
        check(restored.CancelledAt is null && restored.Stage == "paused", "old automatic task records remain readable without cancellation metadata");
        var timestamp = new DateTimeOffset(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);
        var cancelled = restored.CancelPaused(timestamp);
        check(cancelled.Stage == "cancelled" && cancelled.Terminal && cancelled.CancelledAt == timestamp,
            "cancelling a paused controller task ends local automation and records the cancellation time");
        check(cancelled.TaskId == original.TaskId && cancelled.JobId == original.JobId &&
              cancelled.MaintenanceId == original.MaintenanceId && cancelled.DeviceId == original.DeviceId,
            "local cancellation retains original device, automation, maintenance and deployment IDs");
        check(cancelled.Phase == original.Phase && cancelled.Error == original.Error && cancelled.Options == original.Options &&
              cancelled.Release == original.Release && cancelled.FirmwareBundle == original.FirmwareBundle &&
              cancelled.FirmwareSha256 == original.FirmwareSha256 && cancelled.BackupDirectory == original.BackupDirectory,
            "cancellation retains the paused error, phase, approved package and private recovery bindings");
        check(original.Stage == "paused" && original.CancelledAt is null, "cancellation does not mutate the previous in-memory record");
        foreach (string stage in new[] { "created", "maintaining", "reconnecting", "submitting", "firmware:staged", "succeeded", "failed-recoverable", "cancelled", "superseded" })
        {
            bool refused = false;
            try { (original with { Stage = stage }).CancelPaused(timestamp); }
            catch (InvalidOperationException) { refused = true; }
            check(refused, "paused cancellation refuses another task state: " + stage);
        }
        var connection = new ForbiddenConnection();
        int writes = 0, logs = 0;
        var result = await AutomaticUpgrade.Run(cancelled, connection, _ => writes++, _ => logs++, CancellationToken.None);
        check(result == cancelled && connection.Calls == 0 && writes == 0 && logs == 0,
            "resuming a cancelled local flow sends no query, cancellation, deployment, reboot or maintenance operation");

        string directory = Path.Combine(Path.GetTempPath(), "armhpc-cancel-" + Guid.NewGuid().ToString("N"));
        try
        {
            var vault = new Vault(directory);
            var other = original with { TaskId = Guid.NewGuid().ToString("D"), DeviceId = "other-device" };
            vault.SaveAutomatic([cancelled, other]);
            var history = new Vault(directory).LoadAutomatic();
            check(history.Count == 2 && history[0] == cancelled && history[1] == other,
                "restart retains cancelled history without changing another device's paused task");
            var replacement = AutomaticTask.Create(original.DeviceId, new UpgradeOptions("https://example.invalid/index.json"));
            vault.SaveAutomatic([.. history, replacement]);
            var reopened = new Vault(directory).LoadAutomatic();
            check(reopened.Count == 3 && reopened.Count(task => task.DeviceId == original.DeviceId && !task.Terminal) == 1 &&
                  reopened[0].Stage == "cancelled" && replacement.TaskId != original.TaskId,
                "a new local task can coexist with the retained cancelled record without reusing the original request IDs");
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private sealed class ForbiddenConnection : IUpgradeConnection
    {
        public int Calls { get; private set; }
        private T Forbidden<T>() { Calls++; throw new InvalidOperationException("Cancelled automation must not contact a device"); }
        public Task<JsonElement> Command(string command, IReadOnlyList<string> args, bool yes, CancellationToken token) => Forbidden<Task<JsonElement>>();
        public Task<JsonElement> Maintenance(CancellationToken token) => Forbidden<Task<JsonElement>>();
        public Task<JsonElement> Install(string bundle, string requestId, CancellationToken token) => Forbidden<Task<JsonElement>>();
        public Task<string> UploadCa(string file, CancellationToken token) => Forbidden<Task<string>>();
        public Task Reconnect(bool maintenance, CancellationToken token) => Forbidden<Task>();
    }
}
