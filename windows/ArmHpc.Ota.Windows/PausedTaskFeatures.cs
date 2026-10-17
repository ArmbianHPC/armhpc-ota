// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using System.Windows;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;

public partial class MainWindow
{
    private IReadOnlyList<AutomaticTask> AutomaticTasksForSelection()
    {
        var ids = SelectedTargets(false).Select(device => device.DeviceId).ToHashSet();
        return automaticTasks.Where(task => ids.Contains(task.DeviceId)).ToArray();
    }

    private static JsonElement AutomaticHistory(IEnumerable<AutomaticTask> tasks) =>
        JsonSerializer.SerializeToElement(new
        {
            scope = "controller",
            device_operations_continue = true,
            tasks = tasks.Select(task => new
            {
                task_id = task.TaskId,
                device_id = task.DeviceId,
                stage = task.Stage,
                last_phase = task.Phase,
                last_error = task.Error,
                release = task.Release,
                kind = task.Kind,
                maintenance_id = task.MaintenanceId,
                job_id = task.JobId,
                cancelled_at = task.CancelledAt,
                terminal = task.Terminal
            }).ToArray()
        });

    private IReadOnlyList<AutomaticTask> CancelPausedAutomaticTasks(IReadOnlyList<string> taskIds)
    {
        if (batching)
            throw new InvalidOperationException("请等待当前上位机操作结束后，再取消暂停任务。");
        var ids = taskIds.ToHashSet();
        if (ids.Count == 0 || ids.Count != taskIds.Count ||
            automaticTasks.Count(task => ids.Contains(task.TaskId) && task.Stage == "paused") != ids.Count)
            throw new InvalidOperationException("任务状态已变化；只能取消仍处于暂停状态的上位机自动流程。");

        var timestamp = DateTimeOffset.UtcNow;
        var updated = automaticTasks.Select(task => ids.Contains(task.TaskId) ? task.CancelPaused(timestamp) : task).ToList();
        vault.SaveAutomatic(updated);
        automaticTasks.Clear();
        automaticTasks.AddRange(updated);
        var cancelled = updated.Where(task => ids.Contains(task.TaskId)).ToArray();
        foreach (var device in devices.Where(device => cancelled.Any(task => task.DeviceId == device.DeviceId)))
        {
            device.State = "上位机自动流程已取消";
            device.CommandSummary = "本地流程已取消；设备端已提交的操作继续执行。";
            device.CommandDetail = JsonSerializer.Serialize(AutomaticHistory(cancelled.Where(task => task.DeviceId == device.DeviceId)), Pretty);
        }
        foreach (var task in cancelled)
            Log($"{task.DeviceId} · 已取消暂停的上位机任务 {task.TaskId}；保留历史，设备端已提交的操作继续执行。");
        StatusBar.Text = $"已取消 {cancelled.Length} 个暂停的上位机任务；历史已保留，设备端已提交的操作继续执行。";
        Show(AutomaticHistory(cancelled));
        return cancelled;
    }

    private void CancelPausedTasksClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (batching)
                throw new InvalidOperationException("请等待当前上位机操作结束后，再取消暂停任务。");
            var paused = AutomaticTasksForSelection().Where(task => task.Stage == "paused").ToArray();
            if (paused.Length == 0)
            {
                StatusBar.Text = "所选设备没有暂停的上位机自动任务。";
                return;
            }
            string summary = string.Join(Environment.NewLine, paused.Select(task =>
                $"{devices.First(device => device.DeviceId == task.DeviceId).Name} · {task.TaskId} · {task.Phase}"));
            string message = $"取消以下 {paused.Length} 个暂停的上位机自动流程？\n\n{summary}\n\n原任务 ID、暂停原因和历史记录会保留。设备端已提交的操作继续执行；取消后不会自动继续此流程。";
            if (MessageBox.Show(this, message, "取消暂停任务", MessageBoxButton.YesNo, MessageBoxImage.Question,
                                MessageBoxResult.No) != MessageBoxResult.Yes)
                return;
            CancelPausedAutomaticTasks(paused.Select(task => task.TaskId).ToArray());
        }
        catch (Exception error)
        {
            MessageBox.Show(this, error.Message, "暂停任务未取消");
        }
    }

    private void AutomaticTaskHistoryClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var history = AutomaticTasksForSelection();
            Show(AutomaticHistory(history));
            StatusBar.Text = $"所选设备的上位机自动流程历史：{history.Count} 条。";
        }
        catch (Exception error)
        {
            MessageBox.Show(this, error.Message, "无法读取自动流程历史");
        }
    }
}
