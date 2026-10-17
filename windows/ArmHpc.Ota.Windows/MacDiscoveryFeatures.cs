// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using System.Windows;
using ArmHpc.Ota.Core;

namespace ArmHpc.Ota.Windows;

public partial class MainWindow
{
    sealed record MacScanOutcome(string DeviceId, string PreviousAddress, IReadOnlyList<MacIpCandidate> Candidates,
        bool AddressUpdated = false, string VerifiedAddress = "", string Detail = "等待身份核对");

    void ApplyMacAddress(Device device, MacIpCandidate candidate, RemoteResult response, bool approvedNewFingerprint)
    {
        MacDiscovery.Accept(device, candidate, response, approvedNewFingerprint);
        Update(device, response);
        Save();
    }

    private async void MacScanClick(object sender, RoutedEventArgs e)
    {
        if (batching || scanning is not null || authenticating is not null)
        { StatusBar.Text = "请先停止扫描或等待当前操作完成。"; return; }
        using var session = CancellationTokenSource.CreateLinkedTokenSource(closing.Token);
        var outcomes = new List<MacScanOutcome>();
        try
        {
            var targets = SelectedTargets();
            string[] ranges = string.IsNullOrWhiteSpace(ScanRange.Text) ? [] : [ScanRange.Text.Trim()];
            batching = true; scanning = session; MacScanButton.IsEnabled = false;
            void Progress(string value) => Dispatcher.Invoke(() => { StatusBar.Text = value; Log(value); });
            var report = await MacDiscovery.Scan(targets, ranges, session.Token, Progress);
            outcomes.AddRange(report.Devices.Select(match => new MacScanOutcome(match.DeviceId,
                targets.Single(d => d.DeviceId == match.DeviceId).Address, match.Candidates)));
            void Present() => Show(JsonSerializer.SerializeToElement(new { scan_ranges = report.Ranges, results = outcomes }));
            Present();
            for (int i = 0; i < outcomes.Count; i++)
            {
                session.Token.ThrowIfCancellationRequested();
                var outcome = outcomes[i];
                var device = targets.Single(d => d.DeviceId == outcome.DeviceId);
                device.LastCommand = "按 MAC 查找 IP";
                if (outcome.Candidates.Count == 0)
                    outcome = outcome with { Detail = "扫描范围内没有匹配 MAC；跨路由可能无法读取设备 MAC。" };
                else if (!outcome.Candidates.Any(c => c.SshReady))
                    outcome = outcome with { Detail = "已找到邻居记录，但 SSH 尚未就绪；保留原地址，请稍后重扫。" };
                else
                {
                    try
                    {
                        var credentials = CredentialsFor(device);
                        var approved = new HashSet<string>(StringComparer.Ordinal);
                        bool Approve(string address, string fingerprint)
                        {
                            bool accepted = TrustHost(address, fingerprint);
                            if (accepted) approved.Add(fingerprint);
                            return accepted;
                        }
                        foreach (var candidate in outcome.Candidates.Where(c => c.SshReady))
                        {
                            session.Token.ThrowIfCancellationRequested();
                            try
                            {
                                var response = await ssh.Authenticate(new(candidate.Address, candidate.Port), credentials,
                                    NetworkReconnect.DiscoveryIdentity(device), Approve, Progress, session.Token);
                                ApplyMacAddress(device, candidate, response, approved.Contains(response.Fingerprint));
                                outcome = outcome with { AddressUpdated = true, VerifiedAddress = device.Address,
                                    Detail = "已核对 SSH 指纹和原设备 ID，地址已更新。" };
                                Log($"按 MAC 查找 IP · {outcome.PreviousAddress} → {device.Address} · {device.Mode} · 身份已核对");
                                break;
                            }
                            catch (Exception error) when (!session.IsCancellationRequested)
                            {
                                outcome = outcome with { Detail = NetworkReconnect.FailureReason(error) + "；保留原地址。" };
                                Log($"MAC 匹配地址 {candidate.Address}:{candidate.Port} · {outcome.Detail}");
                            }
                        }
                    }
                    catch (OperationCanceledException) when (!session.IsCancellationRequested)
                    { outcome = outcome with { Detail = "登录设置已取消；保留扫描结果和原地址。" }; }
                }
                outcomes[i] = outcome;
                device.CommandSummary = outcome.AddressUpdated ? "MAC 地址核对完成" : "MAC 扫描结果待核对";
                device.CommandDetail = JsonSerializer.Serialize(outcome, Pretty);
                Present(); Save();
            }
            StatusBar.Text = $"MAC 扫描完成：{outcomes.Sum(o => o.Candidates.Count)} 个匹配地址，{outcomes.Count(o => o.AddressUpdated)} 台完成身份核对。";
        }
        catch (OperationCanceledException) { StatusBar.Text = "MAC 扫描已停止，已核对的地址和扫描结果已保留。"; }
        catch (Exception error) { MessageBox.Show(this, error.Message, "MAC 扫描未完成"); }
        finally
        {
            if (scanning == session) scanning = null;
            batching = false; MacScanButton.IsEnabled = true; RefreshSelectionSummary();
        }
    }
}
