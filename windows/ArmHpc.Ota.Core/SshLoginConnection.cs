// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace ArmHpc.Ota.Core;

public sealed class SshLoginRejectedException(string attempts) : SshAuthenticationException(
    "SSH 登录认证失败：" + attempts + "。请核对对应环境的登录设置。");
internal sealed class SshLoginMethodUnavailableException() : SshAuthenticationException("配置的 SSH 私钥无法加载。");

public sealed partial class SshRunner
{
    sealed class LoginConnection<T>(T client, Credentials credentials, string fingerprint, SshLoginContext? context) : IDisposable
        where T : BaseClient
    {
        public T Client { get; } = client;
        public Credentials Credentials { get; } = credentials;
        public string Fingerprint { get; } = fingerprint;
        public void Verified(JsonElement identity) => context?.Verified?.Invoke(
            Protocol.Text(identity, "device_id"), Protocol.Text(identity, "mode"), Credentials);
        public void Dispose() => Client.Dispose();
    }

    static LoginConnection<T> ConnectLogin<T>(Endpoint endpoint, Credentials credentials, Device? device,
        Func<ConnectionInfo, T> create, CancellationToken token, Func<string, string, bool>? approveHostKey = null,
        string? requiredMode = null) where T : BaseClient
    {
        var remaining = new Queue<LoginChoice>(LoginProfiles.Choices(credentials, requiredMode));
        var attempted = new List<LoginChoice>();
        var approved = new HashSet<string>(StringComparer.Ordinal);
        var failures = new List<string>();
        while (remaining.TryDequeue(out var choice))
        {
            token.ThrowIfCancellationRequested();
            if (attempted.Any(c => LoginProfiles.SameAttempt(c, choice))) continue;
            attempted.Add(choice);
            T? client = null;
            string fingerprint = ""; bool observed = false, trusted = false;
            IReadOnlyList<LoginChoice>? environmentChoices = null;
            bool redirect = false;
            try
            {
                credentials.Ssh?.Progress?.Invoke("SSH 认证 · " + choice.Label);
                client = create(Info(endpoint, choice.Credentials, choice.Authentication));
                client.HostKeyReceived += (_, args) =>
                {
                    observed = true;
                    fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(args.HostKey)).TrimEnd('=');
                    bool pinned = requiredMode is null
                        ? device?.HostKeys.Values.Contains(fingerprint, StringComparer.Ordinal) == true
                        : device?.HostKeys.TryGetValue(requiredMode, out var pin) == true && pin == fingerprint;
                    trusted = device?.IgnoreFingerprint == true || pinned || approved.Contains(fingerprint);
                    if (!trusted && approveHostKey?.Invoke(endpoint.Address, fingerprint) == true)
                    { trusted = true; approved.Add(fingerprint); }
                    args.CanTrust = trusted;
                    if (!trusted) return;
                    var modes = device?.HostKeys.Where(p => p.Value == fingerprint).Select(p => p.Key).Distinct().ToArray() ?? [];
                    string? mode = requiredMode ?? (modes.Length == 1 ? modes[0] : null);
                    if (mode is not ("system" or "rescue") || credentials.Ssh is null) return;
                    environmentChoices = LoginProfiles.Choices(credentials, mode);
                    var preferred = environmentChoices.FirstOrDefault(c => LoginProfiles.SameAttempt(c, choice) ||
                        !attempted.Any(a => LoginProfiles.SameAttempt(a, c)));
                    if (preferred is null || !LoginProfiles.SameAttempt(preferred, choice))
                    { redirect = true; args.CanTrust = false; }
                };
                using var cancelled = token.Register(client.Dispose);
                token.ThrowIfCancellationRequested();
                client.Connect();
                return new(client, choice.Credentials, fingerprint, credentials.Ssh);
            }
            catch (Exception error)
            {
                client?.Dispose(); token.ThrowIfCancellationRequested();
                if (redirect)
                {
                    remaining = new Queue<LoginChoice>(environmentChoices!);
                    credentials.Ssh?.Progress?.Invoke("已按可信 SSH 指纹切换登录环境");
                    continue;
                }
                if (observed && !trusted)
                    throw new SshHostIdentityException("SSH 指纹未获信任；尚未进行账号登录。请核对当前环境的 SSH 身份。");
                if (error is not SshAuthenticationException) throw;
                failures.Add(choice.Label);
                if (environmentChoices is not null) remaining = new Queue<LoginChoice>(environmentChoices);
                credentials.Ssh?.Progress?.Invoke((error is SshLoginMethodUnavailableException ? "SSH 私钥无法加载 · " : "SSH 认证未通过 · ") + choice.Label);
            }
        }
        throw new SshLoginRejectedException(failures.Count == 0 ? "没有可用的环境登录设置" : string.Join("、", failures.Distinct()));
    }
}
