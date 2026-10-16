// SPDX-License-Identifier: GPL-3.0-only
namespace ArmHpc.Ota.Core;

public static class Commands
{
    private static readonly HashSet<string> Public = ["bootstrap", "check", "plan", "download", "apply", "status", "logs", "cancel", "recover", "source", "doctor", "retry", "tools", "receive", "boot"];
    private static readonly HashSet<string> Options = ["--release", "--manifest", "--target", "--job", "--anchor-manifest", "--apply", "--recovery", "--request-id", "--url", "--tools-source", "--allow-http", "--ca", "--origin", "--bundle", "--rollback", "--phase", "--local-only", "--exported-backup-sha256", "--commit", "--execute"];
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";
    public static string Build(string command, IReadOnlyList<string> arguments, bool privileged, bool yes = false)
    {
        if (!Public.Contains(command)) throw new ArgumentException("只能调用公开 OTA 子命令。");
        int start = 0;
        if (command is "source" or "tools" or "boot")
        {
            if (arguments.Count == 0 || !(command == "source" ? new[] {"show","set","test"} : (command=="boot"?new[] {"plan","enter","apply","status","rollback","restore"}:new[] {"status","update"})).Contains(arguments[0])) throw new ArgumentException("未知子操作。");
            start = 1;
        }
        for (int index = start; index < arguments.Count; index++)
        {
            if (!Options.Contains(arguments[index])) throw new ArgumentException("未知 CLI 参数。");
            if (arguments[index] is not ("--apply" or "--recovery" or "--allow-http" or "--rollback" or "--local-only" or "--commit" or "--execute") && ++index >= arguments.Count) throw new ArgumentException("CLI 参数缺少值。");
        }
        string suffix = " ota " + Quote(command) + " --json" + (yes ? " --yes" : "") + " " + string.Join(" ", arguments.Select(Quote));
        string prefix = privileged ? "sudo -n -- " : "";
        return "if test -f /etc/armhpc/rescue-environment; then " + prefix + "/usr/local/sbin/armhpc-rescue" + suffix +
               "; else " + prefix + "/usr/local/sbin/armhpc" + suffix + "; fi";
    }
}
