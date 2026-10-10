// SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text.Json;
namespace ArmHpc.Ota.Core;

public sealed record MaintenanceSelection(AutomaticTask Task,AutomaticTask? Superseded,string Action);

public static class TaskFiles
{
    public static string Digest(string file)
    {
        string path=Path.GetFullPath(file);
        if(!File.Exists(path))throw new FileNotFoundException("维护包不存在，请重新选择实际文件："+path,path);
        using var input=File.OpenRead(path);return Convert.ToHexStringLower(SHA256.HashData(input));
    }
    public static AutomaticTask RelocateBundle(AutomaticTask original,string file)
    {
        if(original.Terminal)throw new InvalidOperationException("该本地任务已结束。");
        string path=Path.GetFullPath(file),digest=Digest(path);
        if(original.Options.BundleSha256 is null || original.Options.BundleSha256!=digest)
            throw new InvalidOperationException("所选维护包与原任务 SHA256 不同，不能以同一维护 ID 替换版本。请核对旧维护状态后创建新维护。");
        return original with {Options=original.Options with {Bundle=path}};
    }
    public static MaintenanceSelection SelectTools(AutomaticTask original,string file,JsonElement? remote=null)
    {
        if(!original.Options.ToolsOnly || original.Terminal)throw new InvalidOperationException("只能处理未结束的工具维护任务；系统升级任务必须继续原绑定。");
        string path=Path.GetFullPath(file),digest=Digest(path);
        if(original.Options.BundleSha256==digest)return new(RelocateBundle(original,path),null,"relocated-original");
        if(remote is null)throw new InvalidOperationException("换维护包前必须查询设备当前维护状态。");
        JsonElement identity=remote.Value;
        if(Protocol.Text(identity,"device_id")!=original.DeviceId || Protocol.Text(identity,"mode") is not ("rescue" or "system"))
            throw new InvalidOperationException("维护状态的设备身份不匹配。");
        if(!identity.TryGetProperty("maintenance",out var current))
            throw new InvalidOperationException("设备没有提供维护状态，不能确认旧任务已结束。");
        if(current.ValueKind!=JsonValueKind.Null)
        {
            if(current.ValueKind!=JsonValueKind.Object || Protocol.Text(current,"stage") is not ("succeeded" or "rolled-back"))
                throw new InvalidOperationException("设备维护尚未结束，不能换包。请选择原 SHA256 的包继续，或先完成/回滚旧维护。");
        }
        var replacement=AutomaticTask.Create(original.DeviceId,new UpgradeOptions("",Bundle:path,ToolsOnly:true,Ranges:original.Options.Ranges));
        var history=original with {Stage="superseded",Error="本地观察被新维护替换；未向设备发送取消，未将旧任务未知结果计为成功。"};
        return new(replacement,history,"new-maintenance-after-device-idle");
    }
    public static void VerifyBundle(AutomaticTask task)
    {
        string file=task.Options.Bundle??throw new InvalidOperationException("本次维护需要原签名包，请重新选择。");
        if(Digest(file)!=task.Options.BundleSha256)throw new InvalidOperationException("维护包 SHA256 与原任务绑定不符。");
    }
}
