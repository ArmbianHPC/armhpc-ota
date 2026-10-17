// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Renci.SshNet;

namespace ArmHpc.Ota.Core;

public sealed record BackupArchiveResult(string Archive,string ArchiveSha256,string InventorySha256,string BackupId,long Bytes);

public static class StorageCleanup
{
    public static JsonElement ProtectControllerTasks(JsonElement plan,bool pending)
    {
        if(!pending)return plan.Clone();
        var value=JsonNode.Parse(plan.GetRawText())!.AsObject();
        var kept=new JsonArray();var protectedItems=value["protected"]!.AsArray();long bytes=0;
        foreach(var item in value["items"]!.AsArray())
        {
            if(item!["kind"]!.GetValue<string>()=="exported-backup")
            {kept.Add(item.DeepClone());bytes=checked(bytes+item["bytes"]!.GetValue<long>());}
            else protectedItems.Add(new JsonObject{["path"]=item["path"]!.GetValue<string>(),
                ["reason"]="上位机保留有未完成任务；保留上传与缓存，供原任务继续。"});
        }
        value["items"]=kept;value["reclaimable_bytes"]=bytes;
        return JsonSerializer.SerializeToElement(value);
    }
    public static string[] Arguments(JsonElement plan)
    {
        var ids=plan.GetProperty("items").EnumerateArray().Select(i=>Protocol.Text(i,"id")).ToArray();
        if(ids.Length==0)throw new InvalidOperationException("清理清单为空。");
        return new[]{"cleanup","--plan-id",Protocol.Text(plan,"plan_id")}
            .Concat(ids.SelectMany(id=>new[]{"--item",id})).ToArray();
    }
}

public static class BackupArchive
{
    static readonly Regex Hash=new("^[a-f0-9]{64}$");
    public static string InventoryHash(JsonElement inventory)
    {
        using var stream=new MemoryStream();
        using(var writer=new Utf8JsonWriter(stream,new(){Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping}))
        {
            void Write(JsonElement value)
            {
                if(value.ValueKind==JsonValueKind.Object){writer.WriteStartObject();foreach(var p in value.EnumerateObject().OrderBy(p=>p.Name,StringComparer.Ordinal)){writer.WritePropertyName(p.Name);Write(p.Value);}writer.WriteEndObject();}
                else if(value.ValueKind==JsonValueKind.Array){writer.WriteStartArray();foreach(var v in value.EnumerateArray())Write(v);writer.WriteEndArray();}
                else value.WriteTo(writer);
            }
            Write(inventory);
        }
        return Convert.ToHexStringLower(SHA256.HashData(stream.ToArray()));
    }
    public static string LocalPath(string root,string name)
    {
        var parts=name.Split('/');
        if(parts.Length==0 || parts.Any(p=>p.Length==0 || p is "." or ".." || p.EndsWith('.') || p.EndsWith(' ') ||
            Regex.IsMatch(p,@"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)",RegexOptions.IgnoreCase) ||
            p.Any(c=>c<' ' || c is '\\' or ':' || Path.GetInvalidFileNameChars().Contains(c))))
            throw new InvalidDataException("备份文件名不安全。");
        string full=Path.GetFullPath(Path.Combine(root,Path.Combine(parts)));
        string prefix=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)+Path.DirectorySeparatorChar;
        if(!full.StartsWith(prefix,StringComparison.Ordinal))throw new InvalidDataException("备份文件超出目录。");
        SafePath(full);return full;
    }
    public static void SafePath(string path)
    {
        for(string? p=Path.GetFullPath(path);p is not null;p=Path.GetDirectoryName(p))
            if((File.Exists(p) || Directory.Exists(p)) && File.GetAttributes(p).HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("备份目标及其父目录不能是链接。");
    }
    public static JsonElement Validate(JsonElement prepared,string deviceId)
    {
        var inventory=prepared.GetProperty("inventory");
        if(Protocol.Text(inventory,"device_id")!=deviceId || Protocol.Text(inventory,"kind")!="private-backup-export" ||
           InventoryHash(inventory)!=Protocol.Text(prepared,"inventory_sha256") || !Hash.IsMatch(Protocol.Text(inventory,"backup_id")) ||
           !Guid.TryParseExact(Protocol.Text(inventory,"task_id"),"D",out _))throw new InvalidDataException("备份清单、设备身份或哈希不符。");
        string task=Protocol.Text(inventory,"task_id"),source=Protocol.Text(inventory,"source");
        if(source!="/var/lib/armhpc/ota/cache/boot-backups/"+task && source!="/data/armhpc-ota/cache/boot-backups/"+task &&
           source!="/var/lib/armhpc/ota/maintenance/backups/"+task)throw new InvalidDataException("备份来源超出允许目录。");
        var files=inventory.GetProperty("files").EnumerateArray().ToArray();var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total=0;
        if(files.Length is <1 or >10000)throw new InvalidDataException("备份文件数量无效。");
        foreach(var f in files)
        {
            string name=Protocol.Text(f,"name");LocalPath(Path.GetTempPath(),name);
            long bytes=f.GetProperty("bytes").GetInt64();
            if(!names.Add(name) || !Hash.IsMatch(Protocol.Text(f,"sha256")) || bytes<0 || bytes>4L*1024*1024*1024)throw new InvalidDataException("备份文件重复或大小、哈希无效。");
            total=checked(total+bytes);
        }
        if(total>8L*1024*1024*1024)throw new InvalidDataException("备份超过单组容量限制。");
        return inventory;
    }
    static void VerifyFile(string path,JsonElement file)
    {
        using var stream=File.OpenRead(path);
        if(stream.Length!=file.GetProperty("bytes").GetInt64() || Convert.ToHexStringLower(SHA256.HashData(stream))!=Protocol.Text(file,"sha256"))
            throw new InvalidDataException("备份大小或 SHA256 不符："+Protocol.Text(file,"name"));
    }
    public static void VerifyArchive(string archive,JsonElement inventory,CancellationToken token=default)
    {
        using var zip=ZipFile.OpenRead(archive);
        var files=inventory.GetProperty("files").EnumerateArray().ToArray();
        if(zip.Entries.Count!=files.Length+1 || zip.Entries.Select(e=>e.FullName).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=zip.Entries.Count)
            throw new InvalidDataException("备份压缩包内容不完整或重复。");
        var manifest=zip.GetEntry("backup-inventory.json")??throw new InvalidDataException("压缩包缺少清单。");
        if(manifest.Length>4*1024*1024)throw new InvalidDataException("压缩包清单过大。");
        using(var input=manifest.Open())using(var doc=JsonDocument.Parse(input))
            if(InventoryHash(doc.RootElement)!=InventoryHash(inventory))throw new InvalidDataException("压缩包清单哈希不符。");
        foreach(var f in files)
        {
            token.ThrowIfCancellationRequested();
            var entry=zip.GetEntry("files/"+Protocol.Text(f,"name"))??throw new InvalidDataException("压缩包缺少备份文件。");
            using var stream=entry.Open();
            if(entry.Length!=f.GetProperty("bytes").GetInt64() || Convert.ToHexStringLower(SHA256.HashData(stream))!=Protocol.Text(f,"sha256"))
                throw new InvalidDataException("压缩包解压校验失败："+entry.FullName);
        }
    }
    public static async Task<BackupArchiveResult> Create(JsonElement prepared,string deviceId,string directory,
        Func<JsonElement,string,CancellationToken,Task> download,Action<string> log,CancellationToken token=default)
    {
        var inventory=Validate(prepared,deviceId);string hash=Protocol.Text(prepared,"inventory_sha256"),id=Protocol.Text(inventory,"backup_id");
        string stem="armhpc-backup_"+deviceId[..Math.Min(12,deviceId.Length)]+"_"+Protocol.Text(inventory,"task_id")+"_"+hash[..12];
        directory=Path.GetFullPath(directory);SafePath(directory);Directory.CreateDirectory(directory);
        string archive=Path.Combine(directory,stem+".zip"),partial=archive+".partial",raw=Path.Combine(directory,"."+stem+".files");
        SafePath(archive);SafePath(partial);SafePath(raw);Directory.CreateDirectory(raw);
        if(!OperatingSystem.IsWindows())File.SetUnixFileMode(raw,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var files=inventory.GetProperty("files").EnumerateArray().ToArray();
        if(!File.Exists(archive))
        {
            foreach(var f in files)
            {
                token.ThrowIfCancellationRequested();string path=LocalPath(raw,Protocol.Text(f,"name"));
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                bool valid=false;
                if(File.Exists(path)){try{VerifyFile(path,f);valid=true;}catch(InvalidDataException){}}
                if(!valid)
                {
                    string incoming=path+".partial";SafePath(incoming);
                    if(File.Exists(incoming) && new FileInfo(incoming).Length>=f.GetProperty("bytes").GetInt64())
                    {
                        try{VerifyFile(incoming,f);}catch(InvalidDataException){File.Delete(incoming);}
                    }
                    await download(f,incoming,token);token.ThrowIfCancellationRequested();VerifyFile(incoming,f);File.Move(incoming,path,true);
                }
                log("已接收并校验："+Protocol.Text(f,"name"));
            }
            token.ThrowIfCancellationRequested();log("上位机正在压缩备份");
            await Task.Run(()=>
            {
                using(var output=new FileStream(partial,FileMode.Create,FileAccess.Write,FileShare.None))
                {
                    if(!OperatingSystem.IsWindows())File.SetUnixFileMode(partial,UnixFileMode.UserRead|UnixFileMode.UserWrite);
                    using(var zip=new ZipArchive(output,ZipArchiveMode.Create,true))
                    {
                        using(var stream=zip.CreateEntry("backup-inventory.json").Open())JsonSerializer.Serialize(stream,inventory);
                        foreach(var f in files)
                        {
                            token.ThrowIfCancellationRequested();string name=Protocol.Text(f,"name");
                            using var input=File.OpenRead(LocalPath(raw,name));using var stream=zip.CreateEntry("files/"+name,CompressionLevel.Optimal).Open();
                            input.CopyTo(stream);
                        }
                    }
                    output.Flush(true);
                }
                log("上位机正在解压校验压缩包");VerifyArchive(partial,inventory,token);File.Move(partial,archive,false);
            },token);
        }
        await Task.Run(()=>VerifyArchive(archive,inventory,token),token);
        string archiveHash;
        using(var stream=File.OpenRead(archive))archiveHash=Convert.ToHexStringLower(SHA256.HashData(stream));
        var result=new BackupArchiveResult(archive,archiveHash,hash,id,files.Sum(f=>f.GetProperty("bytes").GetInt64()));
        string receipt=archive+".json";SafePath(receipt);SafePath(receipt+".partial");
        using(var output=new FileStream(receipt+".partial",FileMode.Create,FileAccess.Write,FileShare.None))
        {if(!OperatingSystem.IsWindows())File.SetUnixFileMode(receipt+".partial",UnixFileMode.UserRead|UnixFileMode.UserWrite);
            JsonSerializer.Serialize(output,new{protocol=1,kind="verified-private-backup-archive",device_id=deviceId,result,inventory});output.Flush(true);}
        File.Move(receipt+".partial",receipt,true);
        // Only the generated, verified download set is removed from the host.
        // Unknown files are retained, and failed exports always keep their raw data.
        foreach(var f in files){string p=LocalPath(raw,Protocol.Text(f,"name"));if(File.Exists(p)){VerifyFile(p,f);File.Delete(p);}}
        var parents=files.Select(f=>Path.GetDirectoryName(LocalPath(raw,Protocol.Text(f,"name")))!).ToHashSet(StringComparer.Ordinal);
        foreach(string directoryPath in parents.OrderByDescending(p=>p.Length))
            for(string? p=directoryPath;p is not null && p!=raw;p=Path.GetDirectoryName(p))
            {SafePath(p);if(Directory.Exists(p) && !Directory.EnumerateFileSystemEntries(p).Any())Directory.Delete(p);}
        if(!Directory.EnumerateFileSystemEntries(raw).Any())Directory.Delete(raw);
        return result;
    }
}

public sealed partial class SshRunner
{
    public async Task<BackupArchiveResult> DownloadBackup(Endpoint endpoint,Credentials credentials,Device device,JsonElement prepared,
        string directory,Action<string> log,CancellationToken token)
    {
        var identity=await Execute(endpoint,credentials,device,"status",[],cancellation:token);
        if(identity.Mode!="rescue")throw new InvalidOperationException("请先进入 Rescue 再导出备份。");
        var inventory=BackupArchive.Validate(prepared,device.DeviceId);
        using var login=await Task.Run(()=>ConnectLogin(endpoint,credentials,device,info=>new SftpClient(info),token,requiredMode:"rescue"),token);
        var client=login.Client;using var cancelled=token.Register(()=>client.Dispose());client.OperationTimeout=TimeSpan.FromSeconds(30);
        return await BackupArchive.Create(prepared,device.DeviceId,directory,async (file,path,ct)=>
        {
            await Task.Run(()=>
            {
                string remote=Protocol.Text(inventory,"source")+"/"+Protocol.Text(file,"name");
                if(client.GetAttributes(remote).IsSymbolicLink)throw new IOException("备份文件不能是链接。");
                using var output=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.None);
                client.DownloadFile(remote,output);ct.ThrowIfCancellationRequested();output.Flush(true);
            },ct);
        },log,token);
    }
}

public sealed partial class SerialRunner
{
    public Task<BackupArchiveResult> DownloadBackup(Device device,Credentials credentials,JsonElement prepared,
        string directory,Action<string> log,CancellationToken token)=>Use(device,credentials,async session=>
    {
        var identity=await Query(session,Commands.Build("status",[],credentials.Username!="root"),token,TimeSpan.FromSeconds(30));
        ConsoleProtocol.VerifyIdentity(device,identity);
        if(Protocol.Text(identity,"mode")!="rescue")throw new InvalidOperationException("请先进入 Rescue 再导出备份。");
        BackupArchive.Validate(prepared,device.DeviceId);
        return await BackupArchive.Create(prepared,device.DeviceId,directory,async (file,path,ct)=>
        {
            string command=Privileged(credentials,"env PYTHONPATH=/usr/lib/armhpc-ota python3 -m armhpc_ota.serial_stream --storage-export "+
                Commands.Quote(Protocol.Text(prepared,"inventory_sha256"))+" --name "+Commands.Quote(Protocol.Text(file,"name")));
            await session.StreamDownload(command,path,file.GetProperty("bytes").GetInt64(),Protocol.Text(file,"sha256"),log,ct);
        },log,token);
    },token);
}
