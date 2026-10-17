// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using ArmHpc.Ota.Core;

public static class BackupStorageChecks
{
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        string home=Path.Combine(Path.GetTempPath(),"armhpc-backup-checks-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(home);
        try
        {
            string task=Guid.NewGuid().ToString("D"),device="fixture-device",backup=new string('b',64);
            byte[] original=System.Text.Encoding.UTF8.GetBytes("private original BOOT bytes"),entry=System.Text.Encoding.UTF8.GetBytes("original entry");
            object File(string name,byte[] bytes)=>new{name,bytes=bytes.Length,sha256=Convert.ToHexStringLower(SHA256.HashData(bytes)),mtime_ns=123L,inode=456L,device=789L};
            var inventory=JsonSerializer.SerializeToElement(new{protocol=1,kind="private-backup-export",device_id=device,backup_id=backup,task_id=task,
                backup_kind="boot",source="/var/lib/armhpc/ota/cache/boot-backups/"+task,files=new[]{File("BOOT-original.img",original),File("entries/boot.scr",entry)}});
            var prepared=JsonSerializer.SerializeToElement(new{inventory,inventory_sha256=BackupArchive.InventoryHash(inventory)});
            var plan=JsonSerializer.SerializeToElement(new{plan_id=new string('a',64),reclaimable_bytes=30,
                items=new[]{new{id=new string('b',64),kind="exported-backup",path="backup",bytes=10},new{id=new string('c',64),kind="upload",path="upload",bytes=20}},
                @protected=Array.Empty<object>()});
            var guarded=StorageCleanup.ProtectControllerTasks(plan,true);
            check(guarded.GetProperty("items").GetArrayLength()==1 && guarded.GetProperty("reclaimable_bytes").GetInt64()==10 &&
                guarded.GetProperty("protected").GetArrayLength()==1 && Protocol.Text(guarded,"plan_id")==Protocol.Text(plan,"plan_id"),"paused controller tasks retain uploads and caches without invalidating device plan identity");
            var cleanupArgs=StorageCleanup.Arguments(guarded);
            check(cleanupArgs.Length==5 && cleanupArgs[^1]==new string('b',64) && cleanupArgs[^2]=="--item","cleanup sends only the exact previewed selection");
            var empty=JsonSerializer.SerializeToElement(new{plan_id=new string('a',64),items=Array.Empty<object>()});
            refused(()=>StorageCleanup.Arguments(empty),"an empty preview never falls back to deleting every device candidate");
            check(StorageCleanup.ProtectControllerTasks(plan,false).GetProperty("items").GetArrayLength()==2,"completed controller tasks do not retain unrelated cache remnants");
            int calls=0;
            async Task Download(JsonElement file,string target,CancellationToken token)
            {
                calls++;await System.IO.File.WriteAllBytesAsync(target,Protocol.Text(file,"name")=="BOOT-original.img"?original:entry,token);
            }
            var result=await BackupArchive.Create(prepared,device,home,Download,_=>{});
            check(calls==2 && System.IO.File.Exists(result.Archive),"original backup files reach the host before compression");
            check(result.Bytes==original.Length+entry.Length && result.InventorySha256==BackupArchive.InventoryHash(inventory),"archive result remains bound to the exact device inventory");
            BackupArchive.VerifyArchive(result.Archive,inventory);
            using(var zip=ZipFile.OpenRead(result.Archive))check(zip.GetEntry("files/entries/boot.scr") is not null && zip.GetEntry("backup-inventory.json") is not null,"host ZIP contains original hierarchy and inventory");
            using(var file=System.IO.File.OpenRead(result.Archive))check(Convert.ToHexStringLower(SHA256.HashData(file))==result.ArchiveSha256,"verified host archive has a whole-file SHA256");
            check(System.IO.File.Exists(result.Archive+".json") && !Directory.GetDirectories(home).Any(),"durable local receipt precedes removal of generated uncompressed staging");
            await BackupArchive.Create(prepared,device,home,(_,_,_)=>throw new Exception("must not redownload a verified archive"),_=>{});
            check(calls==2,"existing verified archive is reused without downloading private files again");
            refused(()=>BackupArchive.Validate(prepared,"other-device"),"backup export refuses another device");
            refused(()=>BackupArchive.LocalPath(home,"../outside"),"backup file path traversal is refused");
            refused(()=>BackupArchive.LocalPath(home,"entries\\outside"),"backup filenames cannot inject platform separators");
            refused(()=>BackupArchive.LocalPath(home,"entries/C:outside"),"backup filenames cannot inject drive paths");
            var changed=JsonSerializer.SerializeToElement(new{inventory,inventory_sha256=new string('0',64)});
            refused(()=>BackupArchive.Validate(changed,device),"modified backup inventory is refused");
            string fail=Path.Combine(home,"failed");bool failed=false;
            try{await BackupArchive.Create(prepared,device,fail,async (_,path,ct)=>await System.IO.File.WriteAllTextAsync(path,"wrong bytes",ct),_=>{});}
            catch(InvalidDataException){failed=true;}
            check(failed && !Directory.GetFiles(fail,"*.zip").Any(),"corrupt download produces no verified archive or cleanup authorization");
            string cancelled=Path.Combine(home,"cancelled");using(var cancel=new CancellationTokenSource())
            {
                cancel.Cancel();bool stopped=false;
                try{await BackupArchive.Create(prepared,device,cancelled,Download,_=>{},cancel.Token);}catch(OperationCanceledException){stopped=true;}
                check(stopped && !Directory.GetFiles(cancelled,"*.zip").Any(),"cancelled backup does not reach compression or cleanup");
            }
            using(var zip=ZipFile.Open(result.Archive,ZipArchiveMode.Update))
            {zip.GetEntry("files/BOOT-original.img")!.Delete();using var stream=zip.CreateEntry("files/BOOT-original.img").Open();stream.Write(new byte[]{1});}
            refused(()=>BackupArchive.VerifyArchive(result.Archive,inventory),"archive readback detects corrupted compressed backup bytes");
            var bundled=new UpgradeOptions("",BundleSha256:new string('a',64));
            JsonElement Agent(string version,string revision)=>JsonSerializer.SerializeToElement(new{agent_version=version,agent_revision=revision});
            check(AutomaticUpgrade.NeedsBundledMaintenance(Agent("1.2.3",""),bundled,new string('a',64)),"bundled same-version rebuild updates an agent lacking revision metadata");
            check(!AutomaticUpgrade.NeedsBundledMaintenance(Agent("1.2.3",BuildIdentity.DisplayVersion.Split("-").Last()),bundled,new string('a',64)),"matching build revision does not repeat maintenance");
            check(!AutomaticUpgrade.NeedsBundledMaintenance(Agent("1.2.3","r"+(int.Parse(BuildIdentity.DisplayVersion.Split('-').Last()[1..])+1)),bundled,new string('a',64)) && !AutomaticUpgrade.NeedsBundledMaintenance(Agent("1.2.4",""),bundled,new string('a',64)),"bundled maintenance never downgrades a newer revision or agent version");
            check(!AutomaticUpgrade.NeedsBundledMaintenance(Agent("1.2.3",""),bundled,new string('b',64)),"arbitrary selected bundles do not inherit the embedded revision policy");
            check(Commands.Build("storage",["cleanup","--plan-id",new string('a',64)],true,true).Contains("'cleanup'"),"storage cleanup uses the authenticated public CLI and approval flag");
            refused(()=>Commands.Build("storage",["delete","--path","/"],true,true),"arbitrary remote deletion is not exposed");
        }
        finally{Directory.Delete(home,true);}
    }
}
