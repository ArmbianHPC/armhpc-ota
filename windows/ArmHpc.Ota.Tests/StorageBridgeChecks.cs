// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using ArmHpc.Ota.Core;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

public static class StorageBridgeChecks
{
    public static void Run(Action<bool,string> check,Action<Action,string> refused)
    {
        JsonElement Space(long free,long inodes=100)=>JsonSerializer.SerializeToElement(new{upload_space=new{
            tmp=new{path="/tmp",free_bytes=free,free_inodes=inodes},shared=new{path="/var/lib/armhpc/ota",free_bytes=free,free_inodes=inodes}}});
        refused(()=>SshRunner.RequireUploadSpace(Space(0),262144,true),"full shared storage refuses maintenance before the first upload byte");
        refused(()=>SshRunner.RequireUploadSpace(Space(1024*1024*1024,0),262144,true),"legacy upload preflight also checks inode availability");
        SshRunner.RequireUploadSpace(Space(1024*1024*1024),262144,true);check(true,"legacy maintenance remains available when capacity is sufficient");
        var error=SshRunner.SftpUploadFailure(new SftpException(StatusCode.Failure,"Failure"),"上传文件","/tmp/upload");
        check(error.Message.Contains("上传文件") && error.Message.Contains("/tmp/upload") && error.Message.Contains("inode"),"generic SFTP Failure includes the operation path and filesystem diagnostic");
        check(SshRunner.BackupStorageVerifier.Contains("verify(signed,c.trust)") && SshRunner.BackupStorageVerifier.Contains("hashlib.sha256(runtime)") &&
              SshRunner.BackupStorageVerifier.Contains("d['device_id']==request.get('device_id')"),"memory backup helper requires signed runtime adapter and device verification");
    }
}
