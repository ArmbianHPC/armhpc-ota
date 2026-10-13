// SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net.Sockets;
using Renci.SshNet;
using Renci.SshNet.Common;
namespace ArmHpc.Ota.Core;

public sealed partial class SshRunner
{
    // SSH.NET accepts chmod-style octal digits, not POSIX bit masks.
    public const short UploadDirectoryMode=700;
    public const short UploadFileMode=600;

    public const string MaintenanceIdentityCode="import json,subprocess;from pathlib import Path;p=Path('/var/lib/armhpc/ota');assert subprocess.check_output(['findmnt','-n','-o','FSTYPE,LABEL','--mountpoint',str(p)],text=True).split()==['ext4','OTA_SHARED'];d=json.loads((p/'identity.json').read_text());t=p/'maintenance/task.json';j=json.loads(t.read_text()) if t.is_file() else None;print(json.dumps({'protocol':1,'ok':True,'data':{'device_id':d['device_id'],'mode':'rescue' if Path('/etc/armhpc/rescue-environment').is_file() else 'system','maintenance':{k:j[k] for k in ('task_id','version','stage','completed','error') if k in j} if j else None}}))";
    public const string MaintenanceVerifier="""
import sys,tarfile,hashlib,json,subprocess,os,shutil
from pathlib import Path,PurePosixPath
sys.path.insert(0,"/usr/lib/armhpc-ota")
from types import SimpleNamespace
from armhpc_ota.metadata import verify
c=SimpleNamespace(state=Path("/var/lib/armhpc/ota"),trust=Path("/etc/armhpc/ota-trust.d")); p=Path(sys.argv[1]); assert p.stat().st_size<268435456,"oversize bundle"
with tarfile.open(p,"r:xz") as t:
 m=t.getmembers(); assert len(m)==2 and {x.name for x in m}=={"manifest.json","runtime.tar.xz"} and all(x.isfile() for x in m),"unsafe bundle"
 assert t.getmember("manifest.json").size<4194304,"oversize manifest"
 raw=t.extractfile("manifest.json").read(); manifest=verify(raw,c.trust)
 assert manifest["kind"]=="tools" and manifest["protocol"]==1 and __import__("re").fullmatch(r"\d+\.\d+\.\d+",manifest["version"]),"wrong maintenance version"
 assert t.getmember("runtime.tar.xz").size==manifest["artifact"]["size"]<268435456,"wrong size"
 runtime=t.extractfile("runtime.tar.xz").read(); assert hashlib.sha256(runtime).hexdigest()==manifest["artifact"]["sha256"],"runtime hash mismatch"
d=c.state/"maintenance"/"imports"/manifest["artifact"]["sha256"]; d.mkdir(parents=True,exist_ok=True,mode=448)
b=d/"bundle.tar.xz"; b.write_bytes(p.read_bytes()); b.chmod(384)
r=d/"runtime.tar.xz"; r.write_bytes(runtime); r.chmod(384)
with tarfile.open(r,"r:xz") as t:
 members=t.getmembers(); assert len(members)<=10000 and sum(x.size for x in members)<268435456,"oversize archive"
 for x in members:
  q=PurePosixPath(x.name); assert not q.is_absolute() and "\\" not in x.name and ".." not in q.parts and (x.isfile() or x.isdir()),"unsafe member"
  target=d.joinpath(*q.parts); assert target.resolve().is_relative_to(d.resolve()) and not target.is_symlink(),"unsafe path"
  if x.isdir():target.mkdir(parents=True,exist_ok=True,mode=448)
  else:
   target.parent.mkdir(parents=True,exist_ok=True,mode=448);target.write_bytes(t.extractfile(x).read());target.chmod(384)
home=next(d.glob("armhpc-ota-*/src")); code="import sys;sys.path.insert(0,"+repr(str(home))+");from armhpc_ota.maintenance import main;raise SystemExit(main())"
result=subprocess.run(["python3","-c",code,"--bundle",str(b),"--request-id",sys.argv[2]],text=True,capture_output=True)
print(result.stdout,end="",flush=True);print(result.stderr,end="",file=sys.stderr,flush=True);sys.exit(result.returncode)
""";

    private static ConnectionInfo Info(Endpoint endpoint,Credentials credentials)
    {
        AuthenticationMethod auth=credentials.PrivateKeyPath is {Length:>0}
            ? new PrivateKeyAuthenticationMethod(credentials.Username,new PrivateKeyFile(credentials.PrivateKeyPath,credentials.Passphrase))
            : new PasswordAuthenticationMethod(credentials.Username,credentials.Password);
        return new ConnectionInfo(endpoint.Address,endpoint.Port,credentials.Username,auth){Timeout=TimeSpan.FromSeconds(8)};
    }
    private static Func<string> Pin(BaseClient client,Device device,string? mode=null)
    {
        string fingerprint="";
        client.HostKeyReceived+=(_,e)=>
        {
            fingerprint="SHA256:"+Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust=device.IgnoreFingerprint || (mode is null
                ? device.HostKeys.Values.Contains(fingerprint,StringComparer.Ordinal)
                : device.HostKeys.TryGetValue(mode,out var pin) && pin==fingerprint);
        };
        return ()=>fingerprint;
    }
    public static void ValidateMaintenanceIdentity(Device device,JsonElement identity,string fingerprint)
    {
        string mode=Protocol.Text(identity,"mode");
        if(Protocol.Text(identity,"device_id")!=device.DeviceId || mode is not ("system" or "rescue"))
            throw new InvalidOperationException("维护设备身份或环境不匹配。");
        if(!device.IgnoreFingerprint && (!device.HostKeys.TryGetValue(mode,out var pin) || pin!=fingerprint))
            throw new InvalidOperationException("当前环境的 SSH 主机密钥未登记或已改变。请单独核查后重新登记。");
    }
    public async Task<string> Upload(Endpoint endpoint,Credentials credentials,Device device,string file,CancellationToken token=default,bool maintenance=false)
    {
        var identity=maintenance ? await MaintenanceStatus(endpoint,credentials,device,token)
            : (await Execute(endpoint,credentials,device,"status",[],cancellation:token)).Data;
        string mode=Protocol.Text(identity,"mode");
        return await Task.Run(()=>
        {
            using var client=new SftpClient(Info(endpoint,credentials));Pin(client,device,mode);client.Connect();
            using var cancellation=token.Register(()=>client.Dispose());
            client.OperationTimeout=TimeSpan.FromSeconds(30);
            return UploadVerifiedFile(client,file,"/tmp/armhpc-ota-upload-"+Guid.NewGuid().ToString("N"),token);
        },token);
    }
    public static string UploadVerifiedFile(SftpClient client,string file,string directory,CancellationToken token=default)
    {
        string stage="准备目录";
        try
        {
            token.ThrowIfCancellationRequested();
            client.CreateDirectory(directory);client.ChangePermissions(directory,UploadDirectoryMode);
            var folder=client.GetAttributes(directory);
            if(!folder.OwnerCanRead || !folder.OwnerCanWrite || !folder.OwnerCanExecute || folder.GroupCanRead || folder.GroupCanWrite || folder.GroupCanExecute || folder.OthersCanRead || folder.OthersCanWrite || folder.OthersCanExecute)
                throw new InvalidOperationException("远程上传目录权限不是 0700。");
            string destination=directory+"/"+Path.GetFileName(file);stage="上传文件";
            using var input=File.OpenRead(file);string expected=Convert.ToHexStringLower(SHA256.HashData(input));input.Position=0;
            client.UploadFile(input,destination);token.ThrowIfCancellationRequested();
            stage="设置文件权限";client.ChangePermissions(destination,UploadFileMode);
            var attributes=client.GetAttributes(destination);
            if(attributes.Size!=input.Length || !attributes.OwnerCanRead || !attributes.OwnerCanWrite || attributes.OwnerCanExecute || attributes.GroupCanRead || attributes.GroupCanWrite || attributes.GroupCanExecute || attributes.OthersCanRead || attributes.OthersCanWrite || attributes.OthersCanExecute)
                throw new InvalidOperationException("远程上传文件大小或 0600 权限校验失败。");
            stage="校验上传内容";using var remote=client.OpenRead(destination);
            if(Convert.ToHexStringLower(SHA256.HashData(remote))!=expected)throw new InvalidOperationException("SFTP 上传 SHA256 不匹配。");
            token.ThrowIfCancellationRequested();return destination;
        }
        catch(Exception) when(token.IsCancellationRequested){throw new OperationCanceledException(token);}
        catch(Renci.SshNet.Common.SftpPermissionDeniedException error){throw new InvalidOperationException("SFTP "+stage+"被设备拒绝：请核对登录账户权限。",error);}
        catch(ArgumentOutOfRangeException error) when(error.ParamName=="mode"){throw new InvalidOperationException("SFTP "+stage+"的权限参数无效，请使用修复后的控制器版本。",error);}
    }
    public async Task<JsonElement> InstallTools(Endpoint endpoint,Credentials credentials,Device device,string bundle,CancellationToken token=default,string? requestId=null)
    {
        try
        {
        string remote=await Upload(endpoint,credentials,device,bundle,token,true);
        // The installed verifier establishes trust before authenticated package code is loaded.
        string verifier=MaintenanceVerifier;
        return await Task.Run(()=>
        {
            using var client=new SshClient(Info(endpoint,credentials));var fingerprint=Pin(client,device);client.Connect();
            using var cancellation=token.Register(()=>client.Dispose());
            var identity=StableIdentity(client,credentials);
            ValidateMaintenanceIdentity(device,identity,fingerprint());
            string command=(credentials.Username!="root"?"sudo -n -- ":"")+"python3 -c "+Commands.Quote(verifier)+" "+Commands.Quote(remote)+" "+Commands.Quote(requestId??Guid.NewGuid().ToString("D"));
            using var execution=client.CreateCommand(command);execution.CommandTimeout=TimeSpan.FromMinutes(10);
            string output=execution.Execute();
            return DecodeMaintenanceReply(output,execution.Error,execution.ExitStatus);
        },token);
        }
        catch(Exception) when(token.IsCancellationRequested){throw new OperationCanceledException(token);}
        catch(Exception error) when(error is SshConnectionException or SshOperationTimeoutException or SocketException)
        {throw new TransientConnectionException("维护接入连接中断；保留原请求 ID，重连后查询设备任务。",error);}
    }
    public static JsonElement DecodeMaintenanceReply(string output,string error,int? exitStatus)
    {
        string diagnostic=error.Trim();if(diagnostic.Length>1200)diagnostic=diagnostic[^1200..];
        if(!string.IsNullOrWhiteSpace(output))
        {
            var data=Protocol.Decode(output);
            if(exitStatus is not null && exitStatus!=0)
                throw new RemoteRejectedException("maintenance_bootstrap_failed","维护接入退出码 "+exitStatus+"。"+(diagnostic.Length>0?diagnostic:"设备返回了非成功退出状态。"));
            return data;
        }
        if(exitStatus is null || exitStatus==0)
            throw new TransientConnectionException("维护接入结果未知：未收到 CLI JSON；保留原请求 ID 并查询设备状态。"+(diagnostic.Length>0?" "+diagnostic:""));
        throw new RemoteRejectedException("maintenance_bootstrap_failed","维护接入退出码 "+exitStatus+"："+(diagnostic.Length>0?diagnostic:"设备没有返回 stdout 或 stderr；请查询原维护任务。"));
    }
    private static JsonElement StableIdentity(SshClient client,Credentials credentials)
    {
        string code=MaintenanceIdentityCode;
        using var cmd=client.CreateCommand((credentials.Username!="root"?"sudo -n -- ":"")+"python3 -c "+Commands.Quote(code));
        cmd.CommandTimeout=TimeSpan.FromSeconds(20);return Protocol.Decode(cmd.Execute());
    }
    public Task<JsonElement> MaintenanceStatus(Endpoint endpoint,Credentials credentials,Device device,CancellationToken token=default,bool rollback=false)
        => Task.Run(()=>
        {
            using var client=new SshClient(Info(endpoint,credentials));var fingerprint=Pin(client,device);client.Connect();var identity=StableIdentity(client,credentials);
            ValidateMaintenanceIdentity(device,identity,fingerprint());
            if(!rollback)return identity;
            using var cmd=client.CreateCommand((credentials.Username!="root"?"sudo -n -- ":"")+"python3 /var/lib/armhpc/ota/maintenance/runner.py --rollback");
            cmd.CommandTimeout=TimeSpan.FromMinutes(3);return Protocol.Decode(cmd.Execute());
        },token);

}
