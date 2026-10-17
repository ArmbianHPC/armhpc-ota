// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Text;
using System.Text.Json;
using Renci.SshNet;

namespace ArmHpc.Ota.Core;

public sealed class BackupStorageSession(ConnectionRouter router,Device device,Credentials credentials,string? bundle,Action<string>? progress=null)
{
    readonly string session=Guid.NewGuid().ToString("D");
    bool announced;
    public Task<JsonElement> Command(string[] arguments,bool yes=false,CancellationToken token=default)
    {
        if(device.Transport=="ssh" && bundle is not null && File.Exists(bundle))
        {
            if(!announced){progress?.Invoke("通过 SSH 准备备份与空间管理；无需预先安装新维护工具。");announced=true;}
            return router.BackupStorageBridge(new(device.Address,device.Port),credentials,device,bundle,session,arguments,yes,token);
        }
        return Native();
        async Task<JsonElement> Native()=> (await router.Execute(new(device.Address,device.Port),credentials,device,"storage",arguments,yes,cancellation:token)).Data;
    }
}

public sealed partial class SshRunner
{
    public const string BackupStorageVerifier="""
import sys,json,base64,hashlib,io,tarfile,types
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,'/usr/lib/armhpc-ota')
def execute():
 from armhpc_ota.config import Config
 from armhpc_ota.engine import Engine
 from armhpc_ota.metadata import verify
 from armhpc_ota.errors import require
 raw=sys.stdin.buffer.read(8388609)
 require(len(raw)<=8388608,'storage_limit','Backup request exceeds its limit')
 request=json.loads(raw);bundle=base64.b64decode(request.pop('bundle'),validate=True)
 c=Config.load();engine=Engine(c)
 require(len(bundle)<=4194304,'storage_limit','Maintenance bundle is too large for the memory bridge')
 with tarfile.open(fileobj=io.BytesIO(bundle),mode='r:xz') as archive:
  members=archive.getmembers()
  require(len(members)==2 and {m.name for m in members}=={'manifest.json','runtime.tar.xz'} and all(m.isfile() for m in members),'tools_archive','Invalid signed maintenance archive')
  require(archive.getmember('manifest.json').size<=1048576,'storage_limit','Maintenance manifest too large')
  signed=archive.extractfile('manifest.json').read();manifest=verify(signed,c.trust)
  require(manifest.get('kind')=='tools' and manifest.get('protocol')==1,'tools_manifest','Not a maintenance bundle')
  require(manifest['artifact']['size']==archive.getmember('runtime.tar.xz').size<=4194304,'storage_limit','Memory bridge runtime exceeds its limit')
  runtime=archive.extractfile('runtime.tar.xz').read()
  require(hashlib.sha256(runtime).hexdigest()==manifest['artifact']['sha256'],'tools_hash','Runtime hash differs from signature')
  require(json.loads(signed)['key_id'] in engine.store.control().get('anchor_key_ids',[json.loads(signed)['key_id']]),'anchor_trust','Maintenance key is not pinned')
 from armhpc_ota.device import discover
 d=discover(c);board=c.board()
 require(d['device_id']==request.get('device_id') and d['mode']=='rescue','storage_binding','Connect to the expected Rescue device')
 require(d['board'] in manifest['boards'] and d['architecture'] in manifest['architectures'] and board['layout'] in manifest['layouts'] and board['anchor_abi'] in manifest['anchor_abis'],'tools_compatibility','Maintenance does not match this device')
 with tarfile.open(fileobj=io.BytesIO(runtime),mode='r:xz') as archive:
  prefix='armhpc-ota-'+manifest['version']+'/src/armhpc_ota/'
  for name in ('storage','storage_bridge'):
   try:member=archive.getmember(prefix+name+'.py')
   except KeyError:raise ValueError('Select the r8 or newer maintenance bundle for zero-space backup access')
   require(member.isfile() and member.size<=262144,'tools_layout','Invalid backup helper')
   module=types.ModuleType('armhpc_ota.'+name);module.__package__='armhpc_ota';sys.modules[module.__name__]=module
   setattr(sys.modules['armhpc_ota'],name,module)
   exec(compile(archive.extractfile(member).read(),'<signed '+name+'>','exec'),module.__dict__)
 return sys.modules['armhpc_ota.storage_bridge'].dispatch(engine,request)
try:
 print(json.dumps({'protocol':1,'ok':True,'data':execute()}),flush=True)
except Exception as error:
 print(json.dumps({'protocol':1,'ok':False,'error':{'code':getattr(error,'code','storage_bridge'),'message':str(error)}}),flush=True);sys.exit(2)
""";
    public Task<JsonElement> BackupStorageBridge(Endpoint endpoint,Credentials credentials,Device device,string bundle,string session,
        string[] arguments,bool yes,CancellationToken token)=>Task.Run(async ()=>
    {
        if(new FileInfo(bundle).Length>4*1024*1024)throw new InvalidDataException("内存备份接入需要不超过 4 MiB 的签名维护包。");
        var request=JsonSerializer.SerializeToUtf8Bytes(new{device_id=device.DeviceId,session_id=session,arguments,yes,bundle=File.ReadAllBytes(bundle)});
        using var login=ConnectLogin(endpoint,credentials,device,info=>new SshClient(info),token,requiredMode:"rescue");
        using var cancelled=token.Register(()=>login.Client.Dispose());
        var identity=StableIdentity(login.Client,login.Credentials);ValidateMaintenanceIdentity(device,identity,login.Fingerprint);login.Verified(identity);
        if(Protocol.Text(identity,"mode")!="rescue")throw new InvalidOperationException("请先进入 Rescue。");
        using var command=login.Client.CreateCommand((login.Credentials.Username!="root"?"sudo -n -- ":"")+"python3 -B -c "+Commands.Quote(BackupStorageVerifier));
        command.CommandTimeout=TimeSpan.FromMinutes(30);
        var executing=command.ExecuteAsync(token);
        using(var input=command.CreateInputStream()){await input.WriteAsync(request,token);}
        await executing;
        return DecodeMaintenanceReply(command.Result,command.Error,command.ExitStatus);
    },token);
}
