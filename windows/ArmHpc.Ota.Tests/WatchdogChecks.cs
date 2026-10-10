// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public static class WatchdogChecks
{
    public static async Task Run(Action<bool,string> check,Action<Action,string> refused)
    {
        var frame=new StringBuilder("banner\n"+SerialFrames.Prefix+"{\"state\":\"ack\",\"offset\":12}");
        check(SerialFrames.Take(frame) is null,"stream waits for a complete framed response");
        frame.Append('\n');check(SerialFrames.Take(frame)?.GetProperty("offset").GetInt64()==12,"fragmented stream frame decoded");
        refused(()=>SerialFrames.CheckOffset(JsonSerializer.SerializeToElement(new{state="ack",offset=13}),12,"ack"),"incorrect serial resume ACK refused");
        byte[] data=Enumerable.Range(0,28000).Select(i=>(byte)(i%251)).ToArray();string file=Path.GetTempFileName();File.WriteAllBytes(file,data);
        string digest=Convert.ToHexStringLower(SHA256.HashData(data));
        try
        {
            using var wire=new StreamWire(data,digest,1234);using var session=new ConsoleSession(wire);
            await session.StreamFile("fixture-receiver",file,data.Length,digest,_=>{},CancellationToken.None);
            check(wire.Result.SequenceEqual(data) && wire.Chunks==3,"serial large file resumes durable offset and verifies full SHA256");
            using var bad=new StreamWire(data,digest,0){WrongOffset=true};using var badSession=new ConsoleSession(bad);
            bool error=false;try{await badSession.StreamFile("fixture-receiver",file,data.Length,digest,_=>{},CancellationToken.None);}catch(InvalidOperationException){error=true;}
            check(error && bad.Paused,"serial wrong ACK pauses receiver and never declares success");
        }finally{File.Delete(file);}
        var targets=new[]{new Device{DeviceId="one"},new Device{DeviceId="two"}};
        foreach(string command in new[]{"armhpc-rescue watchdog test --test-id "+Guid.NewGuid()+" --checked-sata-power", "armhpc ota boot apply --request-id "+Guid.NewGuid()})
        {
            var request=ArmHpcCommands.Parse(command);bool rejected=false;
            try{await CommandBatch.Run(targets,request,new(2,true),_=>throw new Exception("Must not submit"));}catch(ArgumentException){rejected=true;}
            check(rejected,"fault/BOOT operations cannot be batched or ignore unknown submission");
        }
        check(Commands.Build("boot",["status"],false).Contains("'status'"),"BOOT maintenance uses the public OTA protocol");
        refused(()=>PrivateBootExport.Destination(Path.GetTempPath(),"../system.img"),"private export rejects non-BOOT filenames");
    }
    sealed class StreamWire(byte[] data,string digest,long start):IConsoleWire
    {
        readonly StringBuilder response=new();readonly MemoryStream received=new(data.Take((int)start).ToArray());
        byte[] result=data.Take((int)start).ToArray();public byte[] Result=>result;public int Chunks;public bool WrongOffset,Paused;
        void Reply(object frame)=>response.Append(SerialFrames.Prefix+JsonSerializer.Serialize(frame)+"\n");
        public string Read(){int n=Math.Min(101,response.Length);string value=response.ToString(0,n);response.Remove(0,n);return value;}
        public void Write(string command)
        {
            if(command.StartsWith("fixture-receiver")){Reply(new{state="ready",offset=start,size=data.Length,sha256=digest});return;}
            using var doc=JsonDocument.Parse(command);var f=doc.RootElement;
            switch(Protocol.Text(f,"operation"))
            {
                case "chunk":
                    if(f.GetProperty("offset").GetInt64()!=result.Length)throw new InvalidOperationException();
                    byte[] bytes=Convert.FromBase64String(Protocol.Text(f,"data"));
                    if(Convert.ToHexStringLower(SHA256.HashData(bytes))!=Protocol.Text(f,"sha256"))throw new InvalidOperationException();
                    result=[..result,..bytes];Chunks++;Reply(new{state="ack",offset=result.Length+(WrongOffset?1:0)});break;
                case "finish":Reply(new{state="verified",offset=result.Length,sha256=Convert.ToHexStringLower(SHA256.HashData(result))});break;
                case "cancel":Paused=true;break;
            }
        }
        public void Dispose(){received.Dispose();}
    }
}
