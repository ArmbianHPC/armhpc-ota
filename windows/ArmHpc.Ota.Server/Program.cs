// SPDX-License-Identifier: GPL-3.0-only
using System.IO.Pipes;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Net.Http.Headers;

string configPath = Path.GetFullPath(args.SkipWhile(x => x != "--config").Skip(1).FirstOrDefault() ?? throw new ArgumentException("--config is required"));
string pipeName = "ARMHPC.OTA.Publish." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(configPath)))[..16];
if (args.Contains("--stop") || args.Contains("--status"))
{
    using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    await pipe.ConnectAsync(3000);
    using var writer = new StreamWriter(pipe, leaveOpen:true) { AutoFlush = true };
    using var reader = new StreamReader(pipe, leaveOpen:true);
    await writer.WriteLineAsync(args.Contains("--stop") ? "stop" : "status");
    Console.WriteLine(await reader.ReadLineAsync()); return;
}
var cfg = JsonSerializer.Deserialize<Settings>(File.ReadAllText(configPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
IPAddress bind = IPAddress.Parse(cfg.Bind);
byte[] octets = bind.GetAddressBytes();
bool privateIp = octets.Length == 4 && (octets[0] == 10 || (octets[0] == 172 && octets[1] is >= 16 and <= 31) || (octets[0] == 192 && octets[1] == 168));
if (!privateIp && !(cfg.TestLoopback && IPAddress.IsLoopback(bind))) throw new ArgumentException("Choose a concrete RFC1918 IPv4 interface");
string root = Path.GetFullPath(cfg.Root).TrimEnd(Path.DirectorySeparatorChar);
if (!Directory.Exists(root) || cfg.Port is < 1 or > 65535) throw new ArgumentException("Invalid root/port");
X509Certificate2? certificate = null;
if (cfg.Https)
{
    string password = cfg.ProtectedPassword is { Length: > 0 }
        ? Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(cfg.ProtectedPassword), null, DataProtectionScope.CurrentUser)) : "";
    certificate = X509CertificateLoader.LoadPkcs12FromFile(cfg.Certificate!, password, X509KeyStorageFlags.UserKeySet);
    if (!certificate.MatchesHostname(cfg.Bind, allowWildcards:false, allowCommonName:false) || !certificate.HasPrivateKey || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow)
        throw new ArgumentException("HTTPS certificate is invalid or lacks its private key");
    // Hostname/SAN verification is also mandatory in each device's TLS client.
}
var builder = WebApplication.CreateBuilder(args: []);
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(k => k.Listen(bind, cfg.Port, o => { if (cfg.Https) o.UseHttps(certificate!); }));
var app = builder.Build();
string log = configPath + ".requests.jsonl";
object logLock = new(); long bytesSent = 0, requests = 0;
app.MapMethods("/{**path}", ["GET", "HEAD"], async context =>
{
    string relative = context.Request.Path.Value?.TrimStart('/') ?? "";
    long count = 0;
    var original = context.Response.Body;
    var counting = new CountingStream(original, n => { count += n; Interlocked.Add(ref bytesSent, n); });
    context.Response.Body = counting;
    try
    {
        if (relative.Length == 0 || relative.Contains('\\') || relative.Split('/').Any(p => p is "" or "." or "..")) { context.Response.StatusCode=404; return; }
        bool allowedName = relative == "ota-index.json" || System.Text.RegularExpressions.Regex.IsMatch(relative, @"^blobs/[0-9a-f]{64}$|^releases/[A-Za-z0-9._-]+/manifest\.json$|^tools/[0-9.]+/maintenance\.tar\.xz$");
        if (!allowedName) { context.Response.StatusCode=404; return; }
        using var catalog = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "server-catalog.json")));
        if (!catalog.RootElement.GetProperty("files").TryGetProperty(relative, out var descriptor)) { context.Response.StatusCode=404; return; }
        string path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) { context.Response.StatusCode=404; return; }
        for (string? p=path; p is not null && p.Length>=root.Length; p=Path.GetDirectoryName(p))
            if ((File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) { context.Response.StatusCode=403; return; }
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 1024*1024, true);
        string expected = descriptor.GetProperty("sha256").GetString()!;
        string actual = Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
        if (stream.Length != descriptor.GetProperty("size").GetInt64() || actual != expected)
        { await stream.DisposeAsync(); context.Response.StatusCode=503; return; }
        stream.Position=0;
        await Results.File(stream, "application/octet-stream", enableRangeProcessing:true,
            entityTag:new EntityTagHeaderValue('"'+expected+'"')).ExecuteAsync(context);
    }
    catch (FileNotFoundException) { if (!context.Response.HasStarted) context.Response.StatusCode=404; }
    catch (DirectoryNotFoundException) { if (!context.Response.HasStarted) context.Response.StatusCode=404; }
    catch (OperationCanceledException) { }
    finally
    {
        context.Response.Body=original; Interlocked.Increment(ref requests);
        lock (logLock) File.AppendAllText(log, JsonSerializer.Serialize(new { time=DateTimeOffset.UtcNow, path=relative,
            status=context.Response.StatusCode, bytes=count, method=context.Request.Method }) + Environment.NewLine);
    }
});
app.MapFallback(context => { context.Response.StatusCode=404; return Task.CompletedTask; });
_ = Task.Run(async () =>
{
    while (!app.Lifetime.ApplicationStopping.IsCancellationRequested)
    {
        try
        {
            using var pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.WaitForConnectionAsync(app.Lifetime.ApplicationStopping);
            using var reader = new StreamReader(pipe, leaveOpen:true);
            using var writer = new StreamWriter(pipe, leaveOpen:true) { AutoFlush=true };
            string? command = await reader.ReadLineAsync();
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { running=true, pid=Environment.ProcessId, bind=cfg.Bind,
                port=cfg.Port, https=cfg.Https, root, requests=Interlocked.Read(ref requests), bytes=Interlocked.Read(ref bytesSent), log }));
            if (command=="stop") app.Lifetime.StopApplication();
        }
        catch (OperationCanceledException) { break; }
        catch (IOException) { }
    }
});
try { await app.RunAsync(); } finally { certificate?.Dispose(); }

sealed record Settings(string Root, string Bind, int Port=8080, bool Https=false, string? Certificate=null, string? ProtectedPassword=null, bool TestLoopback=false);
sealed class CountingStream(Stream inner, Action<int> count) : Stream
{
    public override bool CanRead=>false; public override bool CanSeek=>false; public override bool CanWrite=>true;
    public override long Length=>throw new NotSupportedException(); public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
    public override void Flush()=>inner.Flush(); public override Task FlushAsync(CancellationToken token)=>inner.FlushAsync(token);
    public override void Write(byte[] buffer,int offset,int length) { inner.Write(buffer,offset,length);count(length); }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,CancellationToken token=default) {await inner.WriteAsync(buffer,token);count(buffer.Length);}
    public override async Task WriteAsync(byte[] buffer,int offset,int length,CancellationToken token) {await inner.WriteAsync(buffer,offset,length,token);count(length);}
    public override int Read(byte[] b,int o,int n)=>throw new NotSupportedException(); public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException(); public override void SetLength(long n)=>throw new NotSupportedException();
}
