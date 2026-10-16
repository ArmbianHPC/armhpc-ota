// SPDX-License-Identifier: GPL-3.0-only
using ArmHpc.Ota.Core;
using System.Text.Json;
int checks = 0;
void Check(bool condition, string label) { if (!condition) throw new Exception("FAIL: " + label); checks++; Console.WriteLine("PASS: " + label); }
void Refused(Action operation, string label) { try { operation(); } catch { checks++; Console.WriteLine("PASS: " + label); return; } throw new Exception("FAIL: " + label); }
Check(Scanner.Expand("192.168.200.3/30").SequenceEqual(new[] { "192.168.200.1", "192.168.200.2" }), "explicit CIDR scope");
Check(Scanner.Expand("192.168.200.5/32").Single() == "192.168.200.5", "single address");
Check(Scanner.Expand("192.168.200.4/31").Count == 2, "point-to-point range");
Refused(() => Scanner.Expand("0.0.0.0/0"), "broad scan refused");
Refused(() => Scanner.Expand("::1/128"), "IPv6 scan refused");
string hostile = "r1'; touch /tmp/should-not-exist; echo '";
Check(Commands.Build("plan", ["--release", hostile], true).Contains(Commands.Quote(hostile)), "shell-safe argument quoting");
Refused(() => Commands.Build("_service", [], false), "no GUI-specific service command");
Refused(() => Commands.Build("apply", ["--simulate-root", "/"], false), "fixture parameter forbidden in GUI");
Check(Commands.Build("status", [], false).Contains("armhpc-rescue") && Commands.Build("status", [], false).Contains("armhpc' ota") == false, "same public wrappers");
Check(Protocol.Decode("{\"protocol\":1,\"ok\":true,\"data\":{\"device_id\":\"d1\"}}").GetProperty("device_id").GetString() == "d1", "CLI JSON v1");
Refused(() => Protocol.Decode("{\"protocol\":2,\"ok\":true,\"data\":{}}"), "wrong protocol refused");
Refused(() => Protocol.Decode("{\"protocol\":1,\"ok\":false,\"error\":{\"code\":\"gate\",\"message\":\"blocked\"}}"), "CLI rejection surfaced");
var sample = new Device { Address = "192.168.1.2", Name = "quoted, \"name\"" };
Check(Csv.Import(Csv.Export([sample])).Single().Name == sample.Name, "CSV round trip");
Check(!Csv.Export([sample]).Contains("Password"), "CSV contains no credential fields");
Refused(() => Csv.Import("Address,Password\n192.168.1.2,secret"), "credential CSV refused");
var queue = new BatchQueue(); var order = new System.Collections.Concurrent.ConcurrentQueue<string>();
var devices = Enumerable.Range(0, 6).Select(i => new Device { DeviceId = i.ToString() }).ToArray();
await queue.Run(devices, 4, device => { order.Enqueue(device.DeviceId); return Task.FromResult(false); });
Check(order.SequenceEqual(new[] { "0" }), "failed canary starts no followers");
order.Clear(); queue = new BatchQueue(); int running = 0, maximum = 0;
await queue.Run(devices, 2, async device => { order.Enqueue(device.DeviceId); int active = Interlocked.Increment(ref running); lock(order)maximum = Math.Max(maximum, active); await Task.Delay(40); Interlocked.Decrement(ref running); return true; });
Check(order.First() == "0" && order.Count == 6 && maximum <= 2, "canary first and concurrency bound");
queue = new BatchQueue(); order.Clear();
await queue.Run(devices, 1, device => { order.Enqueue(device.DeviceId); if (device.DeviceId == "1") queue.Stop(); return Task.FromResult(true); });
Check(order.SequenceEqual(new[] { "0", "1" }), "stop keeps started device and skips rest");
string path = Path.Combine(Path.GetTempPath(), "armhpc-vault-" + Guid.NewGuid());
try
{
    var vault = new Vault(path); var credentials = new Credentials("admin", "secret-test-value");
    vault.Save("device-1", credentials);
    Check(vault.Load("device-1") == credentials, "DPAPI credential round trip");
    Check(!File.ReadAllText(Directory.GetFiles(path).Single()).Contains("secret-test-value"), "no plaintext credential on disk");
}
finally { Directory.Delete(path, true); }
var task = new PendingTask("device-1", Guid.NewGuid().ToString("D"), "r2", "all", Ranges: ["192.168.200.0/24"]);
JsonElement StatusFor(PendingTask pending, string stage, string? identity = null, string? jobId = null) =>
    JsonSerializer.SerializeToElement(new { device_id = identity ?? pending.DeviceId,
        job = new { job_id = jobId ?? pending.JobId, stage, progress = new { bytes = 512, total = 1024 } } });
int submissions = 0, reconnects = 0, queries = 0;
bool accepted = false;
var phases = new List<string>();
bool monitored = await JobMonitor.Run(task,
    () => accepted ? Task.FromResult(StatusFor(task, "succeeded")) : throw new RemoteRejectedException("job_missing", "not created"),
    () => { submissions++; accepted = true; throw new TransientConnectionException("lost reply after admission"); },
    () => { reconnects++; return Task.CompletedTask; }, (phase, percent) => phases.Add(phase),
    polls: 5, delay: _ => Task.CompletedTask);
Check(monitored && submissions == 1 && reconnects == 1 && phases.Contains("succeeded"), "lost apply reply is resolved by persistent task ID");
Check(JobMonitor.Progress(StatusFor(task, "downloading").GetProperty("job")) == 50, "CLI byte progress is rendered without a second deployment engine");
submissions = 0;
monitored = await JobMonitor.Run(task, () => Task.FromResult(StatusFor(task, "succeeded")),
    () => { submissions++; return Task.FromResult(JsonSerializer.SerializeToElement(new { job_id = task.JobId })); },
    () => Task.CompletedTask, (_, _) => { }, polls: 2, delay: _ => Task.CompletedTask);
Check(monitored && submissions == 0, "reopened GUI observes an existing task without resubmitting it");
monitored = await JobMonitor.Run(task, () => Task.FromResult(StatusFor(task, "failed-recoverable")),
    () => throw new Exception("must not submit"), () => Task.CompletedTask, (_, _) => { }, polls: 2, delay: _ => Task.CompletedTask);
Check(!monitored, "recoverable device failure pauses followers");
bool mismatched = false;
try { await JobMonitor.Run(task, () => Task.FromResult(StatusFor(task, "succeeded", identity: "another-device")),
    () => throw new Exception("must not submit"), () => Task.CompletedTask, (_, _) => { }, polls: 2, delay: _ => Task.CompletedTask); }
catch (InvalidOperationException) { mismatched = true; }
Check(mismatched, "task observer refuses a different persistent device ID");
bool wrongTask = false;
try { await JobMonitor.Run(task, () => Task.FromResult(StatusFor(task, "succeeded", jobId: Guid.NewGuid().ToString("D"))),
    () => throw new Exception("must not submit"), () => Task.CompletedTask, (_, _) => { }, polls: 2, delay: _ => Task.CompletedTask); }
catch (InvalidOperationException) { wrongTask = true; }
Check(wrongTask, "task observer refuses a different remote task ID");
bool refused = false;
try { await JobMonitor.Run(task, () => throw new RemoteRejectedException("hardware_gate", "physical acceptance missing"),
    () => throw new Exception("must not submit"), () => Task.CompletedTask, (_, _) => { }, polls: 2, delay: _ => Task.CompletedTask); }
catch (RemoteRejectedException error) { refused = error.Code == "hardware_gate"; }
Check(refused, "hardware rejection is not retried as a network failure");
using (var cancelled = new CancellationTokenSource())
{
    cancelled.Cancel(); queries = 0;
    bool stopped = false;
    try { await JobMonitor.Run(task, () => { queries++; return Task.FromResult(StatusFor(task, "succeeded")); },
        () => throw new Exception("must not submit"), () => Task.CompletedTask, (_, _) => { }, cancelled.Token, 2, _ => Task.CompletedTask); }
    catch (OperationCanceledException) { stopped = true; }
    Check(stopped && queries == 0, "GUI observation cancellation sends no remote cancellation");
}
path = Path.Combine(Path.GetTempPath(), "armhpc-task-vault-" + Guid.NewGuid());
try
{
    var vault = new Vault(path); vault.SaveTasks([task]);
    var restored = vault.LoadTasks().Single();
    Check(restored.JobId == task.JobId && restored.Release == "r2" && restored.Ranges!.Single() == "192.168.200.0/24", "approved task and scan boundary persist across GUI restarts");
    string raw = File.ReadAllText(Path.Combine(path, "tasks.json"));
    Check(!raw.Contains("Password") && !raw.Contains("Passphrase") && !raw.Contains("PrivateKeyPath"), "task records contain no credentials");
}
finally { Directory.Delete(path, true); }
Check(Commands.Build("apply", ["--request-id", task.JobId, "--release", "r2"], true, true).Contains("--request-id"), "same CLI accepts an idempotent request ID");

Check(Commands.Build("source",["set","--url","http://192.168.100.192:8080/ota-index.json","--allow-http"],true,true).Contains("--allow-http"),"explicit LAN source command");
Check(Commands.Build("tools",["update","--bundle","/tmp/tool.tar.xz"],true,true).Contains("'update'"),"same tools CLI");
Refused(()=>Commands.Build("tools",["erase"],true),"unknown maintenance action refused");
Check(Commands.Build("retry",["--job",task.JobId],true,true).Contains(task.JobId),"retry original persistent task");
var visibleDevice=new Device {DeviceId="maintenance-fixture"};
var notifications=new List<string?>();visibleDevice.PropertyChanged+=(_,e)=>notifications.Add(e.PropertyName);
visibleDevice.SystemVersion="r13";visibleDevice.RescueVersion="r13";visibleDevice.RescueSlot="b";
Check(notifications.SequenceEqual(new[]{"SystemVersion","RescueVersion","RescueSlot"}),"live system and Rescue versions notify the bound grid");
visibleDevice.Transport="serial";Check(notifications.Last()=="Transport","connection column updates when moving from SSH to serial");
Check(new MaintenanceTask("fixture",Guid.NewGuid().ToString("D"),[],"refused").Terminal,"rejected maintenance does not resume as an in-flight submission");
visibleDevice.HostKeys["system"]="SHA256:system-fixture";visibleDevice.HostKeys["rescue"]="SHA256:rescue-fixture";
var maintenanceIdentity=JsonDocument.Parse("{\"device_id\":\"maintenance-fixture\",\"mode\":\"rescue\"}").RootElement.Clone();
SshRunner.ValidateMaintenanceIdentity(visibleDevice,maintenanceIdentity,"SHA256:rescue-fixture");
Check(true,"maintenance accepts the pinned key of its reported environment");
Refused(()=>SshRunner.ValidateMaintenanceIdentity(visibleDevice,maintenanceIdentity,"SHA256:system-fixture"),"maintenance cannot substitute the normal-system key for the Rescue key");
Refused(()=>SshRunner.ValidateMaintenanceIdentity(visibleDevice,JsonDocument.Parse("{\"device_id\":\"maintenance-fixture\",\"mode\":\"unknown\"}").RootElement,"SHA256:rescue-fixture"),"maintenance refuses an unknown boot environment");
var sdkAttributes=(Renci.SshNet.Sftp.SftpFileAttributes)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(Renci.SshNet.Sftp.SftpFileAttributes));
Refused(()=>sdkAttributes.SetPermissions(448),"actual SSH.NET rejects the previous POSIX 0700 bit-mask argument");
Refused(()=>sdkAttributes.SetPermissions(384),"actual SSH.NET rejects the previous POSIX 0600 bit-mask argument");
sdkAttributes.SetPermissions(SshRunner.UploadDirectoryMode);
Check(sdkAttributes.OwnerCanRead && sdkAttributes.OwnerCanWrite && sdkAttributes.OwnerCanExecute && !sdkAttributes.GroupCanRead && !sdkAttributes.GroupCanWrite && !sdkAttributes.GroupCanExecute && !sdkAttributes.OthersCanRead && !sdkAttributes.OthersCanWrite && !sdkAttributes.OthersCanExecute,"actual SDK upload-directory mode grants owner-only rwx");
sdkAttributes.SetPermissions(SshRunner.UploadFileMode);
Check(sdkAttributes.OwnerCanRead && sdkAttributes.OwnerCanWrite && !sdkAttributes.OwnerCanExecute && !sdkAttributes.GroupCanRead && !sdkAttributes.GroupCanWrite && !sdkAttributes.GroupCanExecute && !sdkAttributes.OthersCanRead && !sdkAttributes.OthersCanWrite && !sdkAttributes.OthersCanExecute,"actual SDK upload-file mode grants owner-only rw");
await AutomationChecks.Run(Check,Refused);
await FirmwareChecks.Run(Check,Refused);
await ManagementChecks.Run(Check,Refused);
await CommandBatchChecks.Run(Check,Refused);
await RebootChecks.Run(Check,Refused);
await SftpTransportChecks.Run(Check);
ClockChecks.Run(Check);
await WatchdogChecks.Run(Check,Refused);
await SerialAuthenticationChecks.Run(Check);
await SerialRebootChecks.Run(Check);
await TaskFilesChecks.Run(Check,Refused);
await DeviceDiscoveryChecks.Run(Check);
Console.WriteLine($"{checks} checks passed; no physical device writes performed.");
