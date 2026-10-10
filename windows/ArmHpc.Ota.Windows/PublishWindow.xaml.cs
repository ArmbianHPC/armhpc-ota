// SPDX-License-Identifier: GPL-3.0-only
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Windows;
using ArmHpc.Ota.Core;
using Microsoft.Win32;
namespace ArmHpc.Ota.Windows;
public partial class PublishWindow : Window
{
 private readonly LanPublisher publisher=new();
 public PublishWindow()
 {
  InitializeComponent();PublishRoot.Text=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ARMHPC","Releases");
  string address=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up).SelectMany(n=>n.GetIPProperties().UnicastAddresses).Select(a=>a.Address).FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetwork && a.ToString().StartsWith("192.168."))?.ToString()??"192.168.100.100";
  BaseUrl.Text="http://"+address+":8080";
  KeyId.Text="local-oect-ota-r10";
  if(File.Exists(publisher.Configuration))
   try {using var j=JsonDocument.Parse(File.ReadAllText(publisher.Configuration));var r=j.RootElement;PublishRoot.Text=r.GetProperty("root").GetString();BaseUrl.Text=(r.GetProperty("https").GetBoolean()?"https":"http")+"://"+r.GetProperty("bind").GetString()+":"+r.GetProperty("port").GetInt32();CertificatePath.Text=r.GetProperty("certificate").GetString();}catch(JsonException){}
 }
 private void Show(object value)=>Output.Text=JsonSerializer.Serialize(value,new JsonSerializerOptions{WriteIndented=true});
 private string[] SigningArgs()=>["--output",PublishRoot.Text,"--key",KeyPath.Text,"--key-id",KeyId.Text];
 private async Task Run(string operation,string[] extra)
 {try{Show(await publisher.Publish(operation,[..SigningArgs(),..extra]));}catch(Exception e){MessageBox.Show(this,e.Message,"发布未完成");}}
 private async void ImportRelease(object s,RoutedEventArgs e)
 {var d=new OpenFileDialog{Filter="框架预构建描述|prepared-release.json|JSON|*.json"};if(d.ShowDialog(this)==true)await Run("import",["--spec",d.FileName,"--base-url",BaseUrl.Text]);}
 private async void ImportTools(object s,RoutedEventArgs e)
 {
  var d=new OpenFileDialog{Title="选择未签名 Linux runtime 包",Filter="构建生成的 Linux runtime|*-linux-runtime.tar.xz|自建运行时归档|*.tar.xz"};
  if(d.ShowDialog(this)!=true)return;
  if(Path.GetFileName(d.FileName).Equals("maintenance.tar.xz",StringComparison.OrdinalIgnoreCase))
  {MessageBox.Show(this,"此文件用于设备维护。请回主窗口点击“自动更新 OTA 工具”或“自动维护并升级”并选择它。现成发布目录填好路径和地址后直接启动服务。","维护包使用入口");return;}
  await Run("tools",["--runtime",d.FileName]);
 }
 private async void RenewIndex(object s,RoutedEventArgs e)=>await Run("index",["--base-url",BaseUrl.Text]);
 private async void StartServer(object s,RoutedEventArgs e)
 {
  try {
   try {Show(await publisher.Control("status"));MessageBox.Show(this,"服务已运行；修改地址或目录前请先停止服务。");return;}catch(IOException){}catch(TimeoutException){}
   var u=new Uri(BaseUrl.Text);if(u.Scheme is not ("http" or "https"))throw new ArgumentException("仅支持 HTTP/HTTPS。");
   if(u.Scheme=="https" && Path.GetFullPath(CertificatePath.Text).StartsWith(Path.GetFullPath(PublishRoot.Text)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("证书私钥不能放在发布目录。");
   publisher.Start(PublishRoot.Text,u.Host,u.Port,u.Scheme=="https",CertificatePath.Text,CertificatePassword.Password);
   await Task.Delay(1200);Show(await publisher.Control("status"));
  } catch(Exception error){MessageBox.Show(this,error.Message,"发布服务启动失败；检查 IP、端口、证书及防火墙。");}
 }
 private async void ServerStatus(object s,RoutedEventArgs e){try{Show(await publisher.Control("status"));}catch(Exception error){Output.Text="未运行："+error.Message;}}
 private async void StopServer(object s,RoutedEventArgs e){try{Show(await publisher.Control("stop"));}catch(Exception error){Output.Text=error.Message;}}
 private void RequestLogs(object s,RoutedEventArgs e){string p=publisher.Configuration+".requests.jsonl";Output.Text=File.Exists(p)?string.Join(Environment.NewLine,File.ReadLines(p).TakeLast(100)):"尚无下载请求。";}
}
