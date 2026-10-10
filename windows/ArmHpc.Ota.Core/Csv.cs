// SPDX-License-Identifier: GPL-3.0-only
using System.Net;
using System.Net.Sockets;
using System.Text;
namespace ArmHpc.Ota.Core;
public static class Csv
{
    public static string Export(IEnumerable<Device> devices)
    {
        static string Q(string v)=>"\""+v.Replace("\"","\"\"")+"\"";
        var all=devices.ToArray();bool extended=all.Any(d=>d.Transport=="serial"),host=all.Any(d=>d.Hostname.Length>0);
        string header=(extended?"Transport,Address,Port,BaudRate,Name":"Address,Port,Name")+(host?",Hostname":"");
        return header+"\r\n"+string.Join("\r\n",all.Select(d=>(extended?$"{Q(d.Transport)},{Q(d.Address)},{d.Port},{d.BaudRate},{Q(d.Name)}":$"{Q(d.Address)},{d.Port},{Q(d.Name)}")+(host?","+Q(d.Hostname):"")))+"\r\n";
    }
    public static IReadOnlyList<Device> Import(string text)
    {
        var lines=text.Replace("\r\n","\n").Split('\n',StringSplitOptions.RemoveEmptyEntries);if(lines.Length==0)throw new ArgumentException("CSV is empty.");
        string header=lines[0].TrimStart('\uFEFF');bool host=header.EndsWith(",Hostname",StringComparison.Ordinal);if(host)header=header[..^9];
        bool extended=header=="Transport,Address,Port,BaudRate,Name";
        if(!extended && header!="Address,Port,Name")throw new ArgumentException("CSV 表头不匹配；不接受凭据列。");
        var result=new List<Device>();
        foreach(string line in lines.Skip(1))
        {
            var columns=new List<string>();var field=new StringBuilder();bool quoted=false;
            for(int i=0;i<line.Length;i++)
            {
                char c=line[i];if(c=='"'){if(quoted && i+1<line.Length && line[i+1]=='"'){field.Append('"');i++;}else quoted=!quoted;}
                else if(c==',' && !quoted){columns.Add(field.ToString());field.Clear();}else field.Append(c);
            }
            columns.Add(field.ToString());if(quoted || columns.Count!=(extended?5:3)+(host?1:0))throw new ArgumentException("无效 CSV 设备行。");
            string transport=extended?columns[0]:"ssh",address=columns[extended?1:0],name=columns[extended?4:2];
            if(!int.TryParse(columns[extended?2:1],out int port) || port is <1 or >65535)throw new ArgumentException("无效端口。");
            int baud=115200;if(extended && (!int.TryParse(columns[3],out baud) || baud<1200 || baud>3000000))throw new ArgumentException("无效串口速率。");
            if(transport=="ssh"){if(!IPAddress.TryParse(address,out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork)throw new ArgumentException("无效 IPv4 地址。");address=ip.ToString();}
            else if(transport!="serial" || !System.Text.RegularExpressions.Regex.IsMatch(address,"^COM[1-9][0-9]*$",System.Text.RegularExpressions.RegexOptions.IgnoreCase))throw new ArgumentException("无效串口地址。");
            string hostname=host?columns[^1]:"";if(hostname.Length>253 || hostname.Any(char.IsControl))throw new ArgumentException("无效主机名。");
            result.Add(new Device{Address=address,Port=port,Transport=transport,BaudRate=baud,Name=name,Hostname=hostname});
        }
        return result;
    }
}
