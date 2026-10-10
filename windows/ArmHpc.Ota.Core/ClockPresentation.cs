// SPDX-License-Identifier: GPL-3.0-only
using System.Globalization;
using System.Text.Json;

namespace ArmHpc.Ota.Core;

public sealed record ClockView(string Caption, string Detail);

public static class ClockPresentation
{
    public static ClockView Describe(JsonElement status, DateTimeOffset received)
    {
        if(!status.TryGetProperty("clock",out var clock) || clock.ValueKind!=JsonValueKind.Object)
            return new("未提供", "旧设备未提供时间质量。电脑接收时间："+received.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        string quality=Protocol.Text(clock,"quality");
        string caption=quality switch {"synchronised"=>"已校准","estimated"=>"估计时间","invalid"=>"时间异常",_=>"未提供"};
        var lines=new List<string>{"时间状态："+caption,"时间来源："+Protocol.Text(clock,"source"),
            "设备 UTC："+Epoch(clock,"epoch"),"最近保存 UTC："+Epoch(clock,"last_saved_epoch"),
            "电脑接收时间："+received.ToString("yyyy-MM-dd HH:mm:ss zzz")};
        if(clock.TryGetProperty("correction",out var correction) && correction.ValueKind==JsonValueKind.Object)
            lines.Add("时钟校正："+Protocol.Text(correction,"direction")+" · "+correction.GetRawText());
        if(status.TryGetProperty("job",out var job) && job.ValueKind==JsonValueKind.Object)
            lines.Add("设备任务耗时："+Duration(job));
        return new(caption,string.Join(Environment.NewLine,lines));
    }

    private static string Epoch(JsonElement clock,string name)
    {
        if(!clock.TryGetProperty(name,out var value) || value.ValueKind!=JsonValueKind.Number || !value.TryGetDouble(out double seconds) || !double.IsFinite(seconds))return "未提供";
        try{return DateTimeOffset.FromUnixTimeMilliseconds(checked((long)(seconds*1000))).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'",CultureInfo.InvariantCulture);}
        catch(Exception error) when(error is ArgumentOutOfRangeException or OverflowException){return "无效时间";}
    }

    public static string Duration(JsonElement job)
    {
        if(!job.TryGetProperty("events",out var input) || input.ValueKind!=JsonValueKind.Array)return "未提供";
        var events=input.EnumerateArray().OrderBy(e=>e.TryGetProperty("sequence",out var s) && s.ValueKind==JsonValueKind.Number && s.TryGetInt64(out var n)?n:long.MaxValue).ToArray();
        if(events.Length<2)return "尚无足够记录";
        var boots=events.Select(e=>Protocol.Text(e,"boot_id")).Distinct().ToArray();
        if(boots.Length==1 && boots[0].Length>0 && Number(events[0],out var first) && Number(events[^1],out var last) && last>=first)
            return Span(last-first)+"（同次启动单调计时）";
        var utc=new List<DateTimeOffset>();
        foreach(var e in events)
        {
            if(!e.TryGetProperty("clock",out var clock) || Protocol.Text(clock,"quality")!="synchronised" || clock.TryGetProperty("correction",out _) ||
               !DateTimeOffset.TryParse(Protocol.Text(e,"time"),CultureInfo.InvariantCulture,DateTimeStyles.None,out var value) || utc.Count>0 && value<utc[^1])
                return "跨启动，无法准确统计";
            utc.Add(value);
        }
        return Span((utc[^1]-utc[0]).TotalSeconds)+"（已校准 UTC）";
    }

    private static bool Number(JsonElement e,out double number)
    {
        number=0;
        return e.TryGetProperty("monotonic_seconds",out var value) && value.ValueKind==JsonValueKind.Number && value.TryGetDouble(out number) && double.IsFinite(number) && number>=0;
    }

    private static string Span(double seconds)=>seconds>=0 && seconds<TimeSpan.MaxValue.TotalSeconds
        ? TimeSpan.FromSeconds(seconds).ToString(seconds>=86400?"d\\.hh\\:mm\\:ss":"hh\\:mm\\:ss",CultureInfo.InvariantCulture):"无法准确统计";
}
