// SPDX-License-Identifier: GPL-3.0-only
using System.Text.Json;
using ArmHpc.Ota.Core;
public static class ClockChecks
{
    public static int Run(Action<bool,string> check)
    {
        int count=0;void C(bool value,string label){check(value,label);count++;}
        JsonElement Read(string value)=>JsonDocument.Parse(value).RootElement.Clone();
        C(ClockPresentation.Describe(Read("{}"),DateTimeOffset.Now).Caption=="未提供","old agent clock is optional");
        foreach(var pair in new[]{("synchronised","已校准"),("estimated","估计时间"),("invalid","时间异常")})
            C(ClockPresentation.Describe(Read("{\"clock\":{\"quality\":\""+pair.Item1+"\"}}"),DateTimeOffset.Now).Caption==pair.Item2,"clock quality "+pair.Item1);
        var view=ClockPresentation.Describe(Read("{\"clock\":{\"quality\":\"estimated\",\"source\":\"restored-shared-time\",\"epoch\":1791570000,\"last_saved_epoch\":1791569000}}"),DateTimeOffset.Now);
        C(view.Detail.Contains("UTC") && view.Detail.Contains("电脑接收时间") && view.Detail.Contains("restored-shared-time"),"device UTC separated from receiver time");
        C(ClockPresentation.Duration(Read("{\"events\":[{\"sequence\":2,\"boot_id\":\"b\",\"monotonic_seconds\":80,\"time\":\"2000-01-01\"},{\"sequence\":1,\"boot_id\":\"b\",\"monotonic_seconds\":20,\"time\":\"2026-10-09\"}]}" )).StartsWith("00:01:00"),"monotonic elapsed ignores wall-clock regression and sorts sequence");
        C(ClockPresentation.Duration(Read("{\"events\":[{\"boot_id\":\"a\",\"monotonic_seconds\":80},{\"boot_id\":\"b\",\"monotonic_seconds\":20}]}"))=="跨启动，无法准确统计","cross boot no negative duration");
        C(ClockPresentation.Duration(Read("{\"events\":[{\"sequence\":1,\"boot_id\":\"a\",\"time\":\"2026-10-09T01:00:00Z\",\"clock\":{\"quality\":\"synchronised\"}},{\"sequence\":2,\"boot_id\":\"b\",\"time\":\"2026-10-09T01:02:00Z\",\"clock\":{\"quality\":\"synchronised\"}}]}" )).StartsWith("00:02:00"),"cross boot calibrated UTC duration");
        C(ClockPresentation.Describe(Read("{\"clock\":{\"epoch\":1e100}}"),DateTimeOffset.Now).Detail.Contains("无效时间"),"malformed epoch does not crash GUI");
        return count;
    }
}
