// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Reflection;
namespace ArmHpc.Ota.Core;
public static class BuildIdentity
{
    public static string CoreVersion => typeof(BuildIdentity).Assembly.GetName().Version!.ToString(3);
    public static string DisplayVersion => typeof(BuildIdentity).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? CoreVersion;
}
