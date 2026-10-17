// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
namespace ArmHpc.Ota.Windows;

public static class ApplicationVersion
{
    public static string Number { get; } = ArmHpc.Ota.Core.BuildIdentity.DisplayVersion;
    public static string WindowTitle => $"ARMHPC OTA {Number} · 批量管理与命令";
    public static string HeaderText => $"{Number}   ·   SSH / USB 串口   ·   并发 1–8";
}
