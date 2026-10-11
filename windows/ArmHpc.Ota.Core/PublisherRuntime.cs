// SPDX-FileCopyrightText: 2026 ARMHPC contributors
// SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;

namespace ArmHpc.Ota.Core;

public static class PublisherRuntime
{
    public static ProcessStartInfo Create()
    {
        string runtime;
        if (OperatingSystem.IsWindows())
        {
            runtime = Path.Combine(AppContext.BaseDirectory, "publisher", "python.exe");
            if (!File.Exists(runtime)) throw new InvalidOperationException("安装目录缺少 Python 发布助手。");
        }
        else
        {
            runtime = Environment.GetEnvironmentVariable("ARMHPC_PYTHON") ?? "python3";
        }
        var result = new ProcessStartInfo(runtime)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        if (!OperatingSystem.IsWindows())
        {
            string library = Path.Combine(AppContext.BaseDirectory, "publisher", "Lib");
            if (!Directory.Exists(Path.Combine(library, "armhpc_ota")))
                throw new InvalidOperationException("安装目录缺少 Python 包解析助手。");
            result.Environment["PYTHONPATH"] = library;
            result.Environment["PYTHONDONTWRITEBYTECODE"] = "1";
        }
        return result;
    }
}
