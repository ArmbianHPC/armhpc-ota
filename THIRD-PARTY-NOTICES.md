# 许可与第三方组件

OTA 原创 Python、C、C#、构建工具与文档采用 GPL-3.0-only，全文见 LICENSE。对应源码包含构建及安装脚本。

框架共用的原创组件采用 `GPL-2.0-only OR GPL-3.0-only`，组合到本程序时使用 GPLv3 选项。运行时包与源码附件提供这些组件的精确源码和来源 commit。

| 组件 | 许可 | 来源 |
| --- | --- | --- |
| Python | PSF 及附属组件原许可 | https://www.python.org/psf/license/ |
| cryptography | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| OpenSSL | Apache-2.0 | https://github.com/openssl/openssl |
| cffi / libffi | MIT | https://github.com/python-cffi/cffi / https://github.com/libffi/libffi |
| pycparser | BSD-3-Clause | https://github.com/eliben/pycparser |
| python-zstandard / zstd | BSD-3-Clause 等原许可 | https://github.com/indygreg/python-zstandard / https://github.com/facebook/zstd |
| SSH.NET | MIT | https://github.com/sshnet/SSH.NET |
| BouncyCastle | MIT | https://github.com/bcgit/bc-csharp |
| .NET / WPF / ASP.NET Core / System.IO.Ports / ProtectedData | MIT 及附属组件原许可 | https://github.com/dotnet/runtime / https://github.com/dotnet/wpf / https://github.com/dotnet/aspnetcore |
| Paramiko | LGPL-2.1-or-later | https://github.com/paramiko/paramiko，开发依赖 |
| Linux / Debian 工具 | 各自原许可 | 由设备发行版安装，按其 copyright/source 记录 |

Windows 便携包携带完整许可材料与精确依赖清单，不能将附属或传递组件全部改标为 MIT/GPL。Python TLS 库和 cryptography 的 OpenSSL 实现可能使用不同版本，分别登记。

包不包含 MiniLoader、系统 IMG、永久引导二进制、用户备份或上游 K3s 二进制。设备端调用发行版工具，运行时对用户配置、数据、K3s 版本及原任务绑定的保护不改变。
