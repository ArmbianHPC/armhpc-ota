# 签名与软件发行

软件版本为 1.0.0，JSON 协议为 1。系统 release ID、递增序号、引导 ABI 和 Guardian 协议分别管理，不等同于软件版本。

`tools/package-runtime.py` 生成对应源码和 Linux runtime；`python -m armhpc_ota.lan_publish tools --help` 提供签名维护包接口。Windows 使用 `tools/build-release.py` 构建便携软件与发布助手。

维护包外层包含 manifest.json 与 runtime.tar.xz，使用设备已经信任的 Ed25519 公钥校验。包中自带的公钥不能替代设备信任根。版本、板卡、架构、布局、哈希、文件目标及角色均需匹配。

旧设备可经 SSH/SFTP 或串口上传维护包；普通系统发起后先进入 Rescue，同步普通系统及 Rescue A/B 的可写层。原任务 ID、文件哈希和传输进度保留；中断后继续原任务。维护完成前阻止新系统更新，可恢复备份。

软件 Release 提供 Windows ZIP、Linux runtime、签名 maintenance、两个对应源码附件、SHA256、依赖／许可清单和源码 commit。签名密钥、凭据、节点备份和系统 IMG 不进入软件源码包。

系统包是独立输入，旧系统 release、签名清单与载荷不因软件版本改变而重签或覆盖。发布版本不可覆盖，修改内容需使用新的版本或 release ID。
