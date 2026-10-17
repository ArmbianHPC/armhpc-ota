# 签名与发行

[English](RELEASES.md)

Release 标题固定为标签本身，采用 `vA.B.C-rN`，例如 `v1.2.3-r10`。英文更新说明位于 `docs/releases/<tag>.md`，简体中文版位于 `<tag>.zh-CN.md`。GitHub 正文使用简短英文说明，并链接中文版。

手动上传的附件固定为 Windows MSI、Linux 上位机 CLI tar.gz 和签名 maintenance tar.xz 三项。许可证、依赖记录、使用说明和对应源码材料放在包内；构建记录及校验值保存在本地。GitHub 的 Source code 链接由平台生成。

`tools/build-msi.py` 构建 Windows 安装包；`tools/build-linux-cli.py` 构建 Linux 上位机；`tools/package-runtime.py` 生成设备运行时。签名接口使用 `python -m armhpc_ota.lan_publish tools --help`。

Linux 上位机构建要求源码已提交且工作区干净，`--source-ref` 必须解析到当前 HEAD；构建旧版本时先检出对应 ref。
构建器从固定 commit 导出一次源码，两种架构均从该快照编译，并将同一源码归档放入发行包。
`BUILD-INFO.json` 记录 commit 和源码归档 SHA256；已跟踪或未跟踪源码存在变更时，在编译前拒绝构建。

```sh
python tools/release-policy.py --tag v1.0.0 --directory /path/to/packages
python tools/release-policy.py --tag v1.0.0 --directory /path/to/packages --apply
```

发布策略默认预览，校验三个附件后再删除额外附件。未指定 `--notes` 时使用仓库中的对应英文更新说明。同名附件字节不同会拒绝发布，需要使用新版本。

维护包包含 `manifest.json` 和 `runtime.tar.xz`，使用设备已信任的公钥验证签名，并检查哈希、型号、架构、布局及文件目标。普通系统发起后先进入 Rescue，再维护普通系统与 Rescue A/B 可写层；中断后继续原任务，备份支持回滚。

软件版本、系统 release ID、递增序号、引导 ABI、Guardian 协议及 JSON `protocol: 1` 分别管理。软件维护不改写已发布的系统载荷和签名清单。密钥、凭据、设备备份及固件二进制保存在源码仓库外。


## 版本编号

采用 `vA.B.C-rN`，`r` 为小写，修订号为正整数。两个仓库各自管理版本：基础版本每次递增一个修订版本，或递增一个次版本并将修订版本归零，或递增一个主版本并将次版本和修订版本归零。例如 `1.2.3` 可进入 `1.2.4`、`1.3.0` 或 `2.0.0`。同一基础版本下修订号递增，允许直接发布 `r1`、`r3`、`r9`。已有不带修订号的数字版本继续兼容。

Release 标题与 tag 一致，附件文件名包含修订号。兼容性仍按数字基础版本、明确能力和签名清单要求校验；固件签名序号独立递增。正式发布前先检查本仓库已公开版本顺序，再执行上传或元数据修改。同名已发布文件保持原字节。
