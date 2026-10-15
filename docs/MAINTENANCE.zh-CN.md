# 仓库维护

[English](MAINTENANCE.md)

本仓库遵循[组织维护流程](https://github.com/ArmbianHPC/.github/blob/main/GOVERNANCE.zh-CN.md)。目前维护者为 `chens32`，PR 必需检查通过并解决讨论，审批人数为 0，不要求 Code Owner 审批。

## CI

`CI` 在 PR、`main` 推送和手动触发时运行。Python 3.11 使用固定 CI 依赖执行既有检查，并核对源码许可及 JSON／YAML。Windows 核心／WPF 检查和 Linux x64／ARM64 CLI 构建使用 global.json 固定的 SDK。

`.github/companion-source.json` 固定配套公开源码提交，更新时同步修改工作流 ref 并检查兼容。第三方 Actions 固定完整提交；Dependabot 按周提交分组更新，由维护者合并。CodeQL 单独运行并上传扫描结果。

PR 使用 GitHub 托管 runner、只读源码权限，不接触发行／设备凭据或实际节点。编译和模拟结果不改变硬件验收；带权限的 `pull_request_target` 工作流不得检出外部 PR 代码。

## 构建与发布

完整镜像组装和签名在受控构建环境执行，记录源码提交及明确的板卡输入。公开 PR CI 不接触签名私钥、用户备份和厂商专有 loader。按[构建说明](BUILD.md)和现有发布规则操作。

记录哈希、源码提交、依赖／许可和初始化配置。全新镜像使用公开初始登录 `root` / `1`，发布前移除本地凭据及 SSH 私钥，并覆盖嵌套恢复模板。已有设备身份／配置保留与全新镜像初始化分别处理。

先创建草稿，上传完整约定附件，核对远端大小与 SHA256，再以版本号标题及双语说明发布。二进制修正使用新版本，已发布文件和 tag 保持不变。未来来源／再分发核查和完整草稿就绪后可启用不可变发行。

Owner 紧急调整仓库规则后应恢复并记录。只有一名维护者时，不设置需要第二人完成的审批或环境审阅。
