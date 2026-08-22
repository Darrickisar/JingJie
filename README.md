# 净界

净界：面向 KernelSU、KernelSU Next 与 APatch 的低耗电过滤模块，支持 hosts、可选 DoH、规则管理和回滚。

![version](https://img.shields.io/badge/version-V1.0-informational)
![versionCode](https://img.shields.io/badge/versionCode-670-lightgrey)
![managers](https://img.shields.io/badge/KernelSU%20%C2%B7%20KernelSU%20Next%20%C2%B7%20APatch-supported-brightgreen)
![license](https://img.shields.io/badge/license-GPL--3.0--only-blue)
[![Telegram](https://img.shields.io/badge/Telegram-%40JingJie__Group-26A5E4?logo=telegram&logoColor=white)](https://t.me/JingJie_Group)

[English](en/README.md)

> **请从官方链接下载，以防恶意脚本。**
> 为保障网络环境安全，本工具仅支持过滤非法骚扰、恶意代码等违规信息。请正确合理使用工具功能，
> 勿将合法商业广告纳入屏蔽范围。

## 这是什么

净界把 hosts 过滤做成一个**默认只做一件事**的模块：安装后只有 hosts 过滤在工作，加密 DNS、应用策略、
拦截历史与额外日志全部默认关闭。当保护、自动刷新、拦截历史与 DoH 都关闭时，模块保持**零额外工作**
状态，不下载来源，也不启动任何可选后台能力。

界面是一套重新设计的应用式控制台（五个页签：首页 / 规则 / 应用 / 日志 / 设置），运行在模块管理器
内置的 WebUI 里，没有独立 App。

## 功能一览

| | |
| --- | --- |
| **规则来源** | 两个可删除、可恢复的内置来源（秋风规则、10007规则）+ 最多 16 个自定义来源（HTTPS）；分组折叠、单源刷新、来源健康度 |
| **名单** | 手工黑白名单（白名单优先级最高）、精确域名覆写、可选的白名单订阅 |
| **hosts** | `拦截全部广告` / `保留奖励广告` 两种模式，暂停与恢复保护，刷新失败时回退到缓存，按版本回滚 |
| **自动更新** | 默认关闭，可选 6 / 12 / 24 小时 |
| **加密 DNS** | 默认关闭。用户自填 DoH 地址，可选全设备或所选应用；不写入 Android Private DNS |
| **应用策略** | 默认关闭。阻止所选应用联网，或仅允许最近一次规则解析出的地址；不启动 VPN、代理或常驻网络进程 |
| **拦截历史** | 默认关闭。开启后仅记录被拒绝的 TCP 连接起始请求，可按应用 / 域名 / 端口 / 时间筛选 |
| **诊断** | 手动载入的规则日志、三档日志级别、一次性环境检查，均不做后台轮询 |
| **外观** | 经典 / 液态两种材质 × 亮色 / 暗色 / 跟随系统 × 三档玻璃强度，可自由组合 |

完整说明见 **[功能介绍文档](https://github.com/Darrickisar/JingJie/blob/main/docs/features.md)**。

## 安装

1. 从 [Releases](https://github.com/Darrickisar/JingJie/releases) 下载
   [`JingJie-V1.0.zip`](https://github.com/Darrickisar/JingJie/releases/download/v1.0/JingJie-V1.0.zip)。
2. 在 KernelSU、KernelSU Next 或 APatch 管理器中使用**“从本地安装”**选择该 ZIP。
3. 按管理器提示重启设备。
4. 从模块卡片的**“打开”**进入净界控制台。首次进入会显示使用说明，确认后模块才会自动刷新已启用的来源。

安装过程不联网；第一次联网发生在你确认使用说明之后。

> **不要在第三方 Recovery 中刷入。** 本包只按受支持管理器的本地 ZIP 安装入口设计，Recovery 刷机
> 流程未经验证。

模块内更新走 `module.prop` 的 `updateJson`（[`update.json`](https://github.com/Darrickisar/JingJie/blob/main/update.json)），指向本仓库 `main` 分支。

## 尚未验证的部分

当前发布环境没有连接已 root 的 Android 设备，因此以下流程**仍需在真机上验证**，本仓库不会把它们
标记为已通过：

- KernelSU、KernelSU Next、APatch 三个管理器的真实安装、重启、打开入口与卸载流程
- 重启后的持久生效、IPv4 / IPv6 双栈行为
- 与 VPN 共存时的行为、指定 UID 的实际作用范围

已经执行的是本地静态测试、WebUI 测试与 BusyBox ash 测试；它们不能替代真机验证。
详见 [V1.0 发布说明](https://github.com/Darrickisar/JingJie/blob/main/docs/release/v1.0.md) 与 [验证记录](https://github.com/Darrickisar/JingJie/blob/main/docs/release/v1.0-verification.md)。

本项目也不把未经验证的兼容性、拦截率、耗电量或性能提升作为承诺。“低耗电”描述的是默认关闭可选后台
能力这一设计取向。

## 开发

```bash
npm install                     # 仅需 @playwright/test
npm test                        # 静态与 WebUI 单元测试（node --test）
npm run test:e2e                # Playwright 端到端与布局测试
npm run test:native             # 原生 history_reader 相关测试
sh tests/shell/run.sh           # BusyBox ash 下的 shell 测试
```

打包发布 ZIP（Windows PowerShell）：

```powershell
powershell -NoProfile -File ./scripts/build-module.ps1   # 产出 dist/JingJie-V1.0.zip
```

`tests/static/package.test.js` 会把 `dist/` 里的 ZIP 逐字节与源文件比对并检查体积预算，因此改动
`webroot/` 或任何随包脚本后必须重新打包，否则测试会以 “packaged content is stale” 失败。

### 目录结构

| 路径 | 内容 |
| --- | --- |
| `webroot/` | WebUI（原生 JS，无框架）：`index.html`、`app.js`、`api.js`、`bridge.js`、`app.css` |
| `webui_api.sh` | WebUI 与模块之间的命令边界 |
| `lib/rules/` | 规则引擎：来源注册、抓取、归一化、生成、挂载、状态、诊断 |
| `*_manager.sh` | 刷新、DoH、防火墙、历史、进程等子系统 |
| `cmd/`、`internal/dohproxy/` | Go 实现的 `jingjie-doh-proxy` |
| `native/`、`tools/` | `history_reader`（C，四种 ABI 预编译）与 `rule_fetcher.dex` |
| `rules/` | 内置安全基线与恢复用 hosts |
| `docs/` | 设计文档、发布说明与验证记录 |
| `tests/` | static / webui / native / shell / device 测试 |

## 许可与第三方组件

`jingjie-doh-proxy` 静态链接了 AdGuard `dnsproxy`（Apache-2.0）与 `miekg/dns`（BSD-3-Clause）等 Go
模块，版本由 `go.mod` / `go.sum` 固定，清单见 [NOTICES](NOTICES)。
规则来源的版权归各自项目所有，净界只做下载与格式转换。

该可执行文件不随模块 ZIP 打包，只在首次启用或检测 DoH 时按设备架构从 v1.0 release 下载，并按
`assets/doh-companions.tsv` 中固定的体积、SHA-256 与 ELF 架构校验。DoH 一直关闭的设备不会下载它。

本项目以 **GPL-3.0-only** 授权，完整条款见 [LICENSE](LICENSE)，版权声明与第三方清单见
[NOTICES](NOTICES)。

## 联系与反馈

- Telegram 交流频道：[@JingJie_Group](https://t.me/JingJie_Group)
- 问题反馈：[GitHub Issues](https://github.com/Darrickisar/JingJie/issues)

## 致谢

- [AWAvenue-Ads-Rule（秋风广告规则）](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
- [10007 规则](https://github.com/lingeringsound/10007)
- KernelSU、KernelSU Next、APatch 及其模块 WebUI 能力

控制台内的“设置 → 关于 → 查看致谢名单”提供同一份名单。

---

作者：相貌平平韩老魔 · 仓库：<https://github.com/Darrickisar/JingJie> · 频道：[@JingJie_Group](https://t.me/JingJie_Group)
