# TwimStar ☄

零成本 P2P 文件传输软件 —— 局域网直连 / 跨网打洞 / 中继兜底，全程零服务器、零账号、免 VPN。

## 特性

- **零成本**：不租服务器，使用 iroh 官方免费公共中继兜底
- **免 VPN**：针对中国大陆运营商网络优化，开箱即用
- **连接码互传**：对方 64 位连接码粘贴即发，端到端直连
- **拖拽发送**：文件拖进窗口即选中，自动保存到接收目录
- **跨网打洞**：QUIC + NAT 打洞（iroh），CGNAT 环境实测可用

## 技术栈

| 层 | 选型 |
|---|---|
| GUI | Tauri 2（WebView2 渲染）+ 原生 HTML/CSS/JS |
| 传输核心 | [iroh](https://github.com/n0-computer/iroh) 1.1（QUIC + NAT 打洞，按 EndpointId 拨号，无需信令服务器） |
| 平台 | Windows（Android / macOS 计划中） |

### 分层连接策略（中国运营商优化）

```
局域网直连 → IPv6 直连 → IPv4 UDP 打洞（国内 STUN）→ UPnP/PCP → 中继兜底
```

## 构建

```bash
cd app/TwimStar-tauri/src-tauri
cargo build --release --features custom-protocol
```

产物：`target/release/twimstar.exe`（单文件绿色版，需系统装有 WebView2 运行时，Win10/11 默认自带）。

> 低内存机器建议加 `-j 1` 并设 `CARGO_PROFILE_RELEASE_OPT_LEVEL=1`。

## 使用

1. 双击运行，复制「我的连接码」发给对方
2. 对方把你的连接码粘贴进「对方连接码」
3. 拖入文件（或点击选择），点「发送」；接收方自动保存到 Downloads

## 目录结构

```
app/TwimStar-tauri   # 当前主版本：Tauri 2 + iroh
app/TwimStar         # 历史版本：egui 界面
demo/iroh-transfer   # 里程碑 1：iroh 最小 CLI demo
tools/               # 网络探测脚本等
```

## 路线图

- [ ] mDNS 局域网自动发现（同网段免抄码）
- [ ] 跨设备真打洞验证（手机热点 vs 家 WiFi）
- [ ] 安卓版（cargo-quad-apk / Tauri mobile）
- [ ] 多文件 / 文件夹传输

## 实测数据（2026-09）

本机双进程：10MB / 437~556ms / 17.9~42.2 MB/s，MD5 一致；CGNAT 公网映射获取成功，高端口 UDP 未被过滤。

## License

MIT
