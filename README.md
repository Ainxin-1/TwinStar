# TwimStar ☄

零成本 P2P 文件传输软件 —— 局域网直连 / 跨网打洞 / 中继兜底，全程零服务器、零账号、免 VPN。

## 特性

- **零成本**：不租服务器，使用 iroh 官方免费公共中继兜底
- **免 VPN**：针对中国大陆运营商网络优化，开箱即用
- **连接码互传**：对方 64 位连接码粘贴即发，端到端直连
- **拖拽发送**：文件拖进窗口即选中，自动保存到接收目录
- **跨网打洞**：QUIC + NAT 打洞（iroh），CGNAT 环境实测可用
- **连接可视**：顶栏实时显示当前走的是「⚡ 直连」还是「🔁 中继」以及 RTT
- **速率可视**：传输中显示实时速率、已传/总量、预计剩余时间，支持中途取消
- **网络自检**：一屏看清 UDP 通不通、NAT 类型、公网地址、中继延迟，并给出可执行建议
- **代理告警**：检测到 sing-box / Clash 等 TUN 虚拟网卡会直接提示——它会吞掉 UDP，打洞必失败

## 技术栈

| 层 | 选型 |
|---|---|
| GUI | Tauri 2（WebView2 渲染）+ 原生 HTML/CSS/JS |
| 传输核心 | [iroh](https://github.com/n0-computer/iroh) 1.1（QUIC + NAT 打洞，按 EndpointId 拨号，无需信令服务器） |
| 平台 | Windows（Android / macOS 计划中） |

### 分层连接策略（中国运营商优化）

```
局域网直连 → IPv6 直连 → IPv4 UDP 打洞（打洞候选地址 + UPnP/PCP）→ 中继兜底
```

### 打洞与吞吐调优（v0.8）

- **等待打洞再发**：iroh 的策略是"先走中继保证连通，同时后台打洞"。大文件（≥2MB）发送前最多等 2.5s 让直连建立，
  直连与中继的吞吐往往差一个数量级，这点等待很划算；小文件不等，直接发。
- **放大 QUIC 流控窗口**：noq 默认单流接收窗口约 1.2MiB（按 100ms RTT 设计）。跨网或绕境外中继时
  RTT 常在 200~400ms，默认窗口会把单流锁死在 5MB/s 上下。v0.8 放到 16MiB，发送窗口 64MiB。
  打洞相关参数（5s 心跳、路径 15s 空闲超时、32 个候选地址）沿用 iroh 默认值，不自作主张。
- **失败自动重试一次**：首拨常卡在地址发现（DNS/pkarr），立刻重试一次通常就通。
- **读写块 256KiB → 1MiB**：长肥管道上降低 syscall 与 QUIC 帧开销占比。
- **TUN/代理检测**：`tasklist` + `ipconfig` 识别 sing-box / Clash / Wintun 等，命中时直接告诉用户"直连没戏，退出它或走中继"。

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
  src-tauri/src/net.rs      网络层：打洞参数 / 通路判定 / 网络自检
  src-tauri/src/transfer.rs 传输层：续传 + SHA-256 落盘校验
  src-tauri/src/core/       纯逻辑层（自 TwinStar v4 移植）
app/TwimStar         # 历史版本：egui 界面
demo/iroh-transfer   # 里程碑 1：iroh 最小 CLI demo
tools/               # 网络探测脚本等
```

## 界面

- **传输**：连接码 / 拖放发送（速率 + 剩余时间 + 取消）/ 自动接收
- **活动日志**：连接、通路、校验结果全量留痕
- **网络**：自检结论 + 建议 + 连通性明细 + 中继延迟，可随时重新检测

## 路线图

- [ ] mDNS 局域网自动发现（同网段免抄码）
- [ ] 跨设备真打洞验证（手机热点 vs 家 WiFi）
- [ ] 安卓版（cargo-quad-apk / Tauri mobile）
- [ ] 多文件 / 文件夹传输

## 实测数据（2026-09）

- 本机双进程：10MB / 437~556ms / 17.9~42.2 MB/s，MD5 一致。
- 真机自检（v0.8，家宽 CGNAT 环境）：UDP v4 可用、IPv6 无；NAT 为锥型（端口不随目标变化 → 可打洞）；
  网卡拿到运营商 CGNAT 地址 `100.74.x.x`，同时探测到公网映射 `112.32.x.x`；
  自动选中继 aps1（新加坡）123ms，euc1 242ms、usw1 211ms。
- 自检可随时复跑：`cargo test smoke_real_network_diag -- --ignored --nocapture`。

## License

MIT
