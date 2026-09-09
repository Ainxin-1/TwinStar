# TwimStar ☄

零成本 P2P 文件传输软件 —— 局域网直连 / 跨网打洞 / 中继兜底，全程零服务器、零账号、免 VPN。

**下载**：[TwimStar v0.9.0（Windows x64，22.0 MB）](https://github.com/Ainxin-1/TwinStar2/releases/download/v0.9.0/TwimStar-v0.9.0-win-x64.exe)
SHA-256：`f146e5c24092246cac9f5e54d427a696c796fc040c38bc7268ee10ae1458ca18`

## 特性

- **零成本**：不租服务器，使用 iroh 官方免费公共中继兜底
- **免 VPN**：针对中国大陆运营商网络优化，开箱即用
- **连接码互传**：对方连接码粘贴即发，端到端直连（支持 `id@ip:port` 带地址写法）
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

### 连接更快更稳（v0.9）

- **带地址的连接码**：连接码支持 `id@ip:port,...` 写法。iroh 的地址发现走 DNS pkarr，
  国内部分运营商 / 代理环境下会超时或查不到，带上地址后这一步直接跳过，对方粘贴即直连。
  「复制带地址」按钮会把本机当前可直连的 UDP 地址一起编进码里。
- **局域网发现直出地址**：设备页广播里带上本端 iroh 监听地址，点列表里的「⚡ 发送」直接拨号，
  不再等网络发现，同网段基本秒连。
- **一次打洞，多次传输**：连接按对端缓存复用，第二次发送跳过拨号与打洞；接收侧在同一条连接上
  连续收多个文件，空闲 120s 才释放。复用连接若已失效会自动重连重发，不会把失败甩给用户。
- **拨号不再无限等待**：单次拨号 15s 超时，失败时给出可执行的下一步（而不是一句 `timeout`）。
- **通路升级实时可见**：打洞是后台持续进行的，传输途中从中继升级到直连会立刻更新顶栏徽章并记一条日志。

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

> 跨网怎么都连不上时，双方都改用「复制带地址」的码再试一次——它跳过 DNS 地址发现，直接按地址拨号。

## 目录结构

```
app/TwimStar-tauri   # 当前主版本：Tauri 2 + iroh
  src-tauri/src/net.rs      网络层：打洞参数 / 连接码 / 通路判定 / 网络自检
  src-tauri/src/transfer.rs 传输层：续传 + SHA-256 落盘校验 + 连接会话复用
  src-tauri/src/disc.rs     局域网 UDP 广播发现（携带直连地址）
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
