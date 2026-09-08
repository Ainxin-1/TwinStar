//! 网络层：端点构建（打洞参数调优）+ 连接路径探测 + 网络环境自检
//!
//! 这一层只关心"怎么把两个端点连起来、连得有多好"，文件收发在 [`crate::transfer`]。
//!
//! 三个能力：
//!   1. [`build_endpoint`]  —— 针对中国家庭网络（CGNAT / 长 RTT 中继）调过参的端点
//!   2. [`connect_peer`]    —— 拨号 + 等打洞 + 判定最终走的是直连还是中继
//!   3. [`collect_diag`]    —— 网络环境自检，给用户一句人话结论

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, RelayMode, SecretKey, Watcher,
    endpoint::{presets, Connection, PortmapperConfig, QuicTransportConfig, VarInt},
    unstable_net_report::NetReport,
};
use serde::Serialize;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const ALPN: &[u8] = b"twimstar/1";

/// 打洞等待上限：给 QUIC 一点时间从"中继先行"升级到"直连"，
/// 大文件走直连能差一个数量级，等 2.5s 很划算；等不到就先走中继，不阻塞传输。
pub const DEFAULT_WAIT_DIRECT: Duration = Duration::from_millis(2500);

/// 连接失败后的重试间隔：首次拨号常卡在地址发现（DNS/pkarr），
/// 立刻重试一次的成本远低于让用户再点一次"发送"。
const RETRY_DELAY: Duration = Duration::from_millis(600);

// ---------------------------------------------------------------- 端点构建

/// 针对跨网传输调过参的 QUIC 配置。
///
/// 只动窗口大小一项，其余沿用 iroh 的默认值 —— 它已经把打洞相关的参数调好了
/// （5s 心跳保活、路径 15s 空闲超时、32 个打洞候选地址），自作主张反而会打洞变差。
///
/// 而窗口是另一回事：noq 的默认值按 100ms RTT 设计，单流接收窗口只有约 1.2MiB。
/// 国内跨网、或者绕境外中继时 RTT 常在 200~400ms，流控会把单流吞吐锁死在
/// 5MB/s 上下（1.2MiB / 0.22s）。放大到 16MiB 才吃得满带宽。
/// 连接级 `receive_window` 默认已经是 VarInt::MAX，不动它。
pub fn tuned_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .stream_receive_window(VarInt::from_u32(16 * 1024 * 1024))
        .send_window(64 * 1024 * 1024)
        .build()
}

/// 构建端点。密钥由设备身份派生，因此"我的连接码"跨重启固定。
pub async fn build_endpoint(seed: [u8; 32]) -> Result<Endpoint> {
    Ok(Endpoint::builder(presets::N0)
        .secret_key(SecretKey::from_bytes(&seed))
        .alpns(vec![ALPN.to_vec()])
        // 中继兜底用 n0 官方免费节点；net_report 会自己挑延迟最低的当家。
        .relay_mode(RelayMode::Default)
        // UPnP/PCP/NAT-PMP：能开就开，是打洞之外最便宜的直连手段。
        .portmapper_config(PortmapperConfig::default())
        .transport_config(tuned_transport_config())
        .bind()
        .await
        .context("创建网络端点失败")?)
}

// ---------------------------------------------------------------- 路径判定

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// 端到端直连（打洞成功 / 局域网 / IPv6）
    Direct,
    /// 纯中继转发
    Relay,
    /// 直连与中继同时存在，但当前没走直连
    Mixed,
    /// 尚未探测
    Unknown,
}

/// 一次连接的通路描述，直接喂给前端展示。
#[derive(Serialize, Clone, Debug)]
pub struct PathView {
    pub kind: PathKind,
    /// 人类可读：直连 / 中继 / 打洞中
    pub label: String,
    /// 往返时延（毫秒），0 表示未知
    pub rtt_ms: u32,
    /// 直连地址或中继域名
    pub detail: String,
}

impl Default for PathView {
    fn default() -> Self {
        Self {
            kind: PathKind::Unknown,
            label: "连接中".into(),
            rtt_ms: 0,
            detail: String::new(),
        }
    }
}

/// 读取连接当前的通路情况（快照）。
pub fn describe(conn: &Connection) -> PathView {
    let mut selected: Option<(bool, Duration, String)> = None; // (is_ip, rtt, detail)
    let mut has_ip = false;
    let mut has_relay = false;
    let mut first: Option<(bool, String)> = None;

    for p in conn.paths().iter() {
        let detail = path_detail(p.remote_addr());
        let rtt = p.rtt();
        if p.is_ip() {
            has_ip = true;
        } else if p.is_relay() {
            has_relay = true;
        }
        if first.is_none() {
            first = Some((p.is_ip(), detail.clone()));
        }
        if p.is_selected() {
            selected = Some((p.is_ip(), rtt, detail));
        }
    }

    let Some((is_ip, rtt, detail)) = selected else {
        let (is_ip, detail) = first.unwrap_or((false, String::new()));
        return PathView {
            kind: if has_ip {
                PathKind::Direct
            } else if has_relay {
                PathKind::Relay
            } else {
                PathKind::Unknown
            },
            label: if is_ip { "直连".into() } else { "中继".into() },
            rtt_ms: 0,
            detail,
        };
    };

    PathView {
        kind: if is_ip {
            PathKind::Direct
        } else if has_ip {
            PathKind::Mixed
        } else {
            PathKind::Relay
        },
        label: if is_ip { "直连".into() } else { "中继".into() },
        rtt_ms: rtt.as_millis() as u32,
        detail,
    }
}

fn path_detail(addr: &iroh::TransportAddr) -> String {
    match addr {
        iroh::TransportAddr::Ip(a) => a.to_string(),
        iroh::TransportAddr::Relay(u) => trim_relay(u.as_str()),
        other => other.to_string(),
    }
}

/// 连接里是否已经出现了直连路径（出现后 iroh 会把流量迁过去）。
pub fn has_direct(conn: &Connection) -> bool {
    conn.paths().iter().any(|p| p.is_ip())
}

fn trim_relay(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_end_matches(|c| c == '/' || c == '.')
        .to_string()
}

/// 等到直连路径出现，或超时。
///
/// iroh 的策略是"先走中继保证连通，同时后台打洞"，打洞成功会自动把流量迁到直连。
/// 大文件传输前等这一小会儿，往往就能从"中继 5MB/s"变成"直连 50MB/s"。
pub async fn wait_for_direct(conn: &Connection, timeout: Duration) -> bool {
    if timeout.is_zero() {
        return has_direct(conn);
    }
    let deadline = Instant::now() + timeout;
    loop {
        if has_direct(conn) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

// ---------------------------------------------------------------- 拨号

/// 拨号并尽量等到直连。
///
/// 失败会重试一次：首拨常见的失败原因是地址发现（DNS / pkarr）还没就绪，
/// 立刻再来一次基本就能通，比让用户手动重发友好得多。
pub async fn connect_peer(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    alpn: &[u8],
    wait_direct: Duration,
) -> Result<Connection> {
    let first = endpoint.connect(addr.clone(), alpn).await;
    let conn = match first {
        Ok(c) => c,
        Err(e) => {
            tokio::time::sleep(RETRY_DELAY).await;
            endpoint
                .connect(addr, alpn)
                .await
                .map_err(|retry| anyhow::anyhow!("连接对方失败：{retry}（首次尝试：{e}）"))?
        }
    };

    if !wait_direct.is_zero() && !has_direct(&conn) {
        wait_for_direct(&conn, wait_direct).await;
    }
    Ok(conn)
}

// ---------------------------------------------------------------- 环境自检

/// 自检结果，一屏展示"我的网络到底能不能打洞"。
#[derive(Serialize, Clone, Debug, Default)]
pub struct Diag {
    /// 已连上的中继（域名）
    pub relay: Option<String>,
    /// UDP 探测是否成功（v4 / v6）
    pub udp_v4: bool,
    pub udp_v6: bool,
    /// 探测到的公网地址
    pub public_v4: Option<String>,
    pub public_v6: Option<String>,
    /// 端口映射是否随目标变化 —— true 即对称型 NAT，打洞难度大
    pub nat_varies: Option<bool>,
    /// 是否位于运营商 CGNAT 地址段
    pub cgnat: bool,
    /// 各中继延迟（域名, 毫秒）
    pub relay_latency: Vec<(String, u32)>,
    /// 本端监听到的地址
    pub local_addrs: Vec<String>,
    /// 检测到的 TUN 网卡 / 代理软件（会吞 UDP，直接毁掉打洞）
    pub vpn_hint: Option<String>,
    /// 一句话结论
    pub verdict: String,
    /// 可执行建议（可为空）
    pub advice: String,
}

fn is_cgnat(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            // 100.64.0.0/10 运营商级 NAT 保留段
            v.octets()[0] == 100 && (v.octets()[1] & 0xC0) == 64
        }
        IpAddr::V6(_) => false,
    }
}

/// 收集网络自检信息。只读，不改动任何连接状态。
pub async fn collect_diag(endpoint: &Endpoint) -> Diag {
    let mut d = Diag::default();

    // 中继连接状态。刚 bind 完中继握手往往还没完成，直接读会误报"未连接"，
    // 所以给它几秒时间；期间顺便刷新 watcher（`get()` 本身会拉最新值）。
    let mut relay_watcher = endpoint.home_relay_status();
    for _ in 0..12 {
        if let Some(url) = relay_watcher
            .get()
            .into_iter()
            .find(|s| s.is_connected())
            .map(|s| trim_relay(s.url().as_str()))
        {
            d.relay = Some(url);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // net_report：UDP 探测 / 公网地址 / NAT 行为 / 中继延迟
    if let Some(r) = net_report(endpoint).await {
        d.udp_v4 = r.udp_v4;
        d.udp_v6 = r.udp_v6;
        d.public_v4 = r.global_v4.map(|a| a.to_string());
        d.public_v6 = r.global_v6.map(|a| a.to_string());
        d.nat_varies = r.mapping_varies_by_dest();
        d.relay_latency = r
            .relay_latency
            .iter()
            .map(|(_probe, url, dur)| (trim_relay(url.as_str()), dur.as_millis() as u32))
            .collect();
        d.relay_latency.truncate(4);
        if let Some(v4) = r.global_v4 {
            d.cgnat = d.cgnat || is_cgnat(&IpAddr::V4(*v4.ip()));
        }
    }

    // 本端地址要等 net_report 跑完再读：探测出来的公网映射/CGNAT 内网地址
    // 这会儿才发布到 endpoint.addr() 上，读早了只有局域网地址。
    let addr = endpoint.addr();
    for s in addr.ip_addrs() {
        // 网卡上出现 100.64/10 说明运营商分的是 CGNAT 内网地址，
        // 光看探测出来的公网地址是看不出来的。
        if is_cgnat(&s.ip()) {
            d.cgnat = true;
        }
        d.local_addrs.push(s.to_string());
    }
    d.local_addrs.extend(
        addr.relay_urls()
            .map(|u| format!("relay:{}", trim_relay(u.as_str()))),
    );

    d.vpn_hint = detect_vpn_tun();
    (d.verdict, d.advice) = verdict(&d);
    d
}

/// 取一份 net_report；最多等 4 秒，等不到就当没有（不阻塞界面）。
async fn net_report(endpoint: &Endpoint) -> Option<NetReport> {
    let mut w = endpoint.net_report();
    for _ in 0..16 {
        if let Some(r) = w.get() {
            return Some(r);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// 根据自检结果给结论。这里写的是给人看的话，不是日志。
fn verdict(d: &Diag) -> (String, String) {
    let mut advice = String::new();

    let udp_ok = d.udp_v4 || d.udp_v6;

    if let Some(vpn) = &d.vpn_hint {
        if !udp_ok {
            advice.push_str(&format!(
                "检测到 {vpn}：TUN 虚拟网卡会吞掉 UDP，打洞必然失败，只能走中继。"
            ));
            advice.push_str("临时退出它再传，速度通常能上一个数量级。");
            return ("代理 / 虚拟网卡正在拦截 UDP，直连基本无望".into(), advice);
        }
        // UDP 探测是真的通了，说明这会儿没被拦。只提示风险，不判死刑。
        advice.push_str(&format!(
            "检测到 {vpn}。目前 UDP 探测正常，但如果开着代理软件，它的 TUN 网卡随时可能吞掉 UDP 流量，\
             表现为对方连不上或只能走中继。传大文件前建议先退出代理。"
        ));
        return ("有虚拟网卡痕迹，UDP 目前仍可用".into(), advice);
    }

    if !udp_ok {
        advice.push_str("UDP 出站被过滤：路由器或运营商拦了。换手机热点、或让对方发起连接（反向打洞）可能有效，实在不行会走中继兜底。");
        return ("UDP 探测失败，本网络打不了洞".into(), advice);
    }

    if d.nat_varies == Some(true) {
        advice.push_str("检测到对称型 NAT：同一内网端口对不同目标映射成不同公网端口，打洞成功率低。");
        if d.cgnat {
            advice.push_str(" 你还在运营商 CGNAT 后面，两层地址转换，直连难度更高。");
        }
        advice.push_str("建议：开启路由器 UPnP，或改用 IPv6（若已分配）。");
        return ("对称型 NAT，打洞成功率偏低".into(), advice);
    }

    if d.cgnat {
        advice.push_str("你在运营商 CGNAT 后面：只要不是对称型 NAT，UDP 打洞仍然可行（实测高端口未被过滤）。");
        if d.udp_v6 {
            advice.push_str(" 已检测到 IPv6，IPv6 直连是最稳的一条路。");
        }
        return ("CGNAT 环境，仍有机会直连".into(), advice);
    }

    if d.udp_v6 {
        advice.push_str("IPv6 可用：让双方都走 IPv6 时几乎必定直连。");
    } else {
        advice.push_str("UDP 通、NAT 行为正常，打洞条件良好。");
    }
    ("网络条件良好，可以直连".into(), advice)
}

// ------------------------------------------------------- TUN / 代理软件检测

const VPN_PROCESSES: &[&str] = &[
    "sing-box.exe",
    "v2rayn.exe",
    "clash",
    "mihomo.exe",
    "verge",
    "nekoray.exe",
    "hiddify",
    "xray.exe",
    "v2ray.exe",
    "tun2socks.exe",
];

const TUN_ADAPTERS: &[&str] = &[
    "wintun",
    "tap-windows",
    "sing-box",
    "clash",
    "mihomo",
    "tun0",
    "utun",
];

/// 尽力而为地探测"有没有东西在拦 UDP"。检测失败一律返回 None，不影响主流程。
fn detect_vpn_tun() -> Option<String> {
    let mut hits: Vec<String> = Vec::new();

    if let Some(p) = running_vpn_process() {
        hits.push(p);
    }
    if let Some(a) = tun_adapter() {
        let a = a.to_lowercase();
        if !hits.iter().any(|h| h.to_lowercase().contains(&a)) {
            hits.push(a);
        }
    }

    if hits.is_empty() {
        None
    } else {
        Some(hits.join(" / "))
    }
}

fn running_vpn_process() -> Option<String> {
    let out = std::process::Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    VPN_PROCESSES
        .iter()
        .find(|p| text.contains(&p.to_lowercase()))
        .map(|p| p.to_string())
}

fn tun_adapter() -> Option<String> {
    let out = std::process::Command::new("ipconfig")
        .arg("/all")
        .output()
        .ok()?;
    // 中文 Windows 下 ipconfig 输出是 GBK，这里只匹配 ASCII 关键字，丢字符无所谓。
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    TUN_ADAPTERS
        .iter()
        .find(|a| text.contains(*a))
        .map(|a| format!("虚拟网卡 {a}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// 真机冒烟：连真实网络跑一次自检，把结果打出来给人看。
    ///
    /// 默认跳过（要联网、要几秒）。跑法：
    /// `cargo test -p twimstar net::tests::smoke_real_network_diag -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "需要真实网络，默认不跑"]
    async fn smoke_real_network_diag() {
        let ep = build_endpoint([7u8; 32]).await.expect("端点应能创建");
        let d = collect_diag(&ep).await;
        println!("连接码      : {}", ep.id());
        println!("UDP v4/v6   : {} / {}", d.udp_v4, d.udp_v6);
        println!("公网地址    : {:?} / {:?}", d.public_v4, d.public_v6);
        println!("CGNAT       : {}", d.cgnat);
        println!("NAT 随目标变: {:?}", d.nat_varies);
        println!("中继        : {:?}", d.relay);
        println!("中继延迟    : {:?}", d.relay_latency);
        println!("本端地址    : {:?}", d.local_addrs);
        println!("代理/虚拟网卡: {:?}", d.vpn_hint);
        println!("结论        : {}", d.verdict);
        println!("建议        : {}", d.advice);
        assert!(
            d.relay.is_some() || d.udp_v4 || d.udp_v6,
            "至少要能连上中继，或 UDP 可用，否则这个网络下 TwimStar 完全没法工作"
        );
    }

    /// 传一趟文件，返回 (MB/s, 传输前通路, 传输后通路)。
    async fn bench_round(
        from: &Endpoint,
        to: &Endpoint,
        src: &std::path::Path,
        save: &std::path::Path,
    ) -> (f64, String, String) {
        std::fs::create_dir_all(save).unwrap();
        let save2 = save.to_path_buf();
        let to2 = to.clone();
        let recv = tokio::spawn(async move {
            let incoming = to2.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let r = crate::transfer::handle_incoming_with(conn, &save2, None, |_, _, _| {}).await;
            // ack 要靠连接驱动轮询才发出去，端点别立刻丢。
            tokio::time::sleep(Duration::from_millis(300)).await;
            r
        });

        let conn = connect_peer(from, to.id().into(), ALPN, Duration::ZERO)
            .await
            .expect("应能连上");
        let view = describe(&conn);

        let t0 = Instant::now();
        let sent = crate::transfer::send_on_conn(
            &conn,
            src,
            &crate::transfer::SendOptions::default(),
            |_, _| {},
        )
        .await;
        let secs = t0.elapsed().as_secs_f64();
        let received = recv.await.unwrap();

        assert!(sent.is_ok(), "发送失败：{sent:?}");
        assert!(received.is_ok(), "接收失败：{received:?}");

        let after = describe(&conn);
        let size = std::fs::metadata(src).unwrap().len() as f64;
        let fmt = |v: &PathView| format!("{} {} / RTT {}ms", v.label, v.detail, v.rtt_ms);
        (size / secs.max(1e-9) / 1e6, fmt(&view), fmt(&after))
    }

    /// 窗口大小到底值不值？用真实中继跑一次对照。
    ///
    /// 两个端点都只发布中继地址（`AddrFilter::relay_only`），强制流量绕中继 ——
    /// 本机互连 RTT 接近 0，窗口根本不会成为瓶颈，那样测不出差别。
    ///
    /// 关键点：QUIC 的流控窗口是各自通告给对方的，所以同一对连接上两个方向天然不同：
    ///   - tuned → plain：受 plain 那端 1.2MiB 的小窗口卡着（等于 v0.7 的行为）
    ///   - plain → tuned：受 tuned 那端 16MiB 的窗口放行（v0.8 的行为）
    #[tokio::test]
    #[ignore = "需要真实网络并传输 32MB，默认不跑"]
    async fn bench_window_size_over_relay() {
        use iroh::address_lookup::AddrFilter;

        const SIZE: usize = 32 * 1024 * 1024;
        let dir = std::env::temp_dir().join(format!("twimstar-bench-{}", now_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("payload.bin");
        std::fs::write(&src, vec![0x5Au8; SIZE]).unwrap();

        /// 建一个端点；`tuned` 决定用 v0.8 的窗口还是 noq 默认值。
        async fn ep(tuned: bool) -> Endpoint {
            let b = Endpoint::builder(presets::N0)
                .alpns(vec![ALPN.to_vec()])
                .addr_filter(AddrFilter::relay_only());
            let b = if tuned {
                b.transport_config(tuned_transport_config())
            } else {
                b
            };
            b.bind().await.unwrap()
        }

        // 两轮各用一对全新端点：同一对端点传完第二趟会复用已打洞成功的连接，
        // 那样本机直连 RTT 2ms，窗口差异就完全看不出来了。
        let (slow, slow_before, slow_after) =
            bench_round(&ep(true).await, &ep(false).await, &src, &dir.join("to-plain")).await;
        let (fast, fast_before, fast_after) =
            bench_round(&ep(false).await, &ep(true).await, &src, &dir.join("to-tuned")).await;

        println!("—— 32MB，两轮都强制只发布中继地址 ——");
        println!("v0.7 窗口 1.2MiB : {slow:6.2} MB/s");
        println!("   起 {slow_before}\n   止 {slow_after}");
        println!("v0.8 窗口 16MiB  : {fast:6.2} MB/s");
        println!("   起 {fast_before}\n   止 {fast_after}");
        println!("提升             : {:.2}×", fast / slow.max(1e-9));

        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            slow_before.contains("中继") && fast_before.contains("中继"),
            "两轮都必须起步于中继才可比，实际：{slow_before} / {fast_before}"
        );
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    #[test]
    fn cgnat_range_detected() {
        assert!(is_cgnat(&IpAddr::V4(Ipv4Addr::new(100, 74, 0, 1))));
        assert!(!is_cgnat(&IpAddr::V4(Ipv4Addr::new(112, 32, 134, 7))));
        assert!(!is_cgnat(&IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn relay_url_is_trimmed() {
        assert_eq!(
            trim_relay("https://aps1-1.relay.n0.iroh.link."),
            "aps1-1.relay.n0.iroh.link"
        );
    }

    #[test]
    fn verdict_warns_on_sym_nat() {
        let d = Diag {
            udp_v4: true,
            nat_varies: Some(true),
            cgnat: true,
            ..Default::default()
        };
        let (v, _a) = verdict(&d);
        assert!(v.contains("对称型"));
    }

    #[test]
    fn verdict_warns_when_udp_blocked() {
        let d = Diag::default();
        let (v, _a) = verdict(&d);
        assert!(v.contains("打不了洞"));
    }

    #[test]
    fn tuned_window_is_larger_than_default() {
        // 默认单流窗口约 1.2MiB，这里必须显著更大，否则长 RTT 链路仍被流控卡住。
        let cfg = tuned_transport_config();
        let s = format!("{cfg:?}");
        assert!(s.contains("stream_receive_window"), "配置 debug 输出应含窗口字段：{s}");
    }
}
