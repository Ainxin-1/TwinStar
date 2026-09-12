//! 局域网设备发现（UDP 广播）。
//!
//! 只解决"设备互相看见、并拿到对方连接码"——真正的连通交给 iroh。这里广播的是
//! `{id, name, addrs}`，让前端能列出同网段的其他 TwinStar，点一下就把对方连接码
//! 自动填好，省得手动抄一长串 64 位十六进制。
//!
//! 广播里带 `addrs`（本端 iroh 的 UDP 监听地址）是刻意的：同网段两台机器拿到彼此的
//! `ip:port` 就能直接拨号，不必再等 iroh 的地址发现（DNS pkarr 在国内部分网络下
//! 会超时）。设备页点一下即直连，实测从"转圈几秒"变成"秒连"。
//!
//! 设计取舍：
//!   - 固定端口 + 受限广播 `255.255.255.255`，不依赖 mDNS 服务发现（Windows 上
//!     mDNS 服务常常没起，自己发广播最稳）。
//!   - 优雅降级：绑定 / 广播失败（防火墙、无网卡）只留手动输入，绝不拖垮主流程。
//!   - 自己发的广播也会被自己收到，靠 `id` 去重跳过。

use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::net::UdpSocket;

/// 发现专用端口，刻意避开 iroh 占用的范围。
pub const DISCOVERY_PORT: u16 = 39617;
const MAGIC: &str = "TWINSTAR-DISC-v1";
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
const SWEEP_INTERVAL: Duration = Duration::from_secs(2);
/// 超过这个时间没再收到某设备的心跳，就当它离线。
const PEER_TTL: Duration = Duration::from_secs(12);

/// 推给前端的单个设备视图。
#[derive(Serialize, Clone)]
pub struct PeerView {
    /// 可直接填进"对方连接码"的串：`id` 或 `id@ip:port,...`
    pub code: String,
    pub id: String,
    pub name: String,
    /// 是否带直连地址（有地址才能秒连，否则还得走发现服务）
    pub routable: bool,
    /// 距上次见面的秒数（仅展示用）
    pub ago_secs: u64,
}

#[derive(Default)]
struct Registry(Mutex<HashMap<String, (String, Vec<SocketAddr>, Instant)>>);

impl Registry {
    /// 清掉过期设备，返回当前存活列表。
    fn prune(&self, now: Instant) -> Vec<PeerView> {
        let mut map = self.0.lock().unwrap();
        map.retain(|_, (_, _, t)| now.duration_since(*t) < PEER_TTL);
        map.iter()
            .map(|(id, (name, addrs, t))| PeerView {
                // 对方 id 理论上一定合法（是我们自己解析出来的）；万一解析失败就退回裸 id，
                // 至少还能走发现服务，不至于整个设备列表崩掉。
                code: match id.parse::<iroh::EndpointId>() {
                    Ok(eid) => crate::net::format_addr_code(eid, addrs),
                    Err(_) => id.clone(),
                },
                id: id.clone(),
                name: name.clone(),
                routable: !addrs.is_empty(),
                ago_secs: now.duration_since(*t).as_secs(),
            })
            .collect()
    }

    fn upsert(&self, id: &str, name: &str, addrs: Vec<SocketAddr>, now: Instant) {
        self.0
            .lock()
            .unwrap()
            .insert(id.to_string(), (name.to_string(), addrs, now));
    }
}

/// 本端地址是动态的（网卡上下线、打洞后新增映射），所以不拷贝一份快照，
/// 而是每次广播前问调用方要最新的。
type AddrSource = Arc<dyn Fn() -> Vec<SocketAddr> + Send + Sync>;

/// 昵称同理：用户可能中途改名，每轮广播前取当前值，3 秒内全网段可见。
pub type NameSource = Arc<Mutex<String>>;

/// 启动发现。任何一步失败都只记日志、不向上抛，避免拖垮整个网络初始化。
pub fn start(app: AppHandle, my_id: String, my_name: NameSource, addrs: AddrSource) {
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run(app.clone(), my_id, my_name, addrs).await {
            let _ = app.emit("log", format!("ℹ️ 局域网发现未启用：{e:#}"));
        }
    });
}

async fn run(
    app: AppHandle,
    my_id: String,
    my_name: NameSource,
    addrs: AddrSource,
) -> Result<()> {
    let socket = std::sync::Arc::new(UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await?);
    socket.set_broadcast(true)?;
    let registry = std::sync::Arc::new(Registry::default());

    // —— 收：把别人的广播写进登记表，并立刻推一次给前端 ——
    let recv_sock = socket.clone();
    let recv_reg = registry.clone();
    let recv_id = my_id.clone();
    let recv_app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match recv_sock.recv_from(&mut buf).await {
                Ok((n, _addr)) => {
                    if let Some((id, name, addrs)) = parse_announce(&buf[..n]) {
                        if id == recv_id {
                            continue; // 自己的回声
                        }
                        recv_reg.upsert(&id, &name, addrs, Instant::now());
                        let peers = recv_reg.prune(Instant::now());
                        let _ = recv_app.emit("devices", &peers);
                    }
                }
                Err(_) => break,
            }
        }
    });

    // —— 发：周期性广播自己的存在 ——
    // 每次都重新取地址：网卡上下线、打洞拿到新映射后广播内容要跟着变，
    // 否则对方拿到的可能是已经失效的旧端口。
    let dest = std::net::SocketAddr::from((std::net::Ipv4Addr::BROADCAST, DISCOVERY_PORT));
    let send_sock = socket;
    tauri::async_runtime::spawn(async move {
        loop {
            let addrs: Vec<String> = addrs().iter().map(|a| a.to_string()).collect();
            let my_name = my_name.lock().unwrap().clone();
            let announce =
                serde_json::json!({ "magic": MAGIC, "id": my_id, "name": my_name, "addrs": addrs });
            if let Ok(payload) = serde_json::to_vec(&announce) {
                let _ = send_sock.send_to(&payload, dest).await;
            }
            tokio::time::sleep(ANNOUNCE_INTERVAL).await;
        }
    });

    // —— 扫：周期性清过期设备并推送，保证离线设备及时从列表消失 ——
    let sweep_reg = registry;
    let sweep_app = app;
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        let peers = sweep_reg.prune(Instant::now());
        let _ = sweep_app.emit("devices", &peers);
    }
}

/// 从广播报文里解析出 (id, name, addrs)；magic 不对或字段缺失返回 None。
///
/// `addrs` 缺失不算错——旧版本 / 其他实现可能没带，退化成纯 id 即可。
fn parse_announce(buf: &[u8]) -> Option<(String, String, Vec<SocketAddr>)> {
    let v: serde_json::Value = serde_json::from_slice(buf).ok()?;
    if v.get("magic")?.as_str()? != MAGIC {
        return None;
    }
    let id = v.get("id")?.as_str()?.to_string();
    let name = v.get("name")?.as_str()?.to_string();
    if id.is_empty() {
        return None;
    }
    let addrs = v
        .get("addrs")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .filter_map(|s| s.parse::<SocketAddr>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some((id, name, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "magic": MAGIC,
            "id": id,
            "name": "测试机",
            "addrs": ["192.168.1.9:39617", "垃圾地址"],
        }))
        .unwrap()
    }

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_addresses_and_skips_bad_ones() {
        let (id, name, addrs) = parse_announce(&sample(ID)).unwrap();
        assert_eq!(id, ID);
        assert_eq!(name, "测试机");
        // 非法地址应当被丢掉而不是让整个包作废
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].to_string(), "192.168.1.9:39617");
    }

    #[test]
    fn announces_without_addrs_still_parse() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "magic": MAGIC, "id": ID, "name": "老版本",
        }))
        .unwrap();
        let (_id, _name, addrs) = parse_announce(&raw).unwrap();
        assert!(addrs.is_empty(), "没带 addrs 时退化为空地址列表");
    }

    #[test]
    fn rejects_other_magic() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "magic": "something-else", "id": ID, "name": "x",
        }))
        .unwrap();
        assert!(parse_announce(&raw).is_none());
    }

    /// 注册表必须把 code 拼成可用于直连的形式，且能过滤掉过期设备。
    #[test]
    fn registry_builds_routable_code_and_expires() {
        let reg = Registry::default();
        let now = Instant::now();
        let addr: SocketAddr = "192.168.1.9:39617".parse().unwrap();
        reg.upsert(ID, "测试机", vec![addr], now);

        let peers = reg.prune(now);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].code, format!("{ID}@192.168.1.9:39617"));
        assert!(peers[0].routable);

        // 超过 TTL 后应被清掉
        let later = now + PEER_TTL + Duration::from_secs(1);
        assert!(reg.prune(later).is_empty());
    }
}
