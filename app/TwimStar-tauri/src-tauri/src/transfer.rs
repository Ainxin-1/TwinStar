//! 传输层：iroh QUIC 通道 + 断点续传 + 落盘完整性校验
//!
//! 协议（单个双向流）：
//!   1. 发送方 → 接收方：`u32 LE` 元数据长度 + JSON 元数据（文件名/大小/指纹/SHA-256）
//!   2. 接收方 → 发送方：`u64 LE` 续传起点（0 表示从头传）
//!   3. 发送方 → 接收方：从起点开始的原始字节流
//!   4. 接收方 → 发送方：`OK` 或 `ERR:<原因>`
//!
//! 续传判定：接收侧 sidecar `<file>.twinmeta` 记录的指纹与本次一致才续写 `<file>.part`。
//! 完整性：接收完成后对落盘文件复算 SHA-256，与元数据比对；不一致则删除文件并报错。

use anyhow::{Context, Result};
use iroh::{EndpointAddr, endpoint::Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::core::path::{is_inside, sanitize_relative, unique_path, validate_relative};

/// 读盘 / 写盘的块大小。
///
/// 256KiB 是按"低延迟局域网"定的；跨网或走中继时 RTT 常常上百毫秒，
/// 块越大 syscall 与 QUIC 帧开销占比越低，1MiB 在长肥管道上明显更划算。
pub const CHUNK: usize = 1024 * 1024;

/// 发送选项。
#[derive(Clone, Default)]
pub struct SendOptions {
    /// 拨号后等待直连（打洞）的最长时间；`Duration::ZERO` 表示不等。
    pub wait_direct: Duration,
    /// 取消标志：置位后当前发送会尽快停下来。
    pub cancel: Option<Arc<AtomicBool>>,
    /// 对端看到的文件名。默认取源路径的 `file_name()`；
    /// 传整个文件夹时用相对路径（如 `照片/北京/1.jpg`），让对方保留目录结构。
    pub name: Option<String>,
}

impl SendOptions {
    pub fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(false)
    }
}

/// 等对方回"收到"的最长时间。超时不算失败，只是拿不到确认。
const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 全量哈希的体积上限：超过则用快速指纹（避免大文件反复全量摘要）。
pub const FULL_HASH_LIMIT: u64 = 64 * 1024 * 1024;
const SAMPLE: usize = 1024 * 1024;
const SIDECAR_SUFFIX: &str = ".twinmeta";
const PART_SUFFIX: &str = ".part";

// ---------------------------------------------------------------- 元数据

#[derive(Serialize, Deserialize)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    /// 续传判定用：便宜的快速指纹
    pub fingerprint: String,
    /// 完整性校验用：整文件 SHA-256（hex）
    pub sha256: String,
}

#[derive(Serialize, Deserialize)]
struct Sidecar {
    fingerprint: String,
    size: u64,
}

fn sidecar_path(final_path: &Path) -> PathBuf {
    let mut p = final_path.as_os_str().to_os_string();
    p.push(SIDECAR_SUFFIX);
    PathBuf::from(p)
}

fn part_path(final_path: &Path) -> PathBuf {
    let mut p = final_path.as_os_str().to_os_string();
    p.push(PART_SUFFIX);
    PathBuf::from(p)
}

fn write_sidecar(final_path: &Path, size: u64, fingerprint: &str) -> Result<()> {
    let sc = Sidecar { fingerprint: fingerprint.to_string(), size };
    let json = serde_json::to_string(&sc)?;
    std::fs::write(sidecar_path(final_path), json).context("写入续传元数据失败")?;
    Ok(())
}

fn read_sidecar(final_path: &Path) -> Option<Sidecar> {
    let raw = std::fs::read_to_string(sidecar_path(final_path)).ok()?;
    serde_json::from_str::<Sidecar>(&raw).ok()
}

// ---------------------------------------------------------------- 摘要

/// 快速指纹：`sha256(size_le64 || mtime_le64 || 首 1MiB || 末 1MiB)`。
pub fn quick_fingerprint(path: &Path, size: u64, mtime_ms: i64) -> Result<String> {
    let meta = std::fs::metadata(path).context("读取文件元信息失败")?;
    let size = size.min(meta.len());
    let mut h = Sha256::new();
    h.update(size.to_le_bytes());
    h.update(mtime_ms.to_le_bytes());

    use std::io::{Read, Seek};
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; SAMPLE];
    let head = (size as usize).min(SAMPLE);
    if head > 0 {
        f.read_exact(&mut buf[..head])?;
        h.update(&buf[..head]);
    }
    if size as usize > SAMPLE {
        f.seek(SeekFrom::End(-(SAMPLE as i64)))?;
        f.read_exact(&mut buf[..SAMPLE])?;
        h.update(&buf[..SAMPLE]);
    }
    Ok(hex::encode(h.finalize()))
}

/// 整文件 SHA-256（hex）。
pub fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).context("打开文件做完整性校验失败")?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn mtime_ms(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

/// 组装发送侧元数据（顺带算好指纹与整文件摘要）。
///
/// `display` 为 `Some` 时用它当对端看到的名字，否则取源路径的 `file_name()`。
pub fn build_meta_named(path: &Path, display: Option<&str>) -> Result<FileMeta> {
    let size = std::fs::metadata(path)?.len();
    let name = match display {
        Some(n) if !n.trim().is_empty() => n.to_string(),
        _ => path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into()),
    };
    let mtime = mtime_ms(path);
    let fingerprint = if size <= FULL_HASH_LIMIT {
        sha256_file(path)?
    } else {
        quick_fingerprint(path, size, mtime)?
    };
    let digest = if size <= FULL_HASH_LIMIT {
        fingerprint.clone()
    } else {
        sha256_file(path)?
    };
    Ok(FileMeta { name, size, fingerprint, sha256: digest })
}

/// 组装发送侧元数据（名字取源路径的 `file_name()`）。
pub fn build_meta(path: &Path) -> Result<FileMeta> {
    build_meta_named(path, None)
}

// ---------------------------------------------------------------- 发送

/// 发送文件；`on_progress(sent, total)` 用于回报进度。
///
/// `addr` 用 [`EndpointAddr`] 而非裸 EndpointId：除了身份，还可以直接携带
/// 已知的对端地址（局域网 IP、中继 URL），省掉一次地址发现、也便于离线环境测试。
/// 只有 EndpointId 时写 `id.into()` 即可。
// 主要在集成测试中使用；非测试构建会报 dead_code，这里显式放行。
#[allow(dead_code)]
pub async fn send_file<F>(
    endpoint: &iroh::Endpoint,
    addr: EndpointAddr,
    alpn: &[u8],
    path: &Path,
    opts: &SendOptions,
    on_progress: F,
) -> Result<String>
where
    F: FnMut(u64, u64),
{
    let conn = crate::net::connect_peer(endpoint, addr, alpn, opts.wait_direct).await?;
    send_on_conn(&conn, path, opts, on_progress).await
}

/// 在已建立的连接上发送一个文件。
///
/// 与拨号分开，是为了让调用方有机会先拿到通路信息（直连 / 中继）再决定怎么提示用户。
pub async fn send_on_conn<F>(
    conn: &Connection,
    path: &Path,
    opts: &SendOptions,
    mut on_progress: F,
) -> Result<String>
where
    F: FnMut(u64, u64),
{
    let meta = build_meta_named(path, opts.name.as_deref())?;
    let (mut send, mut recv) = conn.open_bi().await.context("打开数据通道失败")?;

    let meta_json = serde_json::to_vec(&meta)?;
    send.write_all(&(meta_json.len() as u32).to_le_bytes()).await?;
    send.write_all(&meta_json).await?;

    // 对端告知续传起点
    let mut off_buf = [0u8; 8];
    recv.read_exact(&mut off_buf).await.context("未收到续传起点")?;
    let offset = u64::from_le_bytes(off_buf).min(meta.size);

    let mut file = tokio::fs::File::open(path).await?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset)).await?;
    }
    let mut sent = offset;
    let mut buf = vec![0u8; CHUNK];
    loop {
        if opts.cancelled() {
            anyhow::bail!("已取消发送");
        }
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await?;
        sent += n as u64;
        on_progress(sent, meta.size);
    }
    send.shutdown().await?;

    // 等待对端校验结果。
    // 注意 1：iroh 的 RecvStream 自带 `read_to_end(limit: usize)` 同名方法，
    //        直接写 recv.read_to_end(&mut v) 会命中它而报类型不匹配，这里显式走 tokio 的 trait 方法。
    // 注意 2：拿不到确认不等于传输失败——对端可能收完就把程序关了，缓冲区里的 OK 来不及发出。
    //        数据已经完整送达，如实标注"未收到确认"，而不是报成错误。
    let ack: Option<String> = match tokio::time::timeout(ACK_TIMEOUT, async {
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    })
    .await
    {
        Ok(Ok(buf)) => Some(String::from_utf8_lossy(&buf).to_string()),
        _ => None,
    };

    match ack {
        Some(a) if a.starts_with("OK") => {
            Ok(format!("发送完成：{}（{} 字节）", meta.name, meta.size))
        }
        Some(a) => Err(anyhow::anyhow!("对方未通过校验：{}", a)),
        None => Ok(format!(
            "数据已全部送达：{}（{} 字节），但未收到对方确认",
            meta.name, meta.size
        )),
    }
}

// ---------------------------------------------------------------- 接收

/// 一个连接上连续空转多久就收工（秒）。
///
/// 打洞是有成本的：拨一次号要走地址发现、中继握手、UDP 穿透，慢的时候好几秒。
/// 连着发第二个文件时重走一遍纯属浪费，所以接收侧传完后会继续守着这条连接，
/// 撑到下一次发送到来；太久没动静再释放，免得白占资源。
pub const SESSION_IDLE: Duration = Duration::from_secs(120);

/// 接收一个文件（连接由调用方持有，可继续复用）。
// 生产路径走 handle_session，这两个入口主要给测试与一次性场景用。
#[allow(dead_code)]
pub async fn handle_one(
    conn: &Connection,
    save_dir: &Path,
    cancel: Option<Arc<AtomicBool>>,
    on_progress: impl FnMut(&str, u64, u64),
) -> Result<String> {
    let (send, recv) = conn.accept_bi().await.context("接受数据通道失败")?;
    handle_stream(send, recv, save_dir, cancel, on_progress).await
}

/// 独立连接模式：收完一个文件就随连接一起释放（测试与一次性场景用）。
#[allow(dead_code)]
pub async fn handle_incoming_with(
    conn: Connection,
    save_dir: &Path,
    cancel: Option<Arc<AtomicBool>>,
    on_progress: impl FnMut(&str, u64, u64),
) -> Result<String> {
    handle_one(&conn, save_dir, cancel, on_progress).await
}

/// 在同一条连接上连续接收多个文件，直到对端不再发或空闲超时。
///
/// 配合发送侧的连接复用，实现"一次打洞、多次传输"。
/// 返回成功接收的文件数；一个都没收到时把首个错误抛出去。
pub async fn handle_session(
    conn: &Connection,
    save_dir: &Path,
    cancel: Option<Arc<AtomicBool>>,
    on_progress: impl FnMut(&str, u64, u64),
    on_file: impl FnMut(String),
) -> Result<usize> {
    handle_session_idle(conn, save_dir, SESSION_IDLE, cancel, on_progress, on_file).await
}

/// 与 [`handle_session`] 相同，但空闲时长可指定（测试用短超时，免得干等）。
pub async fn handle_session_idle(
    conn: &Connection,
    save_dir: &Path,
    idle: Duration,
    cancel: Option<Arc<AtomicBool>>,
    mut on_progress: impl FnMut(&str, u64, u64),
    mut on_file: impl FnMut(String),
) -> Result<usize> {
    let mut files = 0usize;
    loop {
        if cancel
            .as_ref()
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            if files == 0 {
                anyhow::bail!("已取消接收");
            }
            break;
        }
        match tokio::time::timeout(idle, conn.accept_bi()).await {
            Ok(Ok((send, recv))) => {
                let msg =
                    handle_stream(send, recv, save_dir, cancel.clone(), &mut on_progress).await?;
                files += 1;
                on_file(msg);
            }
            Ok(Err(e)) => {
                if files == 0 {
                    return Err(e).context("接受数据通道失败");
                }
                break; // 连接断了，已收的文件照算
            }
            Err(_) => break, // 空闲超时，正常收工
        }
    }
    Ok(files)
}

/// 接收单个双向流：`元数据 → 回续传起点 → 收数据 → 校验 → 回执`。
async fn handle_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    save_dir: &Path,
    cancel: Option<Arc<AtomicBool>>,
    mut on_progress: impl FnMut(&str, u64, u64),
) -> Result<String> {
    // 1) 元数据
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 {
        anyhow::bail!("元数据长度异常：{}", len);
    }
    let mut meta_buf = vec![0u8; len];
    recv.read_exact(&mut meta_buf).await?;
    let meta: FileMeta = serde_json::from_slice(&meta_buf).context("解析元数据失败")?;

    // 2) 落盘路径：安全校验 + 不覆盖已有文件
    validate_relative(&meta.name).map_err(|e| anyhow::anyhow!("文件名非法：{}", e))?;
    let safe = sanitize_relative(&meta.name);
    let mut final_path = save_dir.join(&safe);
    if final_path.exists() {
        final_path = unique_path(save_dir, &safe);
    }
    if !is_inside(save_dir, &final_path) {
        anyhow::bail!("目标路径越出下载目录");
    }
    // 名字里可能带子目录（传整个文件夹时）：先把父目录建出来，
    // 否则后面的 rename 会撞"系统找不到指定的路径"。
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).context("创建接收子目录失败")?;
    }
    let part = part_path(&final_path);
    if !is_inside(save_dir, &part) {
        anyhow::bail!("临时文件路径越出下载目录");
    }

    // 3) 续传判定：sidecar 指纹一致才续
    let sidecar_ok = read_sidecar(&final_path)
        .map(|sc| sc.fingerprint == meta.fingerprint)
        .unwrap_or(false);
    let resume: u64 = if sidecar_ok && part.exists() {
        std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0)
    } else {
        let _ = std::fs::remove_file(&part);
        0
    }
    .min(meta.size);

    // 立刻回续传起点，并落 sidecar（进程中断后仍可续）
    send.write_all(&resume.to_le_bytes()).await?;
    write_sidecar(&final_path, meta.size, &meta.fingerprint)?;

    // 4) 收数据写入 .part，同时流式累计 SHA-256
    //    —— 边收边算，收完即校验，避免落盘后再把整个文件重读一遍
    //       （传 10GB 文件时那就是两次完整磁盘读取，I/O 直接翻倍）。
    let mut hasher = Sha256::new();
    if resume > 0 {
        // 续传：先把已落盘的 .part 前 resume 字节喂进 hasher，
        // 保证最终哈希覆盖的是"完整文件"，而不是只覆盖这一段的增量。
        let mut seeded = 0u64;
        let mut f = std::fs::File::open(&part).context("读取续传基线失败")?;
        let mut sbuf = vec![0u8; CHUNK];
        while seeded < resume {
            let want = ((resume - seeded) as usize).min(CHUNK);
            let n = std::io::Read::read(&mut f, &mut sbuf[..want])
                .context("读取续传基线失败")?;
            if n == 0 {
                break;
            }
            hasher.update(&sbuf[..n]);
            seeded += n as u64;
        }
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&part)
        .await
        .context("无法创建落盘文件")?;
    if resume > 0 {
        file.seek(SeekFrom::Start(resume)).await?;
    }
    let mut received = resume;
    let mut buf = vec![0u8; CHUNK];
    while let Some(n) = recv.read(&mut buf).await? {
        // iroh 的 read 用 Option 表示流结束；某些实现会先给 Some(0) 再给 None，
        // 这里的 n == 0 兜底是必须的，否则空转打满一个核。
        if n == 0 {
            break;
        }
        if cancel
            .as_ref()
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            anyhow::bail!("已取消接收");
        }
        file.write_all(&buf[..n]).await?;
        hasher.update(&buf[..n]);
        received += n as u64;
        on_progress(&meta.name, received, meta.size);
    }
    file.flush().await?;
    // 拿回 std 的 File 再同步 drop：tokio 的 File 是在阻塞线程池里异步关闭句柄的，
    // 直接 drop 就 rename 在 Windows 上会撞 "文件被占用"。
    let std_file = file.into_std().await;
    drop(std_file);

    // 5) 完整性校验 → 转正 or 删除
    if received != meta.size {
        let _ = send.write_all(format!("ERR:大小不符 {}≠{}", received, meta.size).as_bytes()).await;
        anyhow::bail!("大小不符：收到 {} / 应为 {}", received, meta.size);
    }
    // 流式哈希已经覆盖了全部收到字节（含续传基线），直接收口比较。
    let actual = hex::encode(hasher.finalize());
    if actual != meta.sha256 {
        let _ = std::fs::remove_file(&part);
        let _ = send.write_all(format!("ERR:SHA256 不一致").as_bytes()).await;
        anyhow::bail!("完整性校验失败，已删除损坏文件");
    }
    std::fs::rename(&part, &final_path).context("转正文件失败")?;
    let _ = std::fs::remove_file(sidecar_path(&final_path));
    // 注意：write_all 只是把 OK 放进流缓冲，真正发出去要靠连接驱动轮询。
    // 调用方必须保证 handle_incoming 返回后 Endpoint 仍存活一小段时间，
    // 否则 ack 会随连接一起消失，发送方只能看到"连接丢失"。
    send.write_all(b"OK").await?;
    send.shutdown().await?;

    Ok(format!(
        "已接收：{}（{} 字节）→ {}",
        meta.name,
        meta.size,
        final_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{Endpoint, RelayMode, TransportAddr, endpoint::presets};
    use std::net::SocketAddr;

    const TEST_ALPN: &[u8] = b"twimstar/test";

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("twimstar-test-{tag}-{}", now_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    async fn endpoint_pair() -> (iroh::Endpoint, iroh::Endpoint) {
        // 关掉中继，测试只依赖本机回环，不碰外网。
        let a = Endpoint::builder(presets::N0)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let b = Endpoint::builder(presets::N0)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        (a, b)
    }

    /// 拿出服务端绑定的 UDP 端口，拼成可直接拨号的回环地址。
    ///
    /// 关掉中继后没有任何地址发现渠道，必须显式给地址，否则 `connect` 会报
    /// "No addressing information available"。绑定出来的 0.0.0.0 不能当目标，
    /// 需要换成 127.0.0.1。
    fn loopback_addr(ep: &iroh::Endpoint) -> EndpointAddr {
        let mut socks = ep.bound_sockets();
        socks.sort();
        let pick = socks
            .into_iter()
            .find(|a| a.is_ipv4())
            .or_else(|| ep.bound_sockets().into_iter().next())
            .expect("端点至少绑定了一个 socket");
        let ip = if pick.ip().is_unspecified() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            pick.ip()
        };
        EndpointAddr::from_parts(ep.id(), [TransportAddr::Ip(SocketAddr::new(ip, pick.port()))])
    }

    #[test]
    fn fingerprint_is_content_sensitive() {
        let dir = scratch("fp");
        let p = dir.join("a.bin");
        std::fs::write(&p, vec![1u8; 4096]).unwrap();
        let f1 = quick_fingerprint(&p, 4096, 123).unwrap();
        std::fs::write(&p, vec![2u8; 4096]).unwrap();
        let f2 = quick_fingerprint(&p, 4096, 123).unwrap();
        assert_ne!(f1, f2);

        // 空文件的 SHA-256 是固定值，用来钉死实现没有吞掉字节。
        let empty = dir.join("empty.bin");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            sha256_file(&empty).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// 完整往返：小文件一次传完，落盘内容与源文件逐字节一致。
    #[tokio::test]
    async fn roundtrip_transfers_identical_bytes() {
        let dir = scratch("roundtrip");
        let src = dir.join("payload.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let (server, client) = endpoint_pair().await;
        let addr = loopback_addr(&server);
        let save = scratch("roundtrip-save");
        let save_for_task = save.clone();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let r = handle_incoming_with(conn, &save_for_task, None, |_, _, _| {}).await;
            // 见 handle_incoming 末尾的说明：ack 要靠连接驱动轮询才发出去，
            // 这里留一点时间再丢弃端点，否则发送方永远等不到 OK。
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(server);
            r
        });

        let mut ticks = 0u64;
        let msg = send_file(&client, addr, TEST_ALPN, &src, &SendOptions::default(), |_, _| ticks += 1).await;
        assert!(msg.is_ok(), "发送侧报错：{msg:?}");
        let recv = server_task.await.unwrap();
        assert!(recv.is_ok(), "接收侧报错：{recv:?}");
        assert!(ticks > 0, "进度回调应当被触发");

        let got = std::fs::read_dir(&save)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("payload"))
            .expect("应产生落盘文件")
            .path();
        assert_eq!(std::fs::read(&got).unwrap(), data);
        assert!(!got.to_string_lossy().ends_with(".part"), "临时文件未转正");
    }

    /// 断点续传：预先写好前半段 .part + 匹配的 sidecar，只应传后半段且结果正确。
    #[tokio::test]
    async fn resumes_from_existing_part() {
        let dir = scratch("resume");
        let src = dir.join("big.bin");
        let data: Vec<u8> = (0..500_000u32).map(|i| (i % 97) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let half = data.len() / 2;
        let save = scratch("resume-save");
        let final_path = save.join("big.bin");
        let part = part_path(&final_path);
        std::fs::write(&part, &data[..half]).unwrap();

        let meta = build_meta(&src).unwrap();
        write_sidecar(&final_path, meta.size, &meta.fingerprint).unwrap();

        let (server, client) = endpoint_pair().await;
        let addr = loopback_addr(&server);

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let r = handle_incoming_with(conn, &save, None, |_, _, _| {}).await;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(server);
            r
        });

        send_file(&client, addr, TEST_ALPN, &src, &SendOptions::default(), |_, _| {})
            .await
            .expect("续传发送应成功");
        server_task.await.unwrap().expect("续传接收应成功");

        assert_eq!(std::fs::read(&final_path).unwrap(), data, "续传结果应完整一致");
        assert!(!part.exists(), "转正后 .part 应被移走");
        assert!(
            !sidecar_path(&final_path).exists(),
            "成功后 sidecar 应被清理"
        );
    }

    /// 一次打洞、连传两个文件：第二条必须走同一条连接，不再重新拨号。
    ///
    /// 这是"连接复用"的核心回归——如果哪天 handle_session 退化成只收一个就返回，
    /// 第二个文件会静静丢掉，这个测试会挂。
    #[tokio::test]
    async fn session_receives_two_files_on_one_connection() {
        let dir = scratch("session");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, vec![7u8; 120_000]).unwrap();
        std::fs::write(&b, vec![9u8; 80_000]).unwrap();

        let (server, client) = endpoint_pair().await;
        let addr = loopback_addr(&server);
        let save = scratch("session-save");

        let save_for_task = save.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let r = handle_session_idle(
                &conn,
                &save_for_task,
                std::time::Duration::from_secs(15),
                None,
                |_, _, _| {},
                |_| {},
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(server);
            r
        });

        // 两个文件走同一条连接：只拨号一次。
        let conn = crate::net::connect_peer(&client, addr, TEST_ALPN, Duration::ZERO)
            .await
            .expect("应能连上");
        send_on_conn(&conn, &a, &SendOptions::default(), |_, _| {})
            .await
            .expect("第一个文件应发送成功");
        send_on_conn(&conn, &b, &SendOptions::default(), |_, _| {})
            .await
            .expect("第二个文件应发送成功");
        // 关掉连接，让接收侧的等待立即结束，不必耗到空闲超时。
        conn.close(0u32.into(), b"done");
        drop(conn);

        let got = server_task.await.unwrap().expect("接收会话应正常结束");
        assert_eq!(got, 2, "一条连接上应收到 2 个文件，实际 {got}");
        assert_eq!(std::fs::read(save.join("a.bin")).unwrap(), vec![7u8; 120_000]);
        assert_eq!(std::fs::read(save.join("b.bin")).unwrap(), vec![9u8; 80_000]);
    }

    /// 损坏的半成品：sidecar 指纹对不上时必须丢弃重传，不能续在错误数据后面。
    #[tokio::test]
    async fn mismatched_sidecar_forces_restart() {
        let dir = scratch("mismatch");
        let src = dir.join("m.bin");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 31) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let save = scratch("mismatch-save");
        let final_path = save.join("m.bin");
        //  garbage 内容 + 假指纹
        std::fs::write(part_path(&final_path), vec![0xAAu8; 1000]).unwrap();
        write_sidecar(&final_path, data.len() as u64, "stale-fingerprint").unwrap();

        let (server, client) = endpoint_pair().await;
        let addr = loopback_addr(&server);
        let save2 = save.clone();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let r = handle_incoming_with(conn, &save2, None, |_, _, _| {}).await;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(server);
            r
        });

        send_file(&client, addr, TEST_ALPN, &src, &SendOptions::default(), |_, _| {})
            .await
            .expect("发送应成功");
        server_task.await.unwrap().expect("接收应成功");

        assert_eq!(
            std::fs::read(&final_path).unwrap(),
            data,
            "指纹不匹配时应当从头重传，结果仍须正确"
        );
    }
}
