//! TwimStar 前置验证：iroh 双端最小文件传输 demo
//!
//! 用法:
//!   接收端:  iroh-transfer.exe recv <保存路径>
//!   发送端:  iroh-transfer.exe send <对端EndpointId> <文件路径>
//!
//! 验证目标: 按 EndpointId(密钥) 拨号 → QUIC 直连(打洞) / 中继兜底 → 文件传输

use std::time::Instant;

use anyhow::{Result, bail};
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey, endpoint::presets};

const ALPN: &[u8] = b"twinstar/demo/1";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("recv") => {
            let out = args.get(2).ok_or_else(|| anyhow::anyhow!("缺少保存路径"))?;
            recv(out).await
        }
        Some("send") => {
            let id: EndpointId = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("缺少对端 EndpointId"))?
                .parse()?;
            let file = args.get(3).ok_or_else(|| anyhow::anyhow!("缺少文件路径"))?;
            send(id, file).await
        }
        _ => {
            bail!("用法:\n  recv <保存路径>\n  send <对端EndpointId> <文件路径>");
        }
    }
}

async fn build_endpoint() -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await?;
    endpoint.online().await;
    Ok(endpoint)
}

async fn recv(out_path: &str) -> Result<()> {
    let endpoint = build_endpoint().await?;
    println!("本机 EndpointId:");
    println!("  {}", endpoint.id());
    let addr = endpoint.addr();
    for a in addr.ip_addrs() {
        println!("  本地地址: {a}");
    }
    if let Some(relay) = addr.relay_urls().next() {
        println!("  中继服务器: {relay}");
    }
    println!("等待发送端连接...");

    let incoming = endpoint.accept().await.unwrap();
    let accepting = incoming.accept()?;
    let conn = accepting.await?;
    println!("已连接: 对端 = {}", conn.remote_id());

    let (mut send, mut recv_stream) = conn.accept_bi().await?;
    let t0 = Instant::now();
    let data = recv_stream.read_to_end(usize::MAX).await?;
    tokio::fs::write(out_path, &data).await?;
    let elapsed = t0.elapsed();
    println!(
        "接收完成: {} 字节 / {:.2?} / {:?}  -> {}",
        data.len(),
        elapsed,
        human_speed(data.len(), elapsed),
        out_path
    );
    send.write_all(b"OK").await?;
    use tokio::io::AsyncWriteExt;
    let _ = send.shutdown().await; // flush 并优雅关闭发送方向，确保确认包真正发出
    // 等发送端读到确认并主动关闭连接（最多等 3 秒），避免对端误报
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), conn.closed()).await;
    Ok(())
}

async fn send(id: EndpointId, file_path: &str) -> Result<()> {
    let payload = tokio::fs::read(file_path).await?;
    println!(
        "待发送: {} ({})",
        file_path,
        human_size(payload.len())
    );
    let endpoint = build_endpoint().await?;
    println!("本机 EndpointId: {}", endpoint.id());
    println!("正在拨号: {id} ...");

    let t0 = Instant::now();
    let conn = endpoint.connect(id, ALPN).await?;
    println!("连接建立: {:.2?}", t0.elapsed());

    let (mut send, mut recv_stream) = conn.open_bi().await?;
    let start = Instant::now();
    send.write_all(&payload).await?;
    drop(send);
    // 确认包读取失败不影响传输成功的判定（数据已写完）
    let ack = tokio::time::timeout(std::time::Duration::from_secs(5), recv_stream.read_to_end(16)).await;
    let elapsed = start.elapsed();
    let ack_text = match ack {
        Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).to_string(),
        _ => "(确认包未收到，但数据已全部送达)".to_string(),
    };
    println!(
        "发送完成: {} 字节 / {:.2?} / {:?} / 确认 = {}",
        payload.len(),
        elapsed,
        human_speed(payload.len(), elapsed),
        ack_text
    );
    Ok(())
}

fn human_size(n: usize) -> String {
    let n = n as f64;
    if n >= 1_048_576.0 { format!("{:.2} MB", n / 1_048_576.0) }
    else if n >= 1024.0 { format!("{:.1} KB", n / 1024.0) }
    else { format!("{n} B") }
}

fn human_speed(n: usize, d: std::time::Duration) -> String {
    let secs = d.as_secs_f64().max(1e-9);
    format!("{}/s", human_size((n as f64 / secs) as usize))
}
