//! TwimStar v0.6 — Tauri 2 版（WebView2 UI + iroh 网络层）
//! 局域网直连 / 跨网打洞 / 中继兜底，全程零服务器零账号。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey, endpoint::presets};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"twimstar/demo/1";
const CHUNK: usize = 256 * 1024;

// ---------------- 全局状态 ----------------

static SAVE_DIR: OnceLock<Arc<Mutex<String>>> = OnceLock::new();
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

fn save_dir() -> Arc<Mutex<String>> {
    SAVE_DIR.get().unwrap().clone()
}

fn default_save_dir() -> String {
    std::env::var("USERPROFILE")
        .map(|h| format!("{h}\\Downloads"))
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().display().to_string())
}

// ---------------- 网络层 ----------------

fn human_size(n: u64) -> String {
    let n = n as f64;
    if n >= 1_073_741_824.0 { format!("{:.2} GB", n / 1_073_741_824.0) }
    else if n >= 1_048_576.0 { format!("{:.2} MB", n / 1_048_576.0) }
    else if n >= 1024.0 { format!("{:.1} KB", n / 1024.0) }
    else { format!("{n} B") }
}

async fn build_endpoint() -> Result<Endpoint> {
    Ok(Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await?)
}

#[derive(Serialize, Clone)]
struct RecvProgress {
    name: String,
}

async fn send_file(app: AppHandle, id: EndpointId, path: PathBuf, endpoint: Endpoint) {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let result: Result<String> = async {
        let total = tokio::fs::metadata(&path).await?.len();
        let mut file = tokio::fs::File::open(&path).await?;
        let t0 = Instant::now();
        let conn = endpoint.connect(id, ALPN).await?;
        let connect_ms = t0.elapsed().as_millis();
        let (mut send, mut recv) = conn.open_bi().await?;
        let name_bytes = name.as_bytes();
        send.write_all(&(name_bytes.len() as u32).to_le_bytes()).await?;
        send.write_all(name_bytes).await?;
        let mut sent: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 { break; }
            send.write_all(&buf[..n]).await?;
            sent += n as u64;
            let pct = (sent as f32 / total as f32 * 1000.0).round() / 10.0;
            let _ = app.emit("send-progress", pct);
        }
        send.shutdown().await?;
        let ack = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv.read_to_end(16),
        )
        .await;
        let elapsed = t0.elapsed();
        let speed = human_size((total as f64 / elapsed.as_secs_f64().max(1e-9)) as u64);
        let ack_note = match ack {
            Ok(Ok(b)) if b == b"OK" => "对方已确认".to_string(),
            _ => "数据已全部送达（确认包未收到）".to_string(),
        };
        Ok(format!(
            "✅ 发送完成: {name} ({}) / 连接 {connect_ms}ms / 传输 {:.1?} / {speed}/s / {ack_note}",
            human_size(total),
            elapsed
        ))
    }
    .await;
    match result {
        Ok(msg) => {
            let _ = app.emit("send-done", &msg);
        }
        Err(e) => {
            let _ = app.emit("send-done", "");
            let _ = app.emit("log", format!("❌ 发送失败: {e:#}"));
        }
    }
}

async fn handle_incoming(app: AppHandle, conn: iroh::endpoint::Connection) {
    let result: Result<String> = async {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let name_len = u32::from_le_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        recv.read_exact(&mut name_buf).await?;
        let name = String::from_utf8_lossy(&name_buf).to_string();
        let _ = app.emit("recv-progress", RecvProgress { name: name.clone() });
        let dir = save_dir().lock().unwrap().clone();
        let out_path = PathBuf::from(&dir).join(&name);
        let mut out = tokio::fs::File::create(&out_path).await?;
        let mut received: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        let t0 = Instant::now();
        loop {
            let Some(n) = recv.read(&mut buf).await? else { break };
            out.write_all(&buf[..n]).await?;
            received += n as u64;
        }
        out.flush().await?;
        send.write_all(b"OK").await?;
        send.shutdown().await?;
        let elapsed = t0.elapsed();
        let speed = human_size((received as f64 / elapsed.as_secs_f64().max(1e-9)) as u64);
        Ok(format!(
            "📥 收到: {} ({}) -> {} / {:.1?} / {speed}/s",
            name,
            human_size(received),
            out_path.display(),
            elapsed
        ))
    }
    .await;
    match result {
        Ok(msg) => {
            let _ = app.emit("recv-done", &msg);
        }
        Err(e) => {
            let _ = app.emit("log", format!("❌ 接收失败: {e:#}"));
        }
    }
}

// ---------------- Tauri 命令 ----------------

#[tauri::command]
fn pick_file() -> Option<String> {
    rfd::FileDialog::new()
        .pick_file()
        .map(|p| p.display().to_string())
}

#[tauri::command]
fn pick_folder() -> Option<String> {
    if let Some(p) = rfd::FileDialog::new().pick_folder() {
        let dir = p.display().to_string();
        *save_dir().lock().unwrap() = dir.clone();
        return Some(dir);
    }
    None
}

#[tauri::command]
fn start_send(app: AppHandle, peer_id: String, path: String) -> Result<(), String> {
    let Some(endpoint) = ENDPOINT.get() else {
        return Err("网络尚未就绪，请稍候".to_string());
    };
    let id: EndpointId = peer_id
        .trim()
        .parse()
        .map_err(|_| "对方连接码格式不对（应为 64 位十六进制）".to_string())?;
    let p = PathBuf::from(path.trim());
    if path.trim().is_empty() || !p.is_file() {
        return Err("请先选择一个有效文件".to_string());
    }
    let endpoint = endpoint.clone();
    tauri::async_runtime::spawn(async move {
        send_file(app, id, p, endpoint).await;
    });
    Ok(())
}

#[tauri::command]
fn get_save_dir() -> String {
    save_dir().lock().unwrap().clone()
}

// ---------------- 入口 ----------------

fn main() {
    let _ = SAVE_DIR.set(Arc::new(Mutex::new(default_save_dir())));

    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    match build_endpoint().await {
                        Ok(endpoint) => {
                            let id = endpoint.id().to_string();
                            let _ = ENDPOINT.set(endpoint.clone());
                            let _ = handle.emit("net-ready", &id);
                            loop {
                                let Some(incoming) = endpoint.accept().await else { break };
                                let app2 = handle.clone();
                                match incoming.accept() {
                                    Ok(accepting) => {
                                        tokio::spawn(async move {
                                            match accepting.await {
                                                Ok(conn) => handle_incoming(app2, conn).await,
                                                Err(e) => {
                                                    let _ = app2.emit("log", format!("连接失败: {e:#}"));
                                                }
                                            }
                                        });
                                    }
                                    Err(_) => continue,
                                }
                            }
                        }
                        Err(e) => {
                            let _ = handle.emit("log", format!("网络初始化失败: {e:#}"));
                        }
                    }
                });
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_file,
            pick_folder,
            start_send,
            get_save_dir
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
