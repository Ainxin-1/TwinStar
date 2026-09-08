//! TwimStar v0.8 — Tauri 2 版（WebView2 UI + iroh QUIC 网络层）
//!
//! 分层：
//!   - [`core`]     纯逻辑层（自 TwinStar v4.0.1 移植）：路径安全 / 密码学 / 设备身份 / 帧格式
//!   - [`net`]      网络层：打洞参数调优 / 通路判定 / 网络环境自检
//!   - [`transfer`] 传输层：iroh QUIC + 断点续传 + 落盘完整性校验
//!   - 本文件       Tauri 命令与事件桥接，只做"把进度和通路转发给 UI"
//!
//! 局域网直连 / 跨网打洞 / 中继兜底，全程零服务器零账号。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use iroh::{Endpoint, EndpointId};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::core::identity::DeviceIdentity;
use crate::core::path::format_size;
use crate::net::ALPN;
use crate::transfer::SendOptions;

mod core;
mod net;
mod transfer;

/// 进度事件节流间隔：QUIC 每 1MiB 一个回调，全量转发会把 WebView 刷爆。
const PROGRESS_THROTTLE: Duration = Duration::from_millis(60);

/// 小于这个体积就不值得等打洞了 —— 等待的时间比传输本身还长。
const WORTH_WAITING_SIZE: u64 = 2 * 1024 * 1024;

// ---------------- 全局状态 ----------------

static SAVE_DIR: OnceLock<Arc<Mutex<String>>> = OnceLock::new();
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();
/// 取消标志。UI 同一时刻只有一个传输在跑，一把全局开关足够。
static CANCEL: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn save_dir() -> Arc<Mutex<String>> {
    SAVE_DIR.get().unwrap().clone()
}

fn cancel_flag() -> Arc<AtomicBool> {
    CANCEL.get_or_init(|| Arc::new(AtomicBool::new(false))).clone()
}

fn default_save_dir() -> String {
    std::env::var("USERPROFILE")
        .map(|h| format!("{h}\\Downloads"))
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().display().to_string())
}

// ---------------- 网络层 ----------------

/// 端点密钥由设备身份派生，因此"我的连接码"跨重启固定。
async fn build_endpoint() -> Result<Endpoint> {
    let seed = DeviceIdentity::load_or_create().derive_endpoint_seed();
    net::build_endpoint(seed).await
}

// ---------------- 事件载荷 ----------------

#[derive(Serialize, Clone)]
struct ProgressView {
    name: String,
    pct: f32,
    sent: u64,
    total: u64,
    /// 字节/秒
    speed: u64,
    /// 预计剩余秒数
    eta: u32,
}

/// 滑动窗口速率表：取最近 800ms 的斜率，比"总量/总时长"更能反映当下网速。
struct Meter {
    samples: std::collections::VecDeque<(Instant, u64)>,
}

impl Meter {
    fn new() -> Self {
        Self { samples: std::collections::VecDeque::with_capacity(64) }
    }

    fn update(&mut self, done: u64) -> f64 {
        let now = Instant::now();
        self.samples.push_back((now, done));
        while self.samples.len() > 2
            && now.duration_since(self.samples.front().unwrap().0) > Duration::from_millis(800)
        {
            self.samples.pop_front();
        }
        let Some((t0, b0)) = self.samples.front().copied() else {
            return 0.0;
        };
        let dt = now.duration_since(t0).as_secs_f64();
        if dt < 0.05 {
            return 0.0;
        }
        ((done - b0) as f64 / dt).max(0.0)
    }
}

/// 节流器：只在间隔到达或收尾时放行一次。
struct Throttle {
    last: Instant,
}

impl Throttle {
    fn new() -> Self {
        Self { last: Instant::now() }
    }
    fn ready(&mut self, force: bool) -> bool {
        if force || self.last.elapsed() >= PROGRESS_THROTTLE {
            self.last = Instant::now();
            true
        } else {
            false
        }
    }
}

fn pct(done: u64, total: u64) -> f32 {
    if total == 0 {
        return 100.0;
    }
    ((done as f32 / total as f32) * 1000.0).round() / 10.0
}

fn eta_secs(sent: u64, total: u64, speed: f64) -> u32 {
    if speed < 1024.0 || sent >= total {
        return 0;
    }
    ((total - sent) as f64 / speed).ceil().min(99_999.0) as u32
}

// ---------------- 发送 / 接收 ----------------

/// 发送包装：拨号 → 判定通路 → [`transfer::send_on_conn`]，把进度转成 UI 事件。
async fn do_send(app: AppHandle, endpoint: Endpoint, id: EndpointId, path: PathBuf) {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    let flag = cancel_flag();
    flag.store(false, Ordering::Relaxed);
    let opts = SendOptions {
        wait_direct: if size >= WORTH_WAITING_SIZE {
            net::DEFAULT_WAIT_DIRECT
        } else {
            Duration::ZERO
        },
        cancel: Some(flag.clone()),
    };

    let t0 = Instant::now();
    let conn = match net::connect_peer(&endpoint, id.into(), ALPN, opts.wait_direct).await {
        Ok(c) => c,
        Err(e) => {
            let _ = app.emit("send-done", "");
            let _ = app.emit("log", format!("❌ 发送失败：{e:#}"));
            return;
        }
    };

    let view = net::describe(&conn);
    let _ = app.emit("conn-info", &view);
    let _ = app.emit(
        "log",
        format!("🔗 通路：{} {}（RTT {} ms）", view.label, view.detail, view.rtt_ms),
    );
    if view.kind != net::PathKind::Direct && opts.wait_direct.is_zero() {
        let _ = app.emit("log", "ℹ️ 正在后台尝试打洞，成功会自动切到直连");
    }

    let mut meter = Meter::new();
    let mut th = Throttle::new();
    let app2 = app.clone();
    let name_for_cb = name.clone();

    let outcome = transfer::send_on_conn(&conn, &path, &opts, move |sent, total| {
        let speed = meter.update(sent);
        if th.ready(sent >= total) {
            let _ = app2.emit(
                "send-progress",
                ProgressView {
                    name: name_for_cb.clone(),
                    pct: pct(sent, total),
                    sent,
                    total,
                    speed: speed as u64,
                    eta: eta_secs(sent, total, speed),
                },
            );
        }
    })
    .await;

    // 传完再看一眼通路：可能已经从"中继起步"升级成"直连"。
    let final_view = net::describe(&conn);
    let _ = app.emit("conn-info", &final_view);

    match outcome {
        Ok(msg) => {
            let elapsed = t0.elapsed().as_secs_f64().max(1e-9);
            let speed = format_size((size as f64 / elapsed) as u64);
            let text = format!(
                "✅ 发送完成：{name}（{}）/ 耗时 {:.1?} / {speed}/s / {}\n通路：{} {}",
                format_size(size),
                t0.elapsed(),
                msg,
                final_view.label,
                final_view.detail
            );
            let _ = app.emit("send-done", &text);
            let _ = app.emit("log", &text);
        }
        Err(e) => {
            let _ = app.emit("send-done", "");
            let _ = app.emit("log", format!("❌ 发送失败：{e:#}"));
        }
    }
}

/// 接收包装：调 [`transfer::handle_incoming_with`]，把进度与结果转成 UI 事件。
async fn do_recv(app: AppHandle, conn: iroh::endpoint::Connection, dir: PathBuf) {
    let view = net::describe(&conn);
    let _ = app.emit("conn-info", &view);

    let mut th = Throttle::new();
    let mut meter = Meter::new();
    let mut started_at: Option<Instant> = None;
    let app2 = app.clone();
    let flag = cancel_flag();
    // 上一个任务可能留了取消标记，接收开始前先清掉。
    flag.store(false, Ordering::Relaxed);

    let outcome = transfer::handle_incoming_with(
        conn,
        Path::new(&dir),
        Some(flag),
        |name, got, total| {
            if started_at.is_none() {
                started_at = Some(Instant::now());
            }
            let speed = meter.update(got);
            if th.ready(got >= total) {
                let _ = app2.emit(
                    "recv-progress",
                    ProgressView {
                        name: name.to_string(),
                        pct: pct(got, total),
                        sent: got,
                        total,
                        speed: speed as u64,
                        eta: eta_secs(got, total, speed),
                    },
                );
            }
        },
    )
    .await;

    match outcome {
        Ok(msg) => {
            let note = match started_at {
                Some(t) => format!(" / 耗时 {:.1?}", t.elapsed()),
                None => String::new(),
            };
            let text = format!("📥 {msg}{note}");
            let _ = app.emit("recv-done", &text);
            let _ = app.emit("log", &text);
        }
        Err(e) => {
            let _ = app.emit("recv-done", "");
            let _ = app.emit("log", format!("❌ 接收失败：{e:#}"));
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
fn get_save_dir() -> String {
    save_dir().lock().unwrap().clone()
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
        do_send(app, endpoint, id, p).await;
    });
    Ok(())
}

/// 取消当前传输。已落盘的部分会留在 `.part` 里，下次重发可续传。
#[tauri::command]
fn cancel_send() {
    cancel_flag().store(true, Ordering::Relaxed);
}

/// 重新做一次网络自检，结果通过 `net-diag` 事件推给前端。
#[tauri::command]
fn refresh_diag(app: AppHandle) {
    let Some(endpoint) = ENDPOINT.get() else { return };
    let endpoint = endpoint.clone();
    tauri::async_runtime::spawn(async move {
        let diag = net::collect_diag(&endpoint).await;
        let _ = app.emit("net-diag", diag);
    });
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

                            // 开局先做一次自检：UDP 通不通、能不能打洞，用户一眼能看到。
                            let diag = net::collect_diag(&endpoint).await;
                            let _ = handle.emit("log", format!("🩺 {}，{}", diag.verdict, diag.advice));
                            let _ = handle.emit("net-diag", diag);

                            loop {
                                let Some(incoming) = endpoint.accept().await else { break };
                                let app2 = handle.clone();
                                let dir = PathBuf::from(save_dir().lock().unwrap().clone());
                                match incoming.accept() {
                                    Ok(accepting) => {
                                        tokio::spawn(async move {
                                            match accepting.await {
                                                Ok(conn) => do_recv(app2, conn, dir).await,
                                                Err(e) => {
                                                    let _ = app2.emit(
                                                        "log",
                                                        format!("连接失败：{e:#}"),
                                                    );
                                                }
                                            }
                                        });
                                    }
                                    Err(_) => continue,
                                }
                            }
                        }
                        Err(e) => {
                            let _ = handle.emit("log", format!("网络初始化失败：{e:#}"));
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
            cancel_send,
            refresh_diag,
            get_save_dir
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
