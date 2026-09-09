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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use iroh::{Endpoint, EndpointId, endpoint::Connection};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::core::config::Config;
use crate::core::identity::DeviceIdentity;
use crate::core::path::format_size;
use crate::net::ALPN;
use crate::transfer::SendOptions;

mod core;
mod disc;
mod net;
mod transfer;

/// 进度事件节流间隔：QUIC 每 1MiB 一个回调，全量转发会把 WebView 刷爆。
const PROGRESS_THROTTLE: Duration = Duration::from_millis(60);

/// 小于这个体积就不值得等打洞了 —— 等待的时间比传输本身还长。
const WORTH_WAITING_SIZE: u64 = 2 * 1024 * 1024;
/// 大文件值得多等一会儿打洞：直连和中继的差距在几十 MB 以上会被明显放大。
const BIG_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// 传输过程中多久看一次通路（直连/中继可能中途切换）。
const PATH_POLL: Duration = Duration::from_secs(1);

// ---------------- 全局状态 ----------------

static SAVE_DIR: OnceLock<Arc<Mutex<String>>> = OnceLock::new();
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();
/// 取消标志。UI 同一时刻只有一个传输在跑，一把全局开关足够。
static CANCEL: OnceLock<Arc<AtomicBool>> = OnceLock::new();
/// 已建好的连接缓存（按对端 id）。打洞一次不容易，能复用就复用。
static CONNS: OnceLock<Arc<Mutex<HashMap<String, Connection>>>> = OnceLock::new();

fn save_dir() -> Arc<Mutex<String>> {
    SAVE_DIR.get().unwrap().clone()
}

fn conn_cache() -> Arc<Mutex<HashMap<String, Connection>>> {
    CONNS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

/// 取出一条还能用的连接；已经关掉的（对端退出、空闲超时）直接丢掉。
fn take_conn(id: &EndpointId) -> Option<Connection> {
    conn_cache()
        .lock()
        .unwrap()
        .remove(&id.to_string())
        .filter(|c| c.close_reason().is_none())
}

/// 还回去给下次用。连接已经死了就不留了。
fn put_conn(id: &EndpointId, conn: Connection) {
    if conn.close_reason().is_none() {
        conn_cache().lock().unwrap().insert(id.to_string(), conn);
    }
}

/// 打洞等待时长：文件越大越值得等，小文件直接走中继更快。
fn wait_direct_for(size: u64) -> Duration {
    if size >= BIG_FILE_SIZE {
        Duration::from_millis(4000)
    } else if size >= WORTH_WAITING_SIZE {
        net::DEFAULT_WAIT_DIRECT
    } else {
        Duration::ZERO
    }
}

/// 监视一条连接的通路变化：从中继升级到直连时立刻通知前端。
///
/// 打洞是后台持续进行的，2.5 秒没等到不代表永远等不到 —— 大文件传到一半
/// 通路升级是很常见的，用户应该能在顶栏看到那一刻，而不是传完才知道。
fn watch_path(app: &AppHandle, conn: &Connection) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let conn = conn.clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut last = net::describe(&conn);
        while !flag.load(Ordering::Relaxed) {
            tokio::time::sleep(PATH_POLL).await;
            if flag.load(Ordering::Relaxed) {
                break;
            }
            let now = net::describe(&conn);
            if now.kind == last.kind && now.detail == last.detail {
                continue;
            }
            let upgraded = now.kind == net::PathKind::Direct && last.kind != net::PathKind::Direct;
            last = now.clone();
            let _ = app.emit("conn-info", &now);
            if upgraded {
                let _ = app.emit(
                    "log",
                    format!("⚡ 已升级为直连 {}（RTT {} ms）", now.detail, now.rtt_ms),
                );
            }
        }
    });
    stop
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

/// 空串当 None 用，免得往日志里塞一行空白。
fn non_empty(s: &'static str) -> Option<&'static str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
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

/// 在一条连接上发一个文件，并把进度实时推给前端。
async fn send_with_progress(
    app: &AppHandle,
    conn: &Connection,
    path: &Path,
    opts: &SendOptions,
    name: &str,
) -> Result<String> {
    transfer::send_on_conn(conn, path, opts, {
        let app = app.clone();
        let name = name.to_string();
        let mut meter = Meter::new();
        let mut th = Throttle::new();
        move |sent, total| {
            let speed = meter.update(sent);
            if th.ready(sent >= total) {
                let _ = app.emit(
                    "send-progress",
                    ProgressView {
                        name: name.clone(),
                        pct: pct(sent, total),
                        sent,
                        total,
                        speed: speed as u64,
                        eta: eta_secs(sent, total, speed),
                    },
                );
            }
        }
    })
    .await
}

/// 发送包装：取连接（能复用就复用）→ 判定通路 → [`transfer::send_on_conn`]，把进度转成 UI 事件。
async fn do_send(
    app: AppHandle,
    endpoint: Endpoint,
    id: EndpointId,
    addrs: Vec<SocketAddr>,
    path: PathBuf,
) {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    let flag = cancel_flag();
    flag.store(false, Ordering::Relaxed);
    let opts = SendOptions {
        wait_direct: wait_direct_for(size),
        cancel: Some(flag.clone()),
    };
    let reused = take_conn(&id);
    let t0 = Instant::now();

    let (conn, is_reused) = match reused {
        Some(c) => {
            let _ = app.emit("log", "♻️ 复用已有连接，跳过打洞");
            (c, true)
        }
        None => {
            let _ = app.emit("log", "🔎 正在寻找对方…");
            let addr = net::endpoint_addr_of(id, &addrs);
            if !addrs.is_empty() {
                let _ = app.emit(
                    "log",
                    format!("📮 连接码自带 {} 个地址，跳过地址发现", addrs.len()),
                );
            }
            match net::connect_peer(&endpoint, addr, ALPN, opts.wait_direct).await {
                Ok(c) => (c, false),
                Err(e) => {
                    let _ = app.emit("send-done", "");
                    let _ = app.emit("log", format!("❌ 发送失败：{e:#}"));
                    if let Some(hint) = non_empty(net::connect_hint(&format!("{e:#}"), !addrs.is_empty())) {
                        let _ = app.emit("log", format!("💡 {hint}"));
                    }
                    return;
                }
            }
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

    let mut stop_watch = watch_path(&app, &conn);
    let mut conn = conn;
    let mut outcome = send_with_progress(&app, &conn, &path, &opts, &name).await;

    // 复用来的连接可能是"僵尸"：对端早就把程序关了，本地看着还在。
    // 这种失败不能算在用户头上，丢掉重连一次即可。
    if outcome.is_err() && is_reused {
        let _ = app.emit("log", "🔄 旧连接已失效，重新建立…");
        match net::connect_peer(
            &endpoint,
            net::endpoint_addr_of(id, &addrs),
            ALPN,
            Duration::ZERO,
        )
        .await
        {
            Ok(fresh) => {
                stop_watch.store(true, Ordering::Relaxed);
                conn = fresh;
                let _ = app.emit("conn-info", &net::describe(&conn));
                stop_watch = watch_path(&app, &conn);
                outcome = send_with_progress(&app, &conn, &path, &opts, &name).await;
            }
            Err(e) => {
                let _ = app.emit("log", format!("❌ 重连失败：{e:#}"));
            }
        }
    }

    stop_watch.store(true, Ordering::Relaxed);

    // 传完再看一眼通路：可能已经从"中继起步"升级成"直连"。
    let final_view = net::describe(&conn);
    let _ = app.emit("conn-info", &final_view);
    put_conn(&id, conn);

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

/// 接收包装：在**同一条连接上**连续接收多个文件，把进度与结果转成 UI 事件。
///
/// 打洞一次要好几秒，对方连着发第二个文件时没必要重新走一遍。
/// 这里收完一份继续守着连接，直到空闲超时（见 [`transfer::SESSION_IDLE`]）。
async fn do_recv(app: AppHandle, conn: iroh::endpoint::Connection, dir: PathBuf) {
    let view = net::describe(&conn);
    let _ = app.emit("conn-info", &view);
    let _ = app.emit(
        "log",
        format!("🔗 对方已连上：{} {}（RTT {} ms）", view.label, view.detail, view.rtt_ms),
    );

    let stop_watch = watch_path(&app, &conn);
    let mut th = Throttle::new();
    let mut meter = Meter::new();
    // 一份文件一个计时起点，两个回调都要用，只能共享。
    let started_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let flag = cancel_flag();
    // 上一个任务可能留了取消标记，接收开始前先清掉。
    flag.store(false, Ordering::Relaxed);

    let outcome = {
        let app_prog = app.clone();
        let app_file = app.clone();
        let start_for_file = started_at.clone();
        transfer::handle_session(
            &conn,
            Path::new(&dir),
            Some(flag),
            move |name, got, total| {
                let mut slot = start_for_file.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(Instant::now());
                }
                drop(slot);
                let speed = meter.update(got);
                if th.ready(got >= total) {
                    let _ = app_prog.emit(
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
            move |msg| {
                let note = match started_at.lock().unwrap().take() {
                    Some(t) => format!(" / 耗时 {:.1?}", t.elapsed()),
                    None => String::new(),
                };
                let text = format!("📥 {msg}{note}");
                let _ = app_file.emit("recv-done", &text);
                let _ = app_file.emit("log", &text);
            },
        )
        .await
    };

    stop_watch.store(true, Ordering::Relaxed);

    match outcome {
        Ok(n) if n > 1 => {
            let _ = app.emit("log", format!("♻️ 本条连接共接收 {n} 个文件，连接已保留备用"));
        }
        Ok(_) => {}
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
    // 连接码可以是纯 id，也可以是 `id@ip:port,...`（带地址时跳过地址发现，直连更快）。
    let (id, addrs) = net::parse_peer_code(&peer_id).map_err(|e| e.to_string())?;
    let p = PathBuf::from(path.trim());
    if path.trim().is_empty() || !p.is_file() {
        return Err("请先选择一个有效文件".to_string());
    }
    let endpoint = endpoint.clone();
    tauri::async_runtime::spawn(async move {
        do_send(app, endpoint, id, addrs, p).await;
    });
    Ok(())
}

/// "带地址的连接码"：把本机当前可直连的 UDP 地址一起编进去。
///
/// 对方粘这个码可以跳过地址发现（DNS pkarr），在国内部分网络下能救活"死活连不上"。
#[tauri::command]
fn my_addr_code() -> Result<String, String> {
    let Some(endpoint) = ENDPOINT.get() else {
        return Err("网络尚未就绪，请稍候".to_string());
    };
    Ok(net::format_addr_code(
        endpoint.id(),
        &net::publicable_addrs(endpoint),
    ))
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

// ---------------- 我的文件 / 局域网设备 ----------------

/// 接收目录里的文件清单（按修改时间倒序，跳过传输中的 .part / .twinmeta）。
#[derive(Serialize, Clone)]
struct FileEntry {
    name: String,
    size: u64,
    /// UNIX 毫秒
    modified: u64,
}

/// 跳过 Windows 的隐藏 / 系统文件（如 desktop.ini、Thumbs.db），不在"我的文件"里显示系统垃圾。
#[cfg(windows)]
fn is_hidden_or_system(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    let attrs = meta.file_attributes();
    (attrs & FILE_ATTRIBUTE_HIDDEN) != 0 || (attrs & FILE_ATTRIBUTE_SYSTEM) != 0
}
#[cfg(not(windows))]
fn is_hidden_or_system(_meta: &std::fs::Metadata) -> bool {
    false
}

fn list_received(dir: &str) -> Vec<FileEntry> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".part") || name.ends_with(".twinmeta") {
                continue; // 传输尚未完成的临时文件，先不显示
            }
            if name.eq_ignore_ascii_case("desktop.ini") || is_hidden_or_system(&meta) {
                continue; // 系统文件不进"我的文件"，避免定位时看不到
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            out.push(FileEntry { name, size: meta.len(), modified });
        }
    }
    out.sort_by(|a, b| b.modified.cmp(&a.modified));
    out
}

/// 列出"我的文件"页内容。
#[tauri::command]
fn list_files() -> Vec<FileEntry> {
    list_received(&save_dir().lock().unwrap().clone())
}

/// 把文件名拼到接收目录后规范化，确保没有逃出 save_dir（防御真实路径穿越）。
/// 注意：允许文件名本身包含 `..` 字符（NTFS 允许，UI 也会显示为视觉省略号），
/// 只拦截把 `..` 当路径分量用的越界访问。
fn resolve_in_save_dir(name: &str) -> Result<PathBuf, String> {
    if name.is_empty() {
        return Err("文件名不合法".into());
    }
    // 防御性：list_files 走的是 file_name()，不会有分隔符；但 JS 可能乱传，这里再拦一次。
    if name.contains('\0') || name.contains('/') || name.contains('\\') {
        return Err("文件名不合法".into());
    }
    let save = Path::new(&save_dir().lock().unwrap().clone()).to_path_buf();
    let target = save.join(name);
    let canon_target = std::fs::canonicalize(&target).map_err(|_| "文件不存在".to_string())?;
    let canon_save = std::fs::canonicalize(&save).unwrap_or(save);
    if !canon_target.starts_with(&canon_save) {
        return Err("文件名不合法".into());
    }
    Ok(target)
}

/// 用系统默认程序打开某个已接收文件。文件名做防穿越处理。
#[tauri::command]
fn open_file(app: AppHandle, name: String) -> Result<(), String> {
    let path = resolve_in_save_dir(&name)?;
    let p = path.to_string_lossy().to_string();
    // 用 explorer（GUI 程序）打开，避免 cmd.exe 控制台窗口闪烁。
    std::process::Command::new("explorer")
        .arg(&p)
        .spawn()
        .map_err(|e| format!("打开失败：{e}"))?;
    let _ = app.emit("log", format!("📂 已用默认程序打开：{name}"));
    Ok(())
}

/// 在资源管理器里打开接收目录。
#[tauri::command]
fn open_folder(app: AppHandle) -> Result<(), String> {
    let dir = save_dir().lock().unwrap().clone();
    std::process::Command::new("explorer")
        .arg(&dir)
        .spawn()
        .map_err(|e| format!("打开文件夹失败：{e}"))?;
    let _ = app.emit("log", format!("📁 已打开接收目录：{dir}"));
    Ok(())
}

/// 在资源管理器里定位并选中某个已接收文件（不打开它）。
#[tauri::command]
fn reveal_file(app: AppHandle, name: String) -> Result<(), String> {
    let path = resolve_in_save_dir(&name)?;
    let p = path.to_string_lossy().to_string();
    // /select, 必须和路径拼成**单个**参数，逗号不能拆开。
    let arg = format!("/select,{}", p);
    std::process::Command::new("explorer")
        .arg(&arg)
        .spawn()
        .map_err(|e| format!("打开位置失败：{e}"))?;
    let _ = app.emit("log", format!("📍 已在资源管理器中定位：{name}"));
    Ok(())
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

                            // 局域网设备发现：广播本机连接码 + 昵称 + 直连地址，
                            // 收同网段的其他 TwimStar（点一下即直连，不走发现服务）。
                            let ep_for_disc = endpoint.clone();
                            disc::start(
                                handle.clone(),
                                id.clone(),
                                Config::load().nickname,
                                std::sync::Arc::new(move || net::publicable_addrs(&ep_for_disc)),
                            );

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
            my_addr_code,
            get_save_dir,
            list_files,
            open_file,
            open_folder,
            reveal_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
