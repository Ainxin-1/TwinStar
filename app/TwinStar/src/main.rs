//! TwimStar v0.5 — 零成本互传（egui GUI 版 · DevKit 风格 UI）
//! 局域网直连 / 跨网打洞 / 中继兜底，全程零服务器零账号。

// release 版隐藏 Windows 控制台窗口（双击只出现 GUI）；debug 版保留控制台方便看日志
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use eframe::egui;
use iroh::{Endpoint, EndpointId, RelayMode, SecretKey, endpoint::presets};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ALPN: &[u8] = b"twimstar/demo/1";
const CHUNK: usize = 256 * 1024;

// ---------------- 网络层 ----------------

#[derive(Clone)]
struct NetHandle {
    rt: tokio::runtime::Handle,
    endpoint: Endpoint,
}

enum UiMsg {
    Net(NetHandle),
    Ready { id: String, info: String },
    Log(String),
    SendPct(f32),
    SendDone(String),
    RecvFile { name: String, pct: f32 },
    RecvDone(String),
}

async fn build_endpoint() -> Result<Endpoint> {
    Ok(Endpoint::builder(presets::N0)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await?)
}

fn human_size(n: u64) -> String {
    let n = n as f64;
    if n >= 1_073_741_824.0 { format!("{:.2} GB", n / 1_073_741_824.0) }
    else if n >= 1_048_576.0 { format!("{:.2} MB", n / 1_048_576.0) }
    else if n >= 1024.0 { format!("{:.1} KB", n / 1024.0) }
    else { format!("{n} B") }
}

fn default_save_dir() -> String {
    std::env::var("USERPROFILE")
        .map(|h| format!("{h}\\Downloads"))
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().display().to_string())
}

fn path_name(p: &str) -> String {
    PathBuf::from(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}

async fn send_file(net: NetHandle, id: EndpointId, path: PathBuf, tx: mpsc::Sender<UiMsg>) {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let _ = tx.send(UiMsg::Log("正在连接对方…".into()));
    let result: Result<String> = async {
        let total = tokio::fs::metadata(&path).await?.len();
        let mut file = tokio::fs::File::open(&path).await?;
        let t0 = Instant::now();
        let conn = net.endpoint.connect(id, ALPN).await?;
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
            let _ = tx.send(UiMsg::SendPct(sent as f32 / total as f32));
        }
        send.shutdown().await?;
        let ack = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv.read_to_end(16),
        ).await;
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
    }.await;
    match result {
        Ok(msg) => { let _ = tx.send(UiMsg::SendDone(msg)); }
        Err(e) => {
            let _ = tx.send(UiMsg::SendDone(String::new()));
            let _ = tx.send(UiMsg::Log(format!("❌ 发送失败: {e:#}")));
        }
    }
}

async fn handle_incoming(
    conn: iroh::endpoint::Connection,
    save_dir: Arc<Mutex<String>>,
    tx: mpsc::Sender<UiMsg>,
) {
    let result: Result<String> = async {
        let (mut send, mut recv) = conn.accept_bi().await?;
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let name_len = u32::from_le_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        recv.read_exact(&mut name_buf).await?;
        let name = String::from_utf8_lossy(&name_buf).to_string();
        let dir = save_dir.lock().unwrap().clone();
        let out_path = PathBuf::from(&dir).join(&name);
        let mut out = tokio::fs::File::create(&out_path).await?;
        let mut received: u64 = 0;
        let mut buf = vec![0u8; CHUNK];
        let t0 = Instant::now();
        loop {
            let Some(n) = recv.read(&mut buf).await? else { break };
            out.write_all(&buf[..n]).await?;
            received += n as u64;
            let _ = tx.send(UiMsg::RecvFile { name: name.clone(), pct: 0.0 });
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
    }.await;
    match result {
        Ok(msg) => { let _ = tx.send(UiMsg::RecvDone(msg)); }
        Err(e) => { let _ = tx.send(UiMsg::Log(format!("❌ 接收失败: {e:#}"))); }
    }
}

fn spawn_network(tx: mpsc::Sender<UiMsg>, save_dir: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();
        rt.block_on(async move {
            match build_endpoint().await {
                Ok(endpoint) => {
                    let id = endpoint.id().to_string();
                    let mut info = String::from("本机地址:\n");
                    for a in endpoint.addr().ip_addrs() {
                        info.push_str(&format!("  {a}\n"));
                    }
                    if let Some(relay) = endpoint.addr().relay_urls().next() {
                        info.push_str(&format!("  中继: {relay}"));
                    }
                    let _ = tx.send(UiMsg::Net(NetHandle {
                        rt: handle,
                        endpoint: endpoint.clone(),
                    }));
                    let _ = tx.send(UiMsg::Ready { id, info });
                    loop {
                        let Some(incoming) = endpoint.accept().await else { break };
                        let tx2 = tx.clone();
                        let sd = save_dir.clone();
                        match incoming.accept() {
                            Ok(accepting) => {
                                tokio::spawn(async move {
                                    match accepting.await {
                                        Ok(conn) => handle_incoming(conn, sd, tx2).await,
                                        Err(e) => {
                                            let _ = tx2.send(UiMsg::Log(format!("连接失败: {e:#}")));
                                        }
                                    }
                                });
                            }
                            Err(_) => continue,
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(UiMsg::Log(format!("网络初始化失败: {e:#}")));
                }
            }
        });
    });
}

// ---------------- 主题 ----------------

mod theme {
    use eframe::egui::Color32;
    pub const BG: Color32 = Color32::from_rgb(0xF5, 0xF6, 0xF8);
    pub const CARD: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
    pub const PRIMARY: Color32 = Color32::from_rgb(0x2E, 0x7C, 0xF6);
    pub const PILL_BG: Color32 = Color32::from_rgb(0xEA, 0xF2, 0xFF);
    pub const TEXT: Color32 = Color32::from_rgb(0x1F, 0x29, 0x37);
    pub const MUTED: Color32 = Color32::from_rgb(0x9C, 0xA3, 0xAF);
    pub const STROKE: Color32 = Color32::from_rgb(0xEC, 0xEE, 0xF1);
    pub const FIELD: Color32 = Color32::from_rgb(0xF3, 0xF4, 0xF6);
    pub const OK: Color32 = Color32::from_rgb(0x16, 0xA3, 0x4A);
    pub const OK_BG: Color32 = Color32::from_rgb(0xE8, 0xF7, 0xEE);
    pub const ERR: Color32 = Color32::from_rgb(0xDC, 0x26, 0x26);
    pub const ERR_BG: Color32 = Color32::from_rgb(0xFD, 0xEC, 0xEC);
}

// ---------------- UI 层 ----------------

fn main() -> eframe::Result<()> {
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 600.0])
            .with_min_inner_size([660.0, 540.0])
            .with_position([160.0, 40.0])
            .with_title("TwimStar — 零成本互传"),
        ..Default::default()
    };
    eframe::run_native(
        "TwimStar",
        native,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            setup_style(&cc.egui_ctx);
            Ok(Box::new(TwimStarApp::new()))
        }),
    )
}

fn setup_fonts(ctx: &egui::Context) {
    for path in ["C:\\Windows\\Fonts\\msyh.ttc", "C:\\Windows\\Fonts\\simhei.ttf"] {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert("cjk".into(), Arc::new(egui::FontData::from_owned(bytes)));
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "cjk".into());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".into());
            ctx.set_fonts(fonts);
            return;
        }
    }
}

fn setup_style(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 7.0);
        let v = &mut style.visuals;
        v.panel_fill = theme::BG;
        v.window_fill = theme::BG;
        v.extreme_bg_color = theme::FIELD;
        v.faint_bg_color = theme::FIELD;
        v.override_text_color = Some(theme::TEXT);
        v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, theme::TEXT);
        v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, theme::TEXT);
        v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, theme::PRIMARY);
        v.widgets.active.fg_stroke = egui::Stroke::new(1.2, theme::PRIMARY);
        v.selection.bg_fill = theme::PRIMARY;
        v.selection.stroke = egui::Stroke::new(1.0, theme::CARD);
    });
}

// ---------- 小组件 ----------

/// 白色卡片（极淡描边 + 10px 圆角）
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(theme::CARD)
        .corner_radius(egui::CornerRadius::same(10))
        .stroke(egui::Stroke::new(1.0, theme::STROKE))
        .inner_margin(egui::Margin::same(14))
        .show(ui, add)
        .inner
}

fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(14.0).strong().color(theme::TEXT));
}

/// pill 小标签（浅色底 + 彩色字）
fn pill(ui: &mut egui::Ui, text: &str, fg: egui::Color32, bg: egui::Color32) {
    egui::Frame::new()
        .fill(bg)
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(11.5).strong().color(fg));
        });
}

/// 蓝色主按钮
fn primary_button(text: &str, size: f32) -> egui::Button {
    egui::Button::new(egui::RichText::new(text).size(size).color(theme::CARD))
        .fill(theme::PRIMARY)
        .corner_radius(egui::CornerRadius::same(8))
}

/// 白底描边次按钮
fn ghost_button(text: &str, size: f32) -> egui::Button {
    egui::Button::new(egui::RichText::new(text).size(size).color(theme::TEXT))
        .fill(theme::CARD)
        .stroke(egui::Stroke::new(1.0, theme::STROKE))
        .corner_radius(egui::CornerRadius::same(8))
}

fn short_id(id: &str) -> String {
    if id.len() > 20 {
        format!("{} … {}", &id[..8], &id[id.len() - 8..])
    } else {
        id.to_string()
    }
}

struct TwimStarApp {
    tx: mpsc::Sender<UiMsg>,
    rx: mpsc::Receiver<UiMsg>,
    net: Option<NetHandle>,
    my_id: Option<String>,
    net_info: String,
    peer_id: String,
    file_path: String,
    sending: bool,
    send_pct: f32,
    recv_status: String,
    recv_name: String,
    recv_pct: f32,
    save_dir: Arc<Mutex<String>>,
    logs: Vec<String>,
    last_result: Option<(String, bool)>,
    tab: usize,
}

impl TwimStarApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let save_dir = Arc::new(Mutex::new(default_save_dir()));
        spawn_network(tx.clone(), save_dir.clone());
        Self {
            tx,
            rx,
            net: None,
            my_id: None,
            net_info: String::new(),
            peer_id: String::new(),
            file_path: String::new(),
            sending: false,
            send_pct: 0.0,
            recv_status: "等待对方连接…".into(),
            recv_name: String::new(),
            recv_pct: 0.0,
            save_dir,
            logs: vec!["TwimStar v0.5 启动".into()],
            last_result: None,
            tab: 0,
        }
    }

    fn log(&mut self, s: impl Into<String>) {
        self.logs.push(s.into());
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }

    fn drain_msgs(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                UiMsg::Net(net) => self.net = Some(net),
                UiMsg::Ready { id, info } => {
                    self.my_id = Some(id);
                    self.net_info = info;
                    self.log("网络就绪 ✅");
                }
                UiMsg::Log(s) => {
                    if s.starts_with("❌") {
                        self.last_result = Some((s.clone(), false));
                    } else if s.starts_with("✅") || s.starts_with("📥") {
                        self.last_result = Some((s.clone(), true));
                    }
                    self.log(s);
                }
                UiMsg::SendPct(p) => self.send_pct = p.clamp(0.0, 1.0),
                UiMsg::SendDone(s) => {
                    self.sending = false;
                    self.send_pct = 0.0;
                    if !s.is_empty() {
                        self.last_result = Some((s.clone(), true));
                        self.log(s);
                    }
                }
                UiMsg::RecvFile { name, pct } => {
                    self.recv_name = name.clone();
                    self.recv_pct = pct.clamp(0.0, 1.0);
                    self.recv_status = format!("正在接收: {name}");
                }
                UiMsg::RecvDone(s) => {
                    self.recv_status = "等待对方连接…".into();
                    self.recv_pct = 0.0;
                    self.last_result = Some((s.clone(), true));
                    self.log(s);
                }
            }
        }
    }

    fn start_send(&mut self) {
        let Some(net) = self.net.clone() else {
            self.log("网络尚未就绪");
            return;
        };
        let id: EndpointId = match self.peer_id.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.last_result = Some(("对方连接码格式不对（应为 64 位十六进制）".into(), false));
                return;
            }
        };
        let path = PathBuf::from(self.file_path.trim());
        if self.file_path.trim().is_empty() || !path.is_file() {
            self.last_result = Some(("请先选择一个有效文件".into(), false));
            return;
        }
        self.sending = true;
        self.send_pct = 0.0;
        self.last_result = None;
        let tx = self.tx.clone();
        net.rt.clone().spawn(send_file(net, id, path, tx));
    }
}

impl eframe::App for TwimStarApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_msgs();

        // 拖放文件进窗口 → 自动选中
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(f) = dropped.first() {
            let p = f.path();
            if !p.as_os_str().is_empty() {
                self.file_path = p.display().to_string();
            }
        }

        // 内容贴边，自己控制所有留白
        ui.style_mut().spacing.window_margin = egui::Margin::same(0);
        ui.style_mut().spacing.item_spacing = egui::vec2(8.0, 8.0);

        // ── 顶栏（白底）：图标块 + 标题/副标题 + 网络状态 ──
        egui::Frame::new()
            .fill(theme::CARD)
            .inner_margin(egui::Margin { left: 18, right: 18, top: 12, bottom: 12 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    // 图标块
                    let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(36.0, 36.0), egui::Sense::hover());
                    ui.painter().rect_filled(icon_rect, 9, theme::PRIMARY);
                    ui.painter().text(
                        icon_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "☄",
                        egui::FontId::proportional(20.0),
                        theme::CARD,
                    );
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("TwimStar").size(18.0).strong().color(theme::TEXT));
                        ui.label(
                            egui::RichText::new("零成本互传 · 免 VPN · 无需账号")
                                .size(11.0)
                                .color(theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.net.is_some() {
                            pill(ui, "● 网络就绪", theme::OK, theme::OK_BG);
                        } else {
                            pill(ui, "● 初始化中", theme::PRIMARY, theme::PILL_BG);
                        }
                    });
                });
            });

        // ── 标签页行（白底，pill 高亮式） ──
        egui::Frame::new()
            .fill(theme::CARD)
            .stroke(egui::Stroke::new(1.0, theme::STROKE))
            .inner_margin(egui::Margin { left: 18, right: 18, top: 6, bottom: 6 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    for (label, idx) in [("传输", 0usize), ("活动日志", 1usize)] {
                        let selected = self.tab == idx;
                        let txt = egui::RichText::new(label)
                            .size(13.0)
                            .strong()
                            .color(if selected { theme::PRIMARY } else { theme::MUTED });
                        let btn = egui::Button::new(txt)
                            .fill(if selected { theme::PILL_BG } else { theme::CARD })
                            .corner_radius(egui::CornerRadius::same(8));
                        if ui.add(btn).clicked() {
                            self.tab = idx;
                        }
                        ui.add_space(2.0);
                    }
                });
            });

        // ── 内容区 ──
        egui::Frame::new()
            .inner_margin(egui::Margin { left: 18, right: 18, top: 14, bottom: 10 })
            .show(ui, |ui| {
                if self.tab == 0 {
                    self.transfer_page(ui, &ctx);
                } else {
                    self.log_page(ui);
                }
            });

        // ── 底部状态栏（紧跟内容） ──
        ui.add_space(4.0);
        egui::Frame::new()
            .fill(theme::CARD)
            .stroke(egui::Stroke::new(1.0, theme::STROKE))
            .inner_margin(egui::Margin { left: 18, right: 18, top: 8, bottom: 8 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                    let status_color = if self.net.is_some() { theme::OK } else { theme::MUTED };
                    ui.painter().circle_filled(dot.center(), 4.0, status_color);
                    if self.sending {
                        ui.label(
                            egui::RichText::new(format!(
                                "正在发送 {}%…",
                                (self.send_pct * 100.0) as u32
                            ))
                            .size(12.0)
                            .color(theme::PRIMARY),
                        );
                    } else if self.recv_status.starts_with("正在接收") {
                        ui.label(
                            egui::RichText::new(&self.recv_status)
                                .size(12.0)
                                .color(theme::PRIMARY),
                        );
                    } else if self.net.is_some() {
                        ui.label(egui::RichText::new("就绪").size(12.0).color(theme::MUTED));
                    } else {
                        ui.label(
                            egui::RichText::new("正在建立网络…")
                                .size(12.0)
                                .color(theme::MUTED),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new("v0.5").size(11.5).color(theme::MUTED));
                    });
                });
            });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::BG.to_normalized_gamma_f32()
    }
}

impl TwimStarApp {
    fn transfer_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // ── 我的连接码 ──
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                section_title(ui, "我的连接码");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(self.my_id.is_some(), primary_button("复制", 12.5))
                        .clicked()
                    {
                        if let Some(id) = &self.my_id {
                            ctx.copy_text(id.clone());
                            self.log("连接码已复制到剪贴板");
                        }
                    }
                    if let Some(id) = &self.my_id {
                        ui.label(
                            egui::RichText::new(short_id(id))
                                .monospace()
                                .size(14.0)
                                .strong()
                                .color(theme::PRIMARY),
                        )
                        .on_hover_text(format!("{id}\n（点击复制）"));
                    } else {
                        ui.spinner();
                        ui.label(egui::RichText::new("连接建立中…").size(12.5).color(theme::MUTED));
                    }
                });
            });
        });

        // ── 发送 ──
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            section_title(ui, "发送文件");
            ui.add_space(2.0);

            // 拖放区
            let w = ui.available_width();
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 72.0), egui::Sense::click());
            let dragging = ctx.input(|i| !i.raw.hovered_files.is_empty());
            let (fill, line, lw) = if dragging {
                (theme::PILL_BG, theme::PRIMARY, 2.0)
            } else if resp.hovered() {
                (theme::FIELD, theme::PRIMARY, 1.5)
            } else {
                (theme::FIELD, theme::STROKE, 1.0)
            };
            ui.painter().rect_filled(rect, 10, fill);
            ui.painter().rect_stroke(
                rect,
                10,
                egui::Stroke::new(lw, line),
                egui::StrokeKind::Inside,
            );
            let empty = self.file_path.trim().is_empty();
            let inner = if empty {
                "📂  把文件拖到这里，或点击选择".to_string()
            } else {
                format!("📄  {}", path_name(&self.file_path))
            };
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                inner,
                egui::FontId::proportional(13.5),
                if empty { theme::MUTED } else { theme::TEXT },
            );
            if resp.clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.file_path = p.display().to_string();
                }
            }
            if !empty {
                resp.on_hover_text(&self.file_path);
            }

            ui.label(
                egui::RichText::new("对方连接码")
                    .size(11.5)
                    .color(theme::MUTED),
            );
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.peer_id)
                    .hint_text("粘贴对方的 64 位连接码")
                    .desired_width(ui.available_width())
                    .font(egui::TextStyle::Monospace),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.start_send();
            }
            ui.add_space(2.0);

            let enabled = !self.sending
                && self.net.is_some()
                && !empty
                && !self.peer_id.trim().is_empty();
            let btn_label = if self.sending { "发送中…" } else { "发 送" };
            let btn = primary_button(btn_label, 14.5)
                .fill(if enabled { theme::PRIMARY } else { theme::PRIMARY.gamma_multiply(0.45) })
                .min_size(egui::vec2(ui.available_width(), 38.0));
            if ui.add_enabled(enabled, btn).clicked() {
                self.start_send();
            }
            if self.sending {
                ui.add(
                    egui::ProgressBar::new(self.send_pct)
                        .show_percentage()
                        .desired_width(ui.available_width()),
                );
            }
            if let Some((msg, ok)) = &self.last_result {
                egui::Frame::new()
                    .fill(if *ok { theme::OK_BG } else { theme::ERR_BG })
                    .corner_radius(egui::CornerRadius::same(8))
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(
                            egui::RichText::new(msg)
                                .size(12.0)
                                .color(if *ok { theme::OK } else { theme::ERR }),
                        );
                    });
            }
        });

        // ── 接收 ──
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                section_title(ui, "接收文件");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    pill(ui, "自动接收", theme::PRIMARY, theme::PILL_BG);
                });
            });
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let dir = self.save_dir.lock().unwrap().clone();
                ui.label(
                    egui::RichText::new(format!("保存到 {dir}"))
                        .size(11.5)
                        .color(theme::MUTED),
                );
                if ui.add(ghost_button("更改", 11.0)).clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        *self.save_dir.lock().unwrap() = p.display().to_string();
                    }
                }
            });
            ui.horizontal(|ui| {
                if self.recv_pct > 0.0 {
                    ui.add(
                        egui::ProgressBar::new(self.recv_pct)
                            .show_percentage()
                            .desired_width(220.0),
                    );
                } else if self.recv_status.starts_with("正在接收") {
                    ui.spinner();
                }
                ui.label(
                    egui::RichText::new(&self.recv_status)
                        .size(12.5)
                        .color(theme::TEXT),
                );
            });
        });
    }

    fn log_page(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                section_title(ui, "活动日志");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(ghost_button("清空", 12.0)).clicked() {
                        self.logs.clear();
                    }
                    pill(ui, &format!("{} 条", self.logs.len()), theme::PRIMARY, theme::PILL_BG);
                });
            });
            ui.add_space(4.0);
            let log_h = (ui.ctx().input(|i| i.viewport_rect()).height() - 280.0).max(200.0);
            egui::ScrollArea::vertical()
                .max_height(log_h)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.logs {
                        ui.label(
                            egui::RichText::new(line)
                                .monospace()
                                .size(11.5)
                                .color(theme::MUTED),
                        );
                    }
                });
        });
    }
}
