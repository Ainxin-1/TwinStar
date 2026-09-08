// TwimStar v0.8 — 前端逻辑（Tauri API）
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { getCurrentWebview } = window.__TAURI__.webview;

// ── 元素 ──
const $ = (id) => document.getElementById(id);
const netPill = $("net-pill");
const connPill = $("conn-pill");
const myIdEl = $("my-id");
const btnCopy = $("btn-copy");
const dropzone = $("dropzone");
const dropzoneText = $("dropzone-text");
const peerInput = $("peer-id");
const btnSend = $("btn-send");
const btnCancel = $("btn-cancel");
const sendProgress = $("send-progress");
const sendBar = $("send-bar");
const sendMeta = $("send-meta");
const sendResult = $("send-result");
const saveDirEl = $("save-dir");
const recvStatus = $("recv-status");
const recvProgress = $("recv-progress");
const recvBar = $("recv-bar");
const recvMeta = $("recv-meta");
const statusDot = $("status-dot");
const statusText = $("status-text");
const logList = $("log-list");
const logCount = $("log-count");
const diagLead = $("diag-lead");
const diagAdvice = $("diag-advice");
const diagGrid = $("diag-grid");
const diagRelays = $("diag-relays");

let selectedFile = null;
let sending = false;
let logLines = [];
let netReady = false;
let myId = null;

// ── 小工具 ──
function fullName(p) {
  const i = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return i >= 0 ? p.slice(i + 1) : p;
}

function fmtSize(b) {
  if (b < 1024) return b + " B";
  const kb = b / 1024;
  if (kb < 1024) return kb.toFixed(1) + " KB";
  const mb = kb / 1024;
  if (mb < 1024) return mb.toFixed(1) + " MB";
  return (mb / 1024).toFixed(2) + " GB";
}

function fmtRate(bytesPerSec) {
  if (!bytesPerSec) return "—";
  return fmtSize(bytesPerSec) + "/s";
}

function fmtEta(sec) {
  if (!sec) return "";
  if (sec < 60) return " 剩余 " + sec + " 秒";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return " 剩余 " + m + " 分 " + (s < 10 ? "0" : "") + s + " 秒";
}

function progressText(p) {
  return fmtSize(p.sent) + " / " + fmtSize(p.total) + " · " + fmtRate(p.speed) + fmtEta(p.eta);
}

function setSendEnabled() {
  btnSend.disabled =
    sending || !selectedFile || peerInput.value.trim().length === 0 || !netReady;
  btnCopy.disabled = !myId;
}

function showResult(msg, ok) {
  sendResult.textContent = msg;
  sendResult.className = "result " + (ok ? "ok" : "err");
}

function addLog(line) {
  logLines.push(line);
  if (logLines.length > 200) logLines.shift();
  const div = document.createElement("div");
  div.textContent = line;
  logList.appendChild(div);
  logList.scrollTop = logList.scrollHeight;
  logCount.textContent = logLines.length + " 条";
}

function idle() {
  statusText.textContent = "就绪";
  statusText.className = "";
  statusDot.className = "dot dot-green";
}

// ── Tab 切换 ──
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const cur = tab.dataset.tab;
    $("page-transfer").classList.toggle("hidden", cur !== "transfer");
    $("page-logs").classList.toggle("hidden", cur !== "logs");
    $("page-net").classList.toggle("hidden", cur !== "net");
  });
});

// ── 网络就绪 ──
listen("net-ready", (e) => {
  netReady = true;
  myId = e.payload;
  myIdEl.textContent = myId.slice(0, 8) + " … " + myId.slice(-8);
  myIdEl.title = myId + "\n（点击复制）";
  netPill.textContent = "● 网络就绪";
  netPill.className = "pill pill-green";
  idle();
  setSendEnabled();
});

// ── 通路：直连 / 中继 ──
listen("conn-info", (e) => {
  const p = e.payload;
  if (!p || p.kind === "unknown") {
    connPill.textContent = "打洞中…";
    connPill.className = "pill pill-gray";
    return;
  }
  connPill.classList.remove("hidden");
  connPill.textContent =
    (p.kind === "direct" ? "⚡ 直连" : "🔁 中继") + (p.rtt_ms ? " " + p.rtt_ms + "ms" : "");
  connPill.className = "pill " + (p.kind === "direct" ? "pill-green" : "pill-amber");
  connPill.title = p.detail || "";
});

// ── 进度与结果 ──
listen("send-progress", (e) => {
  const p = e.payload;
  sendProgress.classList.remove("hidden");
  sendMeta.classList.remove("hidden");
  sendBar.style.width = p.pct + "%";
  sendMeta.textContent = p.pct + "% · " + progressText(p);
  statusText.textContent = "正在发送 " + p.pct + "%…";
  statusText.className = "busy";
  statusDot.className = "dot dot-blue";
});

listen("send-done", (e) => {
  sending = false;
  btnCancel.classList.add("hidden");
  sendProgress.classList.add("hidden");
  sendMeta.classList.add("hidden");
  sendBar.style.width = "0%";
  idle();
  if (e.payload) showResult(e.payload, true);
  setSendEnabled();
});

listen("recv-progress", (e) => {
  const p = e.payload;
  recvStatus.textContent = "正在接收: " + p.name;
  recvStatus.className = "recv-status active";
  recvProgress.classList.remove("hidden");
  recvMeta.classList.remove("hidden");
  recvBar.style.width = p.pct + "%";
  recvMeta.textContent = p.pct + "% · " + progressText(p);
  statusText.textContent = "正在接收 " + p.name + " " + p.pct + "%…";
  statusText.className = "busy";
  statusDot.className = "dot dot-blue";
});

listen("recv-done", (e) => {
  recvStatus.textContent = "等待对方连接…";
  recvStatus.className = "recv-status";
  recvProgress.classList.add("hidden");
  recvMeta.classList.add("hidden");
  recvBar.style.width = "0%";
  idle();
  if (e.payload) addLog(e.payload);
});

listen("log", (e) => {
  addLog(e.payload);
  if (e.payload.startsWith("❌")) {
    showResult(e.payload, false);
    sending = false;
    btnCancel.classList.add("hidden");
    sendProgress.classList.add("hidden");
    sendMeta.classList.add("hidden");
    idle();
    setSendEnabled();
  }
});

// ── 网络自检 ──
function kv(grid, k, v, warn) {
  const row = document.createElement("div");
  row.className = "kv" + (warn ? " warn" : "");
  const kk = document.createElement("span");
  kk.className = "kv-k";
  kk.textContent = k;
  const vv = document.createElement("span");
  vv.className = "kv-v";
  vv.textContent = v;
  row.appendChild(kk);
  row.appendChild(vv);
  grid.appendChild(row);
}

listen("net-diag", (e) => {
  const d = e.payload;
  diagLead.textContent = d.verdict || "检测完成";
  diagLead.className = "diag-lead " + (/直连|良好/.test(d.verdict) ? "ok" : "warn");
  diagAdvice.textContent = d.advice || "";
  diagAdvice.classList.toggle("hidden", !d.advice);

  diagGrid.innerHTML = "";
  kv(diagGrid, "UDP IPv4", d.udp_v4 ? "可用" : "不通", !d.udp_v4);
  kv(diagGrid, "UDP IPv6", d.udp_v6 ? "可用" : "无", false);
  kv(diagGrid, "公网 IPv4", d.public_v4 || "未探测到", false);
  if (d.public_v6) kv(diagGrid, "公网 IPv6", d.public_v6, false);
  kv(diagGrid, "地址环境", d.cgnat ? "运营商 CGNAT（100.64/10）" : "普通 NAT / 公网", false);
  kv(
    diagGrid,
    "NAT 行为",
    d.nat_varies === true ? "对称型（打洞难）" : d.nat_varies === false ? "锥型（可打洞）" : "未知",
    d.nat_varies === true
  );
  kv(diagGrid, "中继", d.relay || "未连接", !d.relay);
  if (d.vpn_hint) kv(diagGrid, "代理 / 虚拟网卡", d.vpn_hint, true);

  diagRelays.innerHTML = "";
  if (!d.relay_latency || !d.relay_latency.length) {
    kv(diagRelays, "—", "暂无延迟数据");
  } else {
    d.relay_latency.forEach(([url, ms]) => kv(diagRelays, url, ms + " ms", ms > 800));
  }
});

$("btn-diag").addEventListener("click", async () => {
  diagLead.textContent = "正在检测网络环境…";
  diagLead.className = "diag-lead";
  try {
    await invoke("refresh_diag");
  } catch (err) {
    diagLead.textContent = "检测失败：" + err;
  }
});

// ── 复制连接码 ──
btnCopy.addEventListener("click", async () => {
  if (!myId) return;
  await navigator.clipboard.writeText(myId);
  btnCopy.textContent = "已复制";
  setTimeout(() => (btnCopy.textContent = "复制"), 1200);
});
myIdEl.addEventListener("click", async () => {
  if (myId) await navigator.clipboard.writeText(myId);
});

// ── 文件选择 ──
dropzone.addEventListener("click", async () => {
  const path = await invoke("pick_file");
  if (path) selectFile(path);
});

function selectFile(path) {
  selectedFile = path;
  dropzoneText.textContent = "📄  " + fullName(path);
  dropzone.classList.add("hasfile");
  dropzone.title = path;
  setSendEnabled();
}

// ── 拖放（Tauri 拦截的拖放事件，带真实路径） ──
getCurrentWebview()
  .onDragDropEvent((event) => {
    const p = event.payload;
    if (p.type === "over") {
      dropzone.classList.add("drag");
    } else if (p.type === "drop") {
      dropzone.classList.remove("drag");
      if (p.paths && p.paths.length) selectFile(p.paths[0]);
    } else {
      dropzone.classList.remove("drag");
    }
  })
  .then((unlisten) => {
    window._unlistenDrag = unlisten;
  });

// ── 发送 / 取消 ──
peerInput.addEventListener("input", setSendEnabled);
peerInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") btnSend.click();
});

btnSend.addEventListener("click", async () => {
  if (btnSend.disabled) return;
  sending = true;
  sendResult.className = "result hidden";
  btnSend.disabled = true;
  btnSend.textContent = "发送中…";
  btnCancel.classList.remove("hidden");
  statusText.textContent = "正在连接 / 打洞…";
  statusText.className = "busy";
  statusDot.className = "dot dot-blue";
  try {
    await invoke("start_send", { peerId: peerInput.value, path: selectedFile });
  } catch (err) {
    showResult(String(err), false);
    sending = false;
    btnCancel.classList.add("hidden");
    idle();
  }
  btnSend.textContent = "发 送";
  setSendEnabled();
});

btnCancel.addEventListener("click", async () => {
  await invoke("cancel_send");
  addLog("已请求取消当前传输");
});

// ── 接收目录 ──
$("btn-folder").addEventListener("click", async () => {
  const dir = await invoke("pick_folder");
  if (dir) saveDirEl.textContent = "保存到 " + dir;
});

invoke("get_save_dir").then((dir) => {
  saveDirEl.textContent = "保存到 " + dir;
});

// ── 日志清空 ──
$("btn-clear").addEventListener("click", () => {
  logLines = [];
  logList.innerHTML = "";
  logCount.textContent = "0 条";
});
