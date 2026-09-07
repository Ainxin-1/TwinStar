// TwimStar v0.6 — 前端逻辑（Tauri API）
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { getCurrentWebview } = window.__TAURI__.webview;

// ── 元素 ──
const $ = (id) => document.getElementById(id);
const netPill = $("net-pill");
const myIdEl = $("my-id");
const btnCopy = $("btn-copy");
const dropzone = $("dropzone");
const dropzoneText = $("dropzone-text");
const peerInput = $("peer-id");
const btnSend = $("btn-send");
const sendProgress = $("send-progress");
const sendBar = $("send-bar");
const sendResult = $("send-result");
const saveDirEl = $("save-dir");
const recvStatus = $("recv-status");
const statusDot = $("status-dot");
const statusText = $("status-text");
const logList = $("log-list");
const logCount = $("log-count");

let selectedFile = null;
let sending = false;
let logLines = [];

function fullName(p) {
  const i = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return i >= 0 ? p.slice(i + 1) : p;
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

// ── Tab 切换 ──
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    $("page-transfer").classList.toggle("hidden", tab.dataset.tab !== "transfer");
    $("page-logs").classList.toggle("hidden", tab.dataset.tab !== "logs");
  });
});

// ── 网络就绪 ──
let netReady = false;
let myId = null;

listen("net-ready", (e) => {
  netReady = true;
  myId = e.payload;
  myIdEl.textContent = myId.slice(0, 8) + " … " + myId.slice(-8);
  myIdEl.title = myId + "\n（点击复制）";
  netPill.textContent = "● 网络就绪";
  netPill.className = "pill pill-green";
  statusDot.className = "dot dot-green";
  statusText.textContent = "就绪";
  setSendEnabled();
});

// ── 进度与结果 ──
listen("send-progress", (e) => {
  sendProgress.classList.remove("hidden");
  sendBar.style.width = e.payload + "%";
  statusText.textContent = "正在发送 " + e.payload + "%…";
  statusText.className = "busy";
  statusDot.className = "dot dot-blue";
});

listen("send-done", (e) => {
  sending = false;
  sendProgress.classList.add("hidden");
  sendBar.style.width = "0%";
  statusText.textContent = "就绪";
  statusText.className = "";
  statusDot.className = "dot dot-green";
  if (e.payload) showResult(e.payload, true);
  setSendEnabled();
});

listen("recv-progress", (e) => {
  recvStatus.textContent = "正在接收: " + e.payload.name;
  recvStatus.className = "recv-status active";
  statusText.textContent = "正在接收 " + e.payload.name + "…";
  statusText.className = "busy";
  statusDot.className = "dot dot-blue";
});

listen("recv-done", (e) => {
  recvStatus.textContent = "等待对方连接…";
  recvStatus.className = "recv-status";
  statusText.textContent = "就绪";
  statusText.className = "";
  statusDot.className = "dot dot-green";
  if (e.payload) addLog(e.payload);
});

listen("log", (e) => {
  addLog(e.payload);
  if (e.payload.startsWith("❌")) {
    showResult(e.payload, false);
    sending = false;
    sendProgress.classList.add("hidden");
    statusText.textContent = "就绪";
    statusText.className = "";
    statusDot.className = "dot dot-green";
    setSendEnabled();
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

// ── 发送 ──
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
  try {
    await invoke("start_send", { peerId: peerInput.value, path: selectedFile });
  } catch (err) {
    showResult(String(err), false);
    sending = false;
    statusText.textContent = "就绪";
    statusText.className = "";
    statusDot.className = "dot dot-green";
  }
  btnSend.textContent = "发 送";
  setSendEnabled();
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
