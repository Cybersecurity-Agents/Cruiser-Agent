const queueItems = [
  { code: "WEB-042", stage: "预处理", cls: "stage-pre", target: "http://10.10.4.21:8080", steps: 38, max: 50, status: "active" },
  { code: "LOGIC-117", stage: "一级", cls: "stage-t1", target: "http://10.10.4.22:9000", steps: 74, max: 100, status: "active" },
  { code: "SSTI-009", stage: "二级", cls: "stage-t2", target: "http://10.10.4.31:7001", steps: 128, max: 150, status: "active" },
  { code: "AUTH-203", stage: "三级", cls: "stage-t3", target: "等待 watcher 方向补位", steps: 182, max: 200, status: "blocked" },
];

const workers = [
  { id: "W1", model: "deepseek-v4-flash", status: "busy", task: "目录扫描与入口识别" },
  { id: "W2", model: "deepseek-v4-flash", status: "busy", task: "参数污染与越权路径" },
  { id: "W3", model: "deepseek-v4-pro", status: "busy", task: "watcher 策展黑板" },
  { id: "S1", model: "deepseek-v4-flash", status: "idle", task: "等待任务板 claim" },
];

const blackboard = [
  { title: "WEB-042", text: "发现 /admin/login 与 /api/profile，登录错误提示暴露 user_id。", color: "var(--blue)" },
  { title: "SSTI-009", text: "模板回显疑似 Jinja2，payload {{7*7}} 返回 49。", color: "var(--green)" },
  { title: "AUTH-203", text: "普通用户 token 可访问 /internal/export，但缺少 role 参数。", color: "var(--amber)" },
  { title: "LOGIC-117", text: "购物车数量允许负数，结算接口未校验库存变更。", color: "var(--red)" },
];

const tools = [
  { name: "dirsearch", desc: "跨会话缓存目录扫描", meter: "88%", color: "var(--blue)" },
  { name: "sqlmap", desc: "SQL 注入探测与利用", meter: "66%", color: "var(--green)" },
  { name: "fenjing", desc: "Python 模板注入辅助", meter: "74%", color: "var(--amber)" },
  { name: "Ghidra", desc: "无头反编译与伪码导出", meter: "52%", color: "var(--red)" },
  { name: "Metasploit", desc: "漏洞验证与数据库联动", meter: "61%", color: "var(--blue)" },
  { name: "nuclei", desc: "模板化漏洞指纹扫描", meter: "79%", color: "var(--green)" },
  { name: "Foundry", desc: "智能合约题工具链", meter: "48%", color: "var(--amber)" },
  { name: "pwntools", desc: "二进制利用脚本框架", meter: "57%", color: "var(--red)" },
];

const logLines = [
  "[VPN] 自动连接成功",
  "[Startup] 已清理 2 个遗留容器",
  "[Stage-Preprocess] 启动 WEB-042 的 50 步预处理",
  "[WEB-042:W1] [COUNT] 38",
  "[SharedInfo] 已加载共享关键信息",
  "[SUBMIT_FLAG][OK] 提交正确，本次得分 80，flag 进度 1/1",
];

let currentFilter = "all";
let running = false;

const queueBoard = document.querySelector("#queueBoard");
const workerList = document.querySelector("#workerList");
const blackboardList = document.querySelector("#blackboardList");
const toolGrid = document.querySelector("#toolGrid");
const logStream = document.querySelector("#logStream");
const runButton = document.querySelector("#runButton");
const syncButton = document.querySelector("#syncButton");
const clearLogs = document.querySelector("#clearLogs");
const shuffleWorkers = document.querySelector("#shuffleWorkers");
const themeToggle = document.querySelector("#themeToggle");
const demoResult = document.querySelector("#demoResult");
const demoTitle = document.querySelector("#demoTitle");
const demoDescription = document.querySelector("#demoDescription");
const demoFlag = document.querySelector("#demoFlag");

function renderQueue() {
  const items = queueItems.filter((item) => currentFilter === "all" || item.status === currentFilter);
  queueBoard.innerHTML = items.map((item) => {
    const value = Math.min(100, Math.round((item.steps / item.max) * 100));
    return `
      <div class="queue-item">
        <span class="stage-badge ${item.cls}">${item.stage}</span>
        <div>
          <div class="challenge-name">${item.code}</div>
          <div class="challenge-meta">${item.target} · ${item.steps}/${item.max} steps</div>
        </div>
        <div class="progress ${item.cls}" aria-label="${item.code} 进度 ${value}%">
          <span style="--value: ${value}%"></span>
        </div>
      </div>
    `;
  }).join("");
}

function renderWorkers() {
  workerList.innerHTML = workers.map((worker) => `
    <div class="worker-card">
      <div class="worker-top">
        <span class="worker-id">${worker.id}</span>
        <span class="status-pill ${worker.status}">${worker.status === "busy" ? "运行中" : "空闲"}</span>
      </div>
      <div class="worker-model">${worker.model}</div>
      <div class="worker-task">${worker.task}</div>
    </div>
  `).join("");
}

function renderBlackboard() {
  blackboardList.innerHTML = blackboard.map((item) => `
    <div class="blackboard-item" style="--accent: ${item.color}">
      <strong>${item.title}</strong>
      <p>${item.text}</p>
    </div>
  `).join("");
}

function renderTools() {
  toolGrid.innerHTML = tools.map((tool) => `
    <div class="tool-card" style="--accent: ${tool.color}; --meter: ${tool.meter}">
      <strong>${tool.name}</strong>
      <p>${tool.desc}</p>
      <div class="tool-meter"><span></span></div>
    </div>
  `).join("");
}

function renderLogs() {
  logStream.textContent = logLines.join("\n");
  logStream.scrollTop = logStream.scrollHeight;
}

function addLog(line) {
  const time = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  logLines.push(`[${time}] ${line}`);
  if (logLines.length > 120) logLines.shift();
  renderLogs();
}

function bumpMetrics() {
  const flags = document.querySelector("#flagsSolved");
  const steps = document.querySelector("#avgSteps");
  const review = document.querySelector("#reviewCount");
  flags.textContent = String(Number(flags.textContent) + 1);
  steps.textContent = String(86 + Math.floor(Math.random() * 28));
  review.textContent = String(2 + Math.floor(Math.random() * 5));
}

function syncState() {
  queueItems.forEach((item) => {
    if (item.status === "active") {
      item.steps = Math.min(item.max, item.steps + 4 + Math.floor(Math.random() * 12));
      if (item.steps >= item.max && item.stage !== "三级") {
        item.steps = Math.max(12, Math.floor(item.max * 0.3));
      }
    }
  });
  addLog("[Fetcher] 状态同步完成，队列与 worker 快照已刷新");
  renderQueue();
  renderWorkers();
}

let demoTimer = null;
let demoStep = 0;

const demoSteps = [
  {
    title: "拉取未解题目",
    description: "调度器通过 tsec-benchmark SDK 获取 WEB-DEMO-001，并准备启动靶场容器。",
    log: "[Fetcher] 获取未解题目 WEB-DEMO-001 difficulty=easy",
  },
  {
    title: "启动靶场容器",
    description: "平台返回目标地址 http://10.10.4.21:8080，Cruiser 等待端口可连接。",
    log: "[Container] WEB-DEMO-001 目标已可连，拉起会话",
  },
  {
    title: "Worker 黑盒探索",
    description: "多个 worker 分别枚举目录、测试参数和读取共享黑板，避免重复探索。",
    log: "[WEB-DEMO-001:W1] dirsearch 发现 /admin/login 与 /api/debug",
  },
  {
    title: "写入共享黑板",
    description: "watcher 将关键事实整理成共享信息，solver 认领下一步探索方向。",
    log: "[KeyInfo] 发现调试接口 /api/debug?token=guest",
  },
  {
    title: "构造利用请求",
    description: "Agent 复用黑板信息访问调试接口，响应中出现候选 flag。",
    log: "[WEB-DEMO-001:W2] GET /api/debug?token=guest 返回 flag{cruiser_demo_success}",
  },
  {
    title: "提交并确认 flag",
    description: "submit_flag 通过平台 SDK 校验成功，本题流程收束并关闭容器。",
    log: "[SUBMIT_FLAG][OK] 提交正确，本次得分 100，flag 进度 1/1",
    flag: "flag{cruiser_demo_success}",
  },
];

function setDemoResult(step) {
  demoTitle.textContent = step.title;
  demoDescription.textContent = step.description;
  if (step.flag) {
    demoResult.classList.add("done");
    demoFlag.textContent = step.flag;
  } else {
    demoResult.classList.remove("done");
    demoFlag.textContent = "搜索中...";
  }
}

function resetDemo() {
  if (demoTimer) {
    clearInterval(demoTimer);
    demoTimer = null;
  }
  demoStep = 0;
  running = false;
  runButton.innerHTML = '<span class="button-icon" aria-hidden="true">▶</span> 启动巡航';
}

function runDemoStep() {
  const step = demoSteps[demoStep];
  if (!step) {
    addLog("[Main] demo 演示完成，已清理 worker 与容器");
    resetDemo();
    return;
  }
  setDemoResult(step);
  addLog(step.log);
  syncState();
  if (step.flag) {
    bumpMetrics();
  }
  demoStep += 1;
}

document.querySelectorAll(".segment").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    currentFilter = button.dataset.filter;
    renderQueue();
  });
});

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    const view = button.dataset.view;
    const target = view === "workers"
      ? document.querySelector(".workers-module")
      : view === "blackboard"
        ? document.querySelector(".blackboard-module")
        : view === "toolchain"
          ? document.querySelector(".toolchain-section")
          : document.querySelector(".metrics-grid");
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

runButton.addEventListener("click", () => {
  if (running) {
    addLog("[Main] 收到停止信号，demo 已停止");
    resetDemo();
    return;
  }
  running = true;
  demoStep = 0;
  demoResult.classList.remove("done");
  demoFlag.textContent = "搜索中...";
  runButton.innerHTML = '<span class="button-icon" aria-hidden="true">■</span> 停止巡航';
  addLog("[Main] demo: uv run python main.py --sessions 5");
  runDemoStep();
  demoTimer = setInterval(runDemoStep, 1400);
});

syncButton.addEventListener("click", syncState);
clearLogs.addEventListener("click", () => {
  logLines.length = 0;
  renderLogs();
});

shuffleWorkers.addEventListener("click", () => {
  workers.push(workers.shift());
  addLog("[Main] worker 模型搭配已重排");
  renderWorkers();
});

themeToggle.addEventListener("click", () => {
  document.body.classList.toggle("dark");
  localStorage.setItem("cruiser-theme", document.body.classList.contains("dark") ? "dark" : "light");
});

if (localStorage.getItem("cruiser-theme") === "dark") {
  document.body.classList.add("dark");
}

renderQueue();
renderWorkers();
renderBlackboard();
renderTools();
renderLogs();
