# Cruiser 技术方案文档

> 面向 CTF 竞赛评测平台（TSec Benchmark）的自动化 Web/逻辑漏洞挖掘与利用 Agent

![Cruiser 概念图](assets/cruiser_cover.png)

| 项目 | 说明 |
|------|------|
| 文档版本 | v1.1 |
| 文档日期 | 2026-08-31 |
| 适用代码基线 | Cruiser 主分支（`main.py` + `cruiser/` 包） |
| 读者对象 | 安全研究人员、Agent 系统开发者、评测平台对接方 |

---

## 目录

1. [概述](#1-概述)
2. [总体架构](#2-总体架构)
3. [核心子系统设计](#3-核心子系统设计)
4. [分层调度机制](#4-分层调度机制)
5. [多会话协作机制](#5-多会话协作机制)
6. [Flag 权威校验与多 Flag 处理](#6-flag-权威校验与多-flag-处理)
7. [LLM 接入与多模型路由](#7-llm-接入与多模型路由)
8. [平台对接流程（TSec Benchmark SDK）](#8-平台对接流程tsec-benchmark-sdk)
9. [靶场网络接入（VPN）](#9-靶场网络接入vpn)
10. [工具链与离线知识库](#10-工具链与离线知识库)
11. [配置体系](#11-配置体系)
12. [并发安全与容错设计](#12-并发安全与容错设计)
13. [可观测性](#13-可观测性)
14. [部署与运行](#14-部署与运行)
15. [性能调优建议](#15-性能调优建议)
16. [风险与限制](#16-风险与限制)
17. [演进方向](#17-演进方向)
18. [附录](#18-附录)

---

## 1. 概述

### 1.1 背景

CTF（Capture The Flag）竞赛评测平台（TSec Benchmark）以「跑分任务」的形式向被测 Agent 下发一批 Web/逻辑漏洞题目。每道题对应一个按需启动的靶场容器，Agent 需通过靶场 VPN 直连容器地址，完成漏洞挖掘与利用，拿到 flag 并提交评分。

人工解题无法匹配评测的吞吐要求，因此 Cruiser 的设计目标是：**以完全自动化的方式完成「拉取题目 → 启动靶场容器 → 驱动 Agent 解题 → 提交 flag → 关闭容器」的完整闭环**，并通过多进程并发、分层调度与跨会话共享记忆机制，在平台活跃容器名额约束下最大化解题吞吐与成功率。

### 1.2 设计目标

| 目标 | 说明 | 对应机制 |
|------|------|----------|
| 全自动闭环 | 无需人工干预跑完整轮评测 | 主进程调度循环 + SDK 对接 |
| 高吞吐 | 容器名额（默认 3）始终打满 | 分层调度 + 动态并行 + 僵尸容器回收 |
| 高成功率 | 难题多轮尝试、多视角探索 | 四级晋升调度 + 多会话黑板共享 + 提示分级启用 |
| 崩溃可恢复 | 任意一层进程死亡不影响全局 | 三层进程边界 + 进程组回收 + 孤儿清理兜底 |
| 结果可信 | flag 必须由平台确认，不信任模型自述 | 框架权威校验 + 程序化补交 |
| 资源合规 | 遵守比赛规则（禁联网检索、提示扣分最小化） | 禁用 WebSearch/WebFetch + 提示延迟到三级启用 |

### 1.3 设计原则

1. **进程边界清晰**：调度、执行、智能体三层进程各司其职，单层崩溃可独立恢复。
2. **文件系统即总线**：跨进程协作不引入消息队列/数据库，全部通过 `reports/` 目录下的文本文件完成，以 `fcntl` 文件锁 + 临时文件 `os.replace` 原子重写保证并发安全。
3. **不信任模型自述**：flag 有效性、进度完成度均以平台 SDK 的同步返回为唯一事实来源。
4. **上下文硬注入**：关键协作信息（题目描述/提示/黑板）通过 Claude Code 钩子物理注入模型上下文，不依赖模型自觉读取文件。
5. **表驱动可扩展**：LLM 提供方接入采用注册表 + 模型名前缀路由，新增一家提供方只需加两行配置。

### 1.4 术语约定

| 术语 | 含义 |
|------|------|
| 题目 / Challenge | 平台下发的一道 CTF 题，有唯一 `unique_code`，可能包含多个 flag |
| 会话 / Session | 一次完整的 `claude` CLI 解题对话 |
| Worker | 执行层子进程（`main.py --sessions 1` 副本），每个 worker 拉起一个 claude 会话 |
| Solver | 定向 worker：只认领任务板上的一条探索方向并聚焦执行 |
| Watcher | 后台策展 LLM：审阅会话活动，维护黑板质量、发布探索方向 |
| 黑板 / Blackboard | 跨会话共享的关键事实文件 `reports/info_<code>.txt` |
| 任务板 / Task Board | 待认领探索方向文件 `reports/tasks_<code>.txt` |
| `[COUNT]` | worker 打印的步数计数（每个 assistant 事件 +1），调度器据此判定层级阈值 |
| turn | claude CLI 的回合数（`--max-turns`），与 `[COUNT]` 不同口径，约为数倍关系 |

---

## 2. 总体架构

### 2.1 三层进程架构

Cruiser 的解题引擎基于 [`claude` CLI](https://docs.anthropic.com/en/docs/claude-code)（`--output-format stream-json` 流式模式）驱动一个自主 Agent，Anthropic 兼容端点默认接入 DeepSeek。系统分为三层进程：

```mermaid
flowchart TB
    subgraph L1["调度层（main.py 主进程）"]
        SCH["分层调度循环<br/>拉题 / 晋级 / 限流"]
        VPNM["VPN 管理<br/>openvpn + 路由修复"]
        CTRM["容器治理<br/>启动 / 预热 / 回收僵尸"]
        REAP["进程治理<br/>atexit killpg / 孤儿清理"]
        DASH["运行台 dashboard.py<br/>:8765"]
    end

    subgraph L2["执行层（worker 子进程 × N）"]
        W1["worker #1<br/>run_auto_scan()"]
        W2["worker #2<br/>run_auto_scan()"]
        W3["worker #3<br/>run_auto_scan()"]
    end

    subgraph L3["Agent 层（claude CLI 进程 × N）"]
        C1["claude 会话 #1<br/>Bash/Read/Write 工具"]
        C2["claude 会话 #2"]
        C3["claude 会话 #3"]
    end

    subgraph EXT["外部依赖"]
        SDK[("TSec Benchmark 平台<br/>list/start/hint/submit/close")]
        LLM[("LLM 端点<br/>DeepSeek / Kimi / GLM")]
        RANGE[("靶场容器群<br/>经 VPN 直连")]
    end

    subgraph FS["文件系统总线（reports/）"]
        BB["info_&lt;code&gt;.txt<br/>共享黑板"]
        TB["tasks_&lt;code&gt;.txt<br/>任务板"]
        HINT["hint_&lt;code&gt;.txt / desc_&lt;code&gt;.txt"]
        RT["_runtime.json 运行态快照"]
    end

    SCH -->|spawn 子进程| W1 & W2 & W3
    SCH --> DASH
    DASH --> BB & TB & HINT & RT
    SCH -->|写入快照| RT
    W1 --> C1
    W2 --> C2
    W3 --> C3
    SCH <-->|SDK| SDK
    W1 -.->|SDK 权威校验 flag| SDK
    C1 & C2 & C3 <-->|Anthropic 兼容端点| LLM
    C1 & C2 & C3 -->|渗透/利用| RANGE
    C1 & C2 & C3 <-->|读写（文件锁+原子重写）| BB & TB
    SCH -->|写入| HINT
```

进程链：

```
main.py（调度器）→ main.py --sessions 1（worker）→ claude CLI → bash/python 工具子进程
```

各层职责与崩溃隔离：

| 层 | 进程 | 职责 | 崩溃影响面 |
|----|------|------|------------|
| 调度层 | `main.py` 主进程 | 唯一与平台交互的进程：轮询未解题目、分层调度、spawn worker、监控 `[COUNT]` 步数、回收容器与孤儿进程、拉起运行台 | 全局退出，`atexit` 整组清理 worker 并关闭活跃容器 |
| 执行层 | worker 子进程（带 `CRUISER_WORKER_ID`） | 调用 `run_auto_scan()`，拉起并解析 claude 流式输出，触发 watcher，权威校验 flag | 单题单会话失败，不影响其他题目 |
| Agent 层 | `claude` CLI 进程 | 真正的解题智能体，用内置 Bash/Read/Write 工具侦察与利用 | 会话结束，worker 收尾后可重启新会话 |

### 2.2 端到端数据流

```mermaid
sequenceDiagram
    autonumber
    participant M as 主进程(调度器)
    participant P as TSec 平台
    participant W as Worker 进程
    participant C as claude CLI
    participant R as 靶场容器
    participant F as reports/ 文件总线

    loop 调度主循环（1s 周期）
        M->>P: list_challenges() 拉取未解题目
        P-->>M: 题目列表 + 容器状态 + flag 进度
        M->>P: start_challenge(code)（名额允许时）
        P-->>M: container_addr（IP:端口 数组）
        M->>M: 端口就绪探测（≤60s）+ 写 desc_<code>.txt
        M->>W: spawn（注入目标/题目码/模型/温度等环境变量）
        W->>F: 注册 .claude/settings.json 钩子
        W->>C: claude -p <任务提示> --output-format stream-json
        C->>F: SessionStart 钩子注入 描述+提示+黑板
        loop 解题循环
            C->>R: 侦察 / 漏洞验证 / 利用（Bash 工具）
            R-->>C: 响应（含 flag 线索）
            C->>F: PostToolUse 每 10 步注入最新黑板
            W->>W: 默认每 4 步后台触发 watcher 策展
            C->>P: submit_flag.py 提交候选 flag
            P-->>C: correct / awarded / 进度 X/Y
        end
        C-->>W: stream-json 结束（result 事件）
        W->>P: 收尾：对所有 flag 候选程序化补交校验
        W-->>M: 输出 {"flag": ...} 或 达到步数阈值
        M->>P: close_challenge(code) 释放名额
    end
```

### 2.3 关键技术选型

| 维度 | 选型 | 理由 |
|------|------|------|
| Agent 运行时 | `claude` CLI（stream-json headless 模式） | 成熟的工具调用循环、上下文压缩、钩子机制；避免自研 ReAct 循环的可靠性问题（旧 `cruiser/agent.py` 手写 ReAct 引擎已弃用保留参考） |
| 解题模型 | DeepSeek（默认 `deepseek-v4-flash`） | 经 Anthropic 兼容端点接入，1M 上下文窗口 |
| 策展模型 | `deepseek-v4-pro` | 黑板策展与方向规划需要更强推理能力 |
| 进程间通信 | 文件系统 + `fcntl` 锁 + `os.replace` | 零外部依赖、崩溃一致性好、可人工检视 |
| 平台对接 | `tsec-benchmark` SDK（httpx） | 官方封装：VPN 预检、题目/容器/提交生命周期、错误码体系 |
| 包管理 | uv + `pyproject.toml` | 快速、可锁定（`uv.lock`）；离线镜像整份分发虚拟环境 |

---

## 3. 核心子系统设计

### 3.1 项目结构

```
Cruiser/
├── main.py                  # CLI 入口：平台调度、多会话并发、分层调度、容器/进程治理、运行台
├── blackboard_hook.py       # Claude Code 钩子：描述/提示/黑板硬注入模型上下文
├── kill_orphans.py          # 悬空 worker/claude 进程清理兜底
├── frontend/                # 运行台静态资源（console.js / console.css / index.html）
├── tools/                   # Agent 调用的 CLI 封装脚本
│   ├── submit_flag.py       # 命令行提交 flag（经 SDK 平台确认）
│   ├── dirsearch_scan.py    # 跨会话去重的目录扫描（同一 URL 只实扫一次）
│   ├── task_board.py        # 探索方向任务板命令行（list/claim/report）
│   └── decompile.py         # PyGhidra 无头反编译 CLI
├── pyproject.toml           # 项目配置与依赖声明
├── cruiser/
│   ├── __init__.py          # 包初始化：禁用 LangSmith 追踪、加载 .env
│   ├── claude_agent.py      # 当前解题引擎：claude CLI 驱动 + 黑板 watcher
│   ├── dashboard.py         # 运行台 HTTP：快照 / 黑板 / 任务板 / 日志
│   ├── runtime.py           # 调度器运行态快照（供运行台读取）
│   ├── taskboard.py         # 任务板读写（文件锁 + 原子重写）
│   ├── llm.py               # LLM 提供方注册表与路由（DeepSeek / Kimi / GLM）
│   ├── prompt.py            # 系统提示词与任务模板
│   ├── tools.py             # SDK 客户端、submit_flag、dirsearch/xss 等工具
│   └── agent.py             # 旧版手写 ReAct 引擎（已弃用，保留供参考）
├── resource/                # 用户名/密码/XSS payload/flag 线索字典
├── kb/                      # 离线漏洞知识库（git submodule：vulhub / nuclei-templates / PayloadsAllTheThings；nuclei 二进制需自行下载）
├── vpn/                     # 靶场 VPN 配置（空目录入库；*.ovpn 不入库）
├── doc/                     # SDK 接入文档 + 本文档
└── reports/                 # 运行时共享黑板 / 任务板 / 提示 / 描述 / 运行态快照（空目录入库）
```

### 3.2 调度层（`main.py` 主进程）

主进程是系统中**唯一与平台交互**的进程（worker 仅以 `submit_flag.py` 形式做权威校验提交），职责包括：

1. **启动自检**
   - `ensure_vpn_connected()`：SDK 预检 VPN，不通则自动用 `vpn/` 下最新 `.ovpn` 配置拉起 openvpn 并修复推送路由（详见 §9）；`vpn/` 为空时跳过 VPN 直接答题。文件锁 `/tmp/cruiser_vpn.lock` 防止并发重复连接。
   - `close_all_containers()`：关闭所有平台侧仍在运行的容器（含已完成题目的残留），确保从干净状态开始。

2. **调度主循环**（1 秒周期）
   - `fetch_all_unsolved()` 拉取未解题目及进度；
   - 与内存中的层级队列（`preprocessed / tier1 / tier2 / tier3 / solved`）对账：题目从平台消失时触发对应会话组的强杀（`kill_flags[code].set()`）；
   - 僵尸容器回收：平台侧仍在运行但本地无在飞线程的容器，由后台线程逐个关闭，避免挤占活跃名额；
   - 按层级依次尝试启动各题的执行器线程，受 `MAX_INFLIGHT`（`CRUISER_MAX_ACTIVE`，默认 3）严格限流。

3. **worker 生命周期管理**
   - `spawn_worker()`：以 `main.py --sessions 1 --challenge-code <CODE>` 形式 fork 子进程，注入 `CRUISER_WORKER_ID`（兼作「跳过 VPN/容器管理」的身份标记）、`CRUISER_WORKSPACE_DIR`、目标地址、模型（`ANTHROPIC_MODEL`）等环境变量；worker 以 `start_new_session` 启动为**独立进程组**。
   - `reader_thread()`：逐行读取 worker 输出，解析 `[COUNT]`，把日志推入运行态；整题是否解出以 SDK 轮询（`is_completed` / flag 进度）为准。
   - 退出清理：`atexit` + SIGINT/SIGTERM 处理器对所有 worker 进程组 `killpg`，并关闭活跃容器；`kill_orphans.py` 作为父进程意外死亡后的悬空进程兜底清理。

4. **冷却与去重**
   - `_in_cooldown()` 防止同一题被频繁重启；
   - skipped（容器未就绪、本轮未实际执行）与 remaining（实际执行但未解出）严格区分——skipped 不消耗层级进度，留在原层重试。

### 3.3 执行层（worker 子进程）

worker 是 `main.py` 自身的副本，因带 `CRUISER_WORKER_ID` 而跳过 VPN/容器管理，直接调用 `cruiser.claude_agent.run_auto_scan()`：

1. 按是否带 `solver_task` 选择系统提示词与任务模板（普通探索 / solver 定向模式）；
2. 在工作空间写入 `.claude/settings.json` 注册黑板钩子（见 §5.2）；
3. 拉起 `claude` CLI 子进程（**不**使用 `start_new_session`，使其留在本进程组内，调度器 `killpg` 时可整组回收）；
4. 逐行解析 stream-json 事件流：
   - `assistant` 事件：`[COUNT]` 步数 +1、提取文本与工具调用、滚动维护最近活动摘要（默认 `deque(maxlen=48)`，`CRUISER_WATCHER_RECENT`）、默认每 4 步（`CRUISER_WATCHER_EVERY`）触发一次后台 watcher、捕获模型提交的 flag 并**当场权威校验**；
   - `user` 事件（工具结果）：正则收集 `flag{...}` 候选，追加观察摘要；
   - `result` 事件：会话结束（success / error_max_turns / error_*），跳出循环；
5. 收尾：会话结束时同步触发一次最终 watcher（30s 超时保护），并对全部 flag 候选逐个程序化补交校验（命中即输出 `[FLAG RECOVERED]`）。

### 3.4 Agent 层（`claude` CLI 进程）

Agent 层的启动命令形态：

```bash
claude -p "<任务提示>" \
  --output-format stream-json --verbose \
  --permission-mode bypassPermissions \
  --append-system-prompt "<系统提示>" \
  --disallowedTools "WebSearch,WebFetch" \
  [--max-turns N]
```

设计要点：

- **禁联网检索**：CTF 比赛禁止联网检索，显式从工具集移除 `WebSearch`/`WebFetch`（headless 下 `bypassPermissions` 会自动放行，必须显式禁用）。
- **系统提示词**（`cruiser/prompt.py`）：定位「Web 漏洞 + 逻辑漏洞」解题专家，覆盖 SQL 注入、XSS（目标为弹窗 `XSS` 字符串）、CSRF、文件包含、文件上传、越权、竞态、业务逻辑等类别的识别与利用套路，并内置工程化守则：
  - 批量/并发策略：爆破枚举类任务必须写脚本或用 `seq | xargs -P N` 并发，禁止逐请求手工尝试；
  - 工具纪律：调用安全工具先 `-h/--help`；目录扫描必须走 `dirsearch_scan` 工具（跨会话去重 + 报告落盘，避免上下文溢出）；flag 只能经 `submit_flag` 工具提交；
  - 产物落盘：大输出写入 `$CRUISER_WORKSPACE_DIR` 后再读取筛选，避免撑爆上下文。
- **上下文窗口管理**：通过 `CLAUDE_CODE_MAX_CONTEXT_TOKENS`（默认 1,000,000）声明真实窗口，`CLAUDE_CODE_AUTO_COMPACT_WINDOW`（默认 800,000）提前触发 auto-compact，留余量避免逼近硬上限。

---

## 4. 分层调度机制

### 4.1 层级模型

新题在四个队列间逐级晋升，每级步数阈值递增；任一会话解出 flag 即整组停止。提示（hint）会按比例扣减得分，因此**延迟到三级才启用**——先用纯黑盒能力尝试，必要时再付出代价。

```mermaid
stateDiagram-v2
    [*] --> 预处理 : 新题出现
    预处理 --> 已解决 : 出 flag
    预处理 --> 一级 : 50 步未解出
    一级 --> 已解决 : 出 flag
    一级 --> 二级 : 100 步未解出
    二级 --> 已解决 : 出 flag
    二级 --> 三级 : 150 步未解出
    三级 --> 已解决 : 出 flag
    三级 --> 三级 : 200 步未解出<br/>放回队尾循环重试（带提示）
    已解决 --> [*]
```

| 层级 | 触发条件 | 步数阈值 | 是否带提示 | 未解出去向 |
|------|----------|----------|------------|------------|
| 预处理 | 新题 | 50 | 否 | 晋级一级 |
| 一级 | 预处理未解出 | 100 | 否 | 晋级二级 |
| 二级 | 一级未解出 | 150 | 否 | 晋级三级 |
| 三级 | 二级未解出 | 200 | 是 | 放回队尾，按 200 步循环重试 |

补充规则：

- 一级队列按题目难度排序（`DIFF_RANK`），优先打简单题，快速积累得分；
- **skipped 语义**：容器未就绪导致本轮根本没执行的题，不算尝试过、不晋级，留在原层等待下一轮；
- 每一级对同一道题并发拉起 `--sessions` 个**黑盒** worker 会话（全程黑盒，无源码审计），各会话独立探索、以不同会话编号署名；
- 所有 worker 均为主力波（wave=2），全部计入步数阈值；阈值判定以**单会话** `[COUNT]` 达到阈值为准。

### 4.2 单轮执行流程（`run_parallel_stage`）

```mermaid
flowchart TD
    A[进入一轮 stage<br/>codes + 阈值 + 提示策略] --> B{遍历每道题}
    B --> C{已有可用地址?}
    C -->|是| D[复用平台侧在运行容器<br/>记入关闭清单]
    C -->|否| E[start_challenge 启动容器<br/>端口就绪探测 ≤60s]
    D --> F
    E --> F{拿到地址?}
    F -->|否| G[本轮跳过 skipped]
    F -->|是| H{prefetch_hint?}
    H -->|是| I[get_hint 拉取提示<br/>写 hint_code.txt]
    H -->|否| J
    I --> J[写 desc_code.txt<br/>spawn N 个 worker 间隔 2s]
    J --> K[reader 线程逐行监控:<br/>COUNT 阈值 / flag 进度 X-Y / 最终 JSON]
    K --> L{任一 worker 解出<br/>且 flag 集齐?}
    L -->|是| M[置 winner<br/>整组 killpg 停止]
    L -->|否, 达阈值| N[stop_threshold<br/>整组停止]
    M --> O[统一 close_challenge<br/>释放名额]
    N --> O
    O --> P[返回 flagged / remaining / skipped]
```

### 4.3 活跃名额限流

- 平台限制同时活跃的容器数，`MAX_INFLIGHT = CRUISER_MAX_ACTIVE`（默认 3），超过上限的启动请求会被平台拒绝（`InvalidState: max active`）；
- 调度循环每轮检查 `_inflight_count() >= MAX_INFLIGHT` 即停止派发新题，剩余题目留待下一轮；
- 僵尸容器回收器持续释放被占用的名额，避免「平台侧在跑、本地没跟踪」的泄漏导致新题无法启动。

---

## 5. 多会话协作机制

多会话并发的核心矛盾是：**既要独立探索（视角多样性），又要共享发现（避免重复劳动）**。Cruiser 用「共享黑板 + 任务板 + 硬注入钩子 + 策展 watcher」四件套解决。

### 5.1 协作机制总览

```mermaid
flowchart LR
    subgraph 会话侧
        C1[会话 #1] 
        C2[会话 #2]
        C3[会话 #3]
    end

    subgraph 注入通道
        HK["blackboard_hook.py<br/>SessionStart / PostToolUse(每10步)"]
    end

    subgraph 文件总线["reports/（fcntl 锁 + 原子重写）"]
        BB["info_&lt;code&gt;.txt 共享黑板"]
        TB["tasks_&lt;code&gt;.txt 任务板<br/>+ .claimed 认领日志"]
        DK["desc/hint_&lt;code&gt;.txt"]
    end

    subgraph 策展侧
        WA["Watcher LLM (deepseek-v4-pro)<br/>默认每 4 步后台审阅"]
    end

    C1 & C2 & C3 -->|写入发现/任务回报| BB
    WA -->|add/update/remove| BB
    WA -->|publish/retire| TB
    C1 & C2 & C3 -->|claim 认领(先到先得)| TB
    BB & TB & DK --> HK
    HK -->|additionalContext 硬注入| C1 & C2 & C3
    C1 & C2 & C3 -.->|默认每4步活动摘要触发| WA
```

### 5.2 上下文硬注入（`blackboard_hook.py`）

不依赖模型自觉去读黑板文件，而是在 worker 工作目录写入 `.claude/settings.json` 注册 Claude Code 钩子，让内容**物理进入模型上下文**：

| 钩子事件 | 触发时机 | 注入内容 |
|----------|----------|----------|
| `SessionStart` | 会话开局一次 | 题目描述 + 题目提示 + 当前黑板（各若非空） |
| `PostToolUse` | 每 10 次工具调用 | 上述三项的最新内容，并标注「请关注并利用其他会话的新发现」 |

- 注入通道为 `hookSpecificOutput.additionalContext`；
- 单项截断 3000 字符（黑板取**尾部** 3000 字符，保留最新发现），防止上下文被协作信息淹没；
- 钩子按 `CRUISER_CHALLENGE_CODE` 定位该题的文件，无内容可注入时不输出任何东西（零开销）。

### 5.3 共享黑板与策展 Watcher

黑板 `reports/info_<code>.txt` 保存各会话已发现的关键事实（口令、路径、端点、结论等），条目格式：

```
[2026-08-15 12:00:00] 会话: 2
关键信息: /admin 存在越权，无需鉴权可读取用户列表
------------------------------------------------------------
```

**Watcher 策展**（`_watcher_curate_blackboard`）：

- 每个会话默认每 4 步（`CRUISER_WATCHER_EVERY`）在后台线程触发一次（单 watcher 并发闸 `busy` 标志防重入）；会话结束时强制补一次尾部采集（30s join 超时，防止 daemon 线程随进程退出丢失最后发现）；
- watcher LLM（`deepseek-v4-pro`，策展与方向规划需要更强推理）基于：题目描述 + 提示 + 最近活动窗口（默认 48 条，近 12 条保留全文）+ 当前黑板 + 任务板（待认领/执行中），产出结构化 JSON：
  - `add`（≤3 条）：提取新关键信息（普通条目不超过 80 字）；**不写入具体 flag 值，也不新增 `[flag方法]`**；
  - `update`（≤3 条）：修正过时/错误条目（保留原头部的时间戳与会话归属，仅替换信息内容；不改 `[flag方法]`）；
  - `remove`（≤3 条）：删除失效条目（含具体 flag 值的条目一律删；`[flag方法]` 除非漏了 flag 字面量否则不删）；
  - `suggest_tasks`（≤2 条）：向任务板推荐新探索方向；
  - `retire_tasks`（≤3 条）：下架重复/过时方向；
- **并发安全应用变更**：LLM 审阅基于无锁快照；应用变更时持文件锁重读最新内容，按**内容模糊匹配**（归一化包含关系或字符 bigram 重叠系数 ≥ 0.6）定位条目——不用行号，规避并发编辑导致的行号漂移；写回走临时文件 + `os.replace` 原子替换；
- watcher 失败静默吞掉，绝不影响解题主流程；
- 附带职责：从活动与黑板中提取 `flag{...}` 候选并程序化兜底提交——**watcher 也能交 flag**（同一段超过 5 个候选视为爆破输出，不自动交）；
- **`[flag方法]`**：首次提交成功时由该会话分叉写入（漏洞点/请求/步骤，不含 flag 字面量），供其他会话复现剩余 flag；watcher 不增删改。

### 5.4 探索方向任务板（`cruiser/taskboard.py`）

任务板 `reports/tasks_<code>.txt` 用于把「接下来值得试什么」显式化，行格式 `[t-xxxxxx] 方向内容`：

```mermaid
sequenceDiagram
    participant WA as Watcher
    participant L as 锁(tasks.lock)
    participant TB as tasks_code.txt
    participant CL as tasks_code.txt.claimed
    participant W as Worker/Solver

    WA->>L: publish_task(方向)
    L->>TB: 判重(待认领+近期已认领)<br/>板满(≥5)拒发
    L-->>WA: 写入/拒绝
    W->>L: claim_task(worker_id)
    L->>TB: 锁内找到并擦除条目（先到先得）
    L->>CL: 追加认领记录 ts|worker|text
    L-->>W: 返回方向 / None(已被抢)
    W->>BB: report_task 完成回报（写入黑板）
```

关键参数与规则：

| 项 | 值 | 说明 |
|----|----|------|
| `_MAX_PENDING` | 5 | 板上最多待认领方向数，超过不再发布 |
| `_CLAIMED_TTL_S` | 45 分钟 | 认领擦除后的方向仍参与判重（防 watcher 重复发布）；超时自动解冻，避免认领方异常死亡导致方向永久锁死 |
| 判重算法 | 归一化包含 / bigram ≥ 0.6 | 消除路径分隔符、标点、空白差异的相似方向判定 |
| 认领语义 | 锁内擦除 | 多 worker 并发认领同一方向时只有一个成功 |

### 5.5 Solver 定向执行

除普通探索 worker 外，每题还有一个 `solver_driver` 线程：

- 维持 ≤ `CRUISER_MAX_SOLVERS`（默认 3）个并发 solver；
- 每个 solver 从任务板 **FIFO 认领一条方向**，以聚焦的系统提示词（`CLAUDE_SOLVER_SYSTEM_PROMPT` + 任务模板）启动定向会话，回合上限 `CRUISER_SOLVER_MAX_TURNS`（默认 40），模型 `CRUISER_SOLVER_MODEL`（默认 `deepseek-v4-flash`）；
- solver 退出即回收补位；整题出 flag 或本轮结束时停止并清杀所有 solver；
- 与探索 worker 的关系：探索 worker 广撒网、自然发现并写黑板；watcher 把「值得深挖但未做」的方向显式化到任务板；solver 按需领任务做定向突破，三者形成「探索 → 策展 → 攻坚」的闭环。

---

## 6. Flag 权威校验与多 Flag 处理

### 6.1 权威校验原则

**不信任模型输出的任何文本标记**（包括模型自称「提交成功」），flag 有效性唯一以平台 SDK 的同步返回为准：

```mermaid
flowchart TD
    A[捕获 flag 候选<br/>submit 工具调用 / assistant 文本 / 工具结果] --> B{形态合法?<br/>_looks_like_flag}
    B -->|否| Z[丢弃]
    B -->|是| C{已核实过?}
    C -->|是| Z
    C -->|否| D[框架亲自调用 submit_flag.py<br/>提交平台]
    D --> E{平台返回 correct / duplicate?}
    E -->|是| F[记录进度；全部 flag 到手才停整题]
    E -->|否| G[继续解题<br/>候选留待收尾复核]
```

- `_verify_flag()` 对同一候选只核实一次（`verified` 集合去重），避免重复提交；返回结构化 `FlagSubmitOutcome`（含 `correct/total`），多 flag 未集齐时会话继续；
- **当场校验**：模型一调用提交工具，框架立即亲自向平台核实；
- **收尾补交**：会话结束（出 flag / 达轮数上限 / 自然结束）时，对全部合法候选按长度降序逐个补交——覆盖「flag 在最后一回合找到、提交命令被 `--max-turns` 切断」等情况，命中打印 `[FLAG RECOVERED]`；
- watcher 策展前也先执行一轮候选兜底提交（即便无可用 watcher LLM 也能补交）；
- 同一段文本出现超过 5 个 `flag{...}` 视为爆破/枚举输出，框架不自动提交（模型主动调用 `submit_flag.py` 仍放行）。

### 6.2 多 Flag 题目的完成判定

一道题可能有多个 flag（`flag_count > 1`），规则：

- `submit_flag` 的同步返回包含「flag 进度 X/Y」，框架记入 `FlagSubmitOutcome`；
- **仅当平台 `is_completed` 或 `correct_flag_count ≥ flag_count` 才判定整题解出**、置 winner 停止整组（调度器以 SDK 轮询为准，不解析 worker 的最终 JSON）；
- 单会话内未集齐全部 flag 时继续运行，不因交对一枚就结束。

---

## 7. LLM 接入与多模型路由

### 7.1 表驱动提供方注册表（`cruiser/llm.py`）

所有「连哪家模型/端点/用哪把 key」的逻辑集中在 `llm.py`，采用**注册表 + 模型名前缀路由**：

```mermaid
flowchart LR
    M[模型名] --> P{前缀匹配<br/>MODEL_PREFIX_TO_PROVIDER}
    P -->|"deepseek*"| DS[deepseek 提供方<br/>DEEPSEEK_API_KEY]
    P -->|"kimi-* / moonshot*"| KM[kimi 提供方<br/>KIMI_API_KEY]
    P -->|"glm-* / chatglm* / zhipu*"| GLM[glm 提供方<br/>GLM_API_KEY]
    P -->|未命中| DS
    DS --> E1[Anthropic 端点<br/>claude CLI 用]
    DS --> E2[OpenAI 兼容端点<br/>langchain watcher 用]
    KM --> E1
    KM --> E2
    GLM --> E1
    GLM --> E2
```

| 提供方 | 密钥环境变量 | 比赛内网端点（默认） | 本地端点（`--local`） |
|--------|--------------|----------------------|------------------------|
| deepseek | `DEEPSEEK_API_KEY` | `http://api.deepseek.com.tsecbench.gw/{anthropic,v1}` | `https://api.deepseek.com/{anthropic,v1}` |
| kimi (moonshot) | `KIMI_API_KEY` | `http://api.moonshot.cn.tsecbench.gw/{anthropic,v1}` | `https://api.moonshot.cn/{anthropic,v1}` |
| glm（TokenHub） | `GLM_API_KEY` | `http://tokenhub.tencentmaas.com.tsecbench.gw` | `https://tokenhub.tencentmaas.com` |

端点解析优先级：**显式环境变量覆盖 > 本地模式官方域名 > 比赛内网域名**。新接一家提供方只需在 `PROVIDERS` 注册表加一条配置 + 在 `MODEL_PREFIX_TO_PROVIDER` 加前缀，无需改任何调用方。

### 7.2 双通道消费

| 消费方 | 通道 | 配置来源 |
|--------|------|----------|
| 解题引擎（claude CLI） | Anthropic 兼容端点（`ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_MODEL`） | `get_claude_provider_env()`，密钥缺失时回退显式 `ANTHROPIC_AUTH_TOKEN` |
| watcher / 旧 ReAct 引擎 | OpenAI 兼容端点（langchain `ChatOpenAI`） | `_build_chat_openai()`，无密钥/依赖时返回 None 静默降级 |

### 7.3 多模型混编与温度分片

- `--worker-models deepseek-v4-flash,deepseek-v4-flash,kimi-k3`：worker 数量 = 清单长度（覆盖 `--sessions`），第 i 个 worker 用第 i 个模型，不同厂商可混搭（按模型名自动路由端点与密钥）；
- 默认模型分工：解题 `deepseek-v4-flash`（`DEEPSEEK_MODEL`/`ANTHROPIC_MODEL` 覆盖）、watcher `deepseek-v4-pro`（`WATCHER_MODEL` 覆盖）、solver `deepseek-v4-flash`（`CRUISER_SOLVER_MODEL` 覆盖）；
- **温度分片**（langchain 路径）：按 worker 编号在 `[CRUISER_TEMP_MIN, CRUISER_TEMP_MAX]`（默认 0.0 ~ 0.9）线性分配——低编号会话确定性高、高编号会话发散性强，用温度梯度制造探索多样性。

---

## 8. 平台对接流程（TSec Benchmark SDK）

平台对接全部走官方 `tsec-benchmark` SDK（详见 `doc/SDK_API.md`），Cruiser 在其上做的工程化增强：

| SDK 能力 | Cruiser 的使用方式 |
|----------|--------------------|
| 上下文管理器入口 VPN 预检（`VpnCheckError`） | 兼作「VPN 是否已连」的探测信号，驱动自动重连逻辑（§9） |
| `list_challenges()` | 1s 周期轮询，过滤 `is_completed`，同步容器状态做僵尸回收与对账 |
| `start_challenge(code)` | 受 `MAX_INFLIGHT` 限流；返回 `container_addr`（`IP:端口` 数组，可能多个），拼为 `http://` 目标串 |
| `get_hint(code)` | **三级才调用**（提示按比扣分），落盘 `hint_<code>.txt` 全会话共享 |
| `submit_flag(code, flag)` | 唯一可信提交通道；`DuplicateSubmit` 视为幂等成功 |
| `close_challenge(code)` | 每轮结束统一关闭 + 启动时全量清理 + 僵尸后台回收，三道防线防泄漏 |

容器就绪探测（`CRUISER_CONTAINER_WARMUP`，默认 60s）：拿到地址后主动探测目标端口，可连即拉起会话；**超时也放行**交由 LLM 解题，防止平台侧慢启动卡死调度。

错误处理映射：

| 平台异常 | 处理策略 |
|----------|----------|
| `VpnCheckError` | 触发自动重连 VPN |
| `InvalidState`（`max active`） | 名额已满，本轮跳过，下轮重试 |
| `InvalidState`（任务已结束） | 向上抛出，停止流程 |
| `DuplicateSubmit` | 幂等，视为该 flag 已计入 |
| `ResourceUnavailable` | 稍后重试启动或跳过 |

---

## 9. 靶场网络接入（VPN）

```mermaid
flowchart TD
    A[主进程启动] --> B{vpn/ 下有 .ovpn?}
    B -->|否| C[跳过 VPN<br/>直接答题（可直连环境）]
    B -->|是| D[SDK 预检 check_vpn]
    D -->|通| E[复用现有连接]
    D -->|不通| F["获取 /tmp/cruiser_vpn.lock 排他锁"]
    F --> G[拿锁后复核（可能已被其他进程连上）]
    G -->|仍不通| H[pkill 残留 openvpn<br/>以最新 .ovpn 后台拉起]
    H --> I[等待 Initialization Sequence Completed<br/>最多 40s]
    I --> J["_fix_pushed_routes:<br/>解析 PUSH_REPLY 路由<br/>ip route replace ... dev tun0"]
    J --> K[最终预检确认]
```

要点：

- 仅主进程执行；spawn 的 worker 子进程带 `CRUISER_WORKER_ID` 会跳过；
- 路由修复：本环境 openvpn 2.5 的 sitnl 对部分推送路由添加失败（Network is unreachable），统一改用 `ip route replace <net>/<mask> dev tun0` 直连设备方式兜底；
- 手动维护通道：本地可自备 `connect_vpn.sh`（已 gitignore，不入库）供人工调试时连接并修复路由。

---

## 10. 工具链与离线知识库

### 10.1 自研 CLI 封装（`tools/`，供 Agent 经 Bash 调用）

| 工具 | 功能 | 设计要点 |
|------|------|----------|
| `submit_flag.py` | 经 SDK 提交并确认 flag | flag 提交的唯一通道；平台同步返回进度 X/Y |
| `dirsearch_scan.py` | 目录扫描 | **跨会话去重**：同一 URL 全会话只实扫一次，其余阻塞复用报告；报告落盘防上下文溢出 |
| `task_board.py` | 任务板 `list/claim/report` | Agent 侧的命令行入口 |
| `decompile.py` | PyGhidra 无头反编译 | 输出 C 伪码，并标注被编译器消除的取数、switch 各 case 语义与未确认 opcode、数据引用 |

### 10.2 预装安全工具集

| 类别 | 工具 |
|------|------|
| Web/渗透 | `dirsearch` / `sqlmap` / `fenjing`（SSTI）/ `nuclei`（内置模板库）/ `ffuf` / `whatweb` / Metasploit + PostgreSQL |
| 逆向/Pwn | Ghidra + PyGhidra / `radare2` / `pwntools` / `angr` / `ropper` / `one_gadget` / GDB |
| 密码/取证 | `pycryptodome` / `gmpy2` / `sympy` / `z3` / `steghide` / `zsteg` / `binwalk` |
| 智能合约 | Foundry（`forge`/`cast`/`anvil`）/ 多版本 `solc` / `slither` / `web3.py` |

`list_security_tools` 工具供 Agent 探测环境内可用的安全工具及版本。

### 10.3 离线知识库与字典

- `kb/`：三个 git submodule（[vulhub](https://github.com/vulhub/vulhub) / [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) / [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)），clone 时加 `--recurse-submodules`；`kb/bin/nuclei` 超过 GitHub 单文件限制，需从 [Releases](https://github.com/projectdiscovery/nuclei/releases) 自行下载。`CRUISER_KB_DIR` 可覆盖路径。配合禁网规则，全部情报来源本地化；
- `resource/`：`username.txt` / `password.txt` / `xss.txt` 字典与 `flag_hunting.txt`（flag 线索清单）。

---

## 11. 配置体系

### 11.1 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--target` | 无 | 扫描目标地址（未提供时由 SDK 启动容器获取） |
| `--challenge-code` | 无 | 题目代码 |
| `--sessions` | 1 | 并发工作会话数（≥2 进入分层调度） |
| `--worker-models` | 无 | 各 worker 模型清单，覆盖 `--sessions`；`kimi-*` 自动路由 Kimi 端点 |
| `--max-steps` | 0 | 引擎内强制步数上限（0 = 不强制，由调度器按阈值监控） |
| `--hint` | 无 | 题目提示 |
| `--quiet` | False | 静默中间输出，仅保留最终 JSON |
| `--local` | False | 本地测试模式：LLM 端点切回官方 https 域名 |
| `--default-timeout` / `--max-timeout` | 0 | `run_command` 默认/上限超时秒数 |

### 11.2 关键环境变量（完整清单见 README）

| 分类 | 变量 | 说明 |
|------|------|------|
| 平台 | `BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` | 平台 API 地址与跑分凭证（必填） |
| 密钥 | `DEEPSEEK_API_KEY` / `KIMI_API_KEY` / `GLM_API_KEY` | 按模型名前缀自动选用 |
| 模型 | `CRUISER_MODEL` / `ANTHROPIC_MODEL` / `WATCHER_MODEL` / `CRUISER_SOLVER_MODEL` | 解题 / watcher / solver 模型 |
| 上下文 | `CLAUDE_CODE_MAX_CONTEXT_TOKENS`（1M）/ `CLAUDE_CODE_AUTO_COMPACT_WINDOW`（800K） | 校正 auto-compact 触发时机 |
| 调度 | `CRUISER_MAX_ACTIVE`（3）/ `CRUISER_CONTAINER_WARMUP`（60s） | 活跃名额 / 容器就绪探测 |
| 协作 | `CRUISER_TEMP_MIN/MAX`（0.0/0.9） | 多会话温度分片区间 |
| watcher | `CRUISER_WATCHER_EVERY`（4）/ `CRUISER_WATCHER_RECENT`（48） | 策展频率与活动窗口 |
| 运行台 | `CRUISER_DASHBOARD` / `CRUISER_DASHBOARD_HOST` / `CRUISER_DASHBOARD_PORT` | 默认 `127.0.0.1:8765`；`=0` 关闭 |
| solver | `CRUISER_SOLVER_MAX_TURNS`（40）/ `CRUISER_MAX_SOLVERS`（3） | solver 回合与并发上限 |
| 逆向 | `GHIDRA_INSTALL_DIR` / `JAVA_HOME` | PyGhidra 运行环境 |

**密钥纪律**：所有凭证一律经环境变量（可写 `.env`，不覆盖已有环境变量），源码零硬编码；`.env` 不入库。

---

## 12. 并发安全与容错设计

### 12.1 并发安全清单

| 场景 | 机制 |
|------|------|
| 黑板/任务板并发读写 | `fcntl.LOCK_EX` 文件锁包裹「读-改-写」全程；写回走临时文件 + `os.replace` 原子替换，读者永远看到完整文件 |
| watcher 应用变更 vs 其他会话写入 | LLM 审阅用无锁快照，应用时锁内重读最新内容，按内容模糊匹配定位（规避行号漂移） |
| 任务认领竞争 | 锁内「找到即擦除」，先到先得；`.claimed` 日志 45 分钟 TTL 参与判重并自动解冻 |
| dirsearch 跨会话重复扫描 | 同一 URL 仅实扫一次，其余会话阻塞等待复用报告 |
| VPN 并发重连 | `/tmp/cruiser_vpn.lock` 排他锁 + 拿锁后复核 |
| flag 重复提交 | 平台侧 `DuplicateSubmit` 幂等 + 本地 `verified` 集合去重 |

### 12.2 容错与恢复矩阵

| 故障 | 检测 | 恢复 |
|------|------|------|
| worker/claude 崩溃 | reader 线程读到 EOF / 进程退出码 | 该题本轮记 remaining，晋级或重试；其他题不受影响 |
| 主进程退出（Ctrl+C/SIGTERM） | 信号处理器 + `atexit` | 整组 `killpg` 所有 worker 并关闭活跃容器 |
| 主进程异常死亡（SIGKILL） | 父进程已死 | `kill_orphans.py` 清理悬空 worker/claude 进程组 |
| 平台侧容器残留 | 启动时全量扫描 + 调度循环僵尸检测 | `close_all_containers()` + 后台回收线程 |
| LLM 端点不可用 | SDK/HTTP 异常 | watcher 降级静默跳过；worker 会话自然结束，下轮重试 |
| watcher LLM 失败 | 异常吞没 | 不影响解题主流程；flag 兜底提交先于策展执行 |
| 容器慢启动 | warmup 探测超时（60s） | 放行交由 LLM 自行重试，防调度卡死 |
| 题目从平台移除 | 轮询对账 | `kill_flags[code].set()` 强杀对应会话组 |
| 上下文逼近上限 | `AUTO_COMPACT_WINDOW`（800K） | claude CLI 自动压缩，留 200K 余量 |

---

## 13. 可观测性

调度主进程默认在 `http://127.0.0.1:8765` 拉起运行台（`cruiser/dashboard.py`），展示题目队列、黑板、任务板、flag 进度与 worker 日志。独立进程可用 `uv run python -m cruiser.dashboard`（只读 `reports/`）。`CRUISER_DASHBOARD=0` 关闭。

系统同时通过结构化 stdout 标记输出，便于 `tee` 落盘与 `grep` 检索：

| 标记 | 含义 |
|------|------|
| `[COUNT] N` | 跨会话单调递增的步数计数（调度阈值依据） |
| `[TOOL] ...` / `[Claude] ...` | 工具调用与模型文本摘要 |
| `[Watcher] 会话 X 维护黑板: 新增/修正/删除` | 黑板策展动作 |
| `[Watcher] 会话 X 任务板: 发布/下架` | 任务板变更 |
| `[Stage-Preprocess/Tier1/Tier2/Tier3]` | 层级调度事件 |
| `[STAGE] 步数达到阈值 c/limit` | 本轮停止原因 |
| `[FLAG RECOVERED]` | 会话结束后程序化补交成功 |
| `[Reaper] 回收僵尸容器` / `[Startup] 关闭遗留容器` | 容器治理 |
| `[{code}:S{idx}]` / `[{code}:SOLVER{sid}]` | 按题+会话前缀的 worker/solver 输出 |

---

## 14. 部署与运行

### 14.1 环境要求

- Python ≥ 3.11，[uv](https://docs.astral.sh/uv/) 包管理器；
- **`claude` CLI 必须安装且在 PATH 中**（引擎依赖）；
- 靶场 VPN 配置放入 `vpn/`（为空则跳过 VPN 直接答题）；
- 可选：Ghidra + JDK（PyGhidra 逆向）。

### 14.2 安装与启动

```bash
# 克隆（含 kb/ 三个 submodule）与依赖
git clone --recurse-submodules https://github.com/TJR181/Cruiser-Agent.git
cd Cruiser-Agent
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# 配置凭证（.env 或环境变量）
export BENCHMARK_BASE_URL=https://<跑分平台地址>
export BENCHMARK_TOKEN=<跑分任务凭证>
export DEEPSEEK_API_KEY=<DeepSeek 密钥>

# 自动模式：拉取未解题目 + 分层调度（推荐）
uv run python main.py --sessions 5

# 多模型混编
uv run python main.py --worker-models deepseek-v4-flash,deepseek-v4-flash,kimi-k3

# 指定单目标
uv run python main.py --target http://<IP:端口> --challenge-code <CODE>

# 本地联网调试（LLM 端点切回官方域名）
uv run python main.py --sessions 3 --local

# 浏览器打开运行台（主进程已拉起时）
# http://127.0.0.1:8765
```

> 离线部署说明：`uv sync` 只装核心依赖，解题中 Agent 还会按需临时加装 Python 包（`web3`/`slither`/`angr` 等）。离线镜像直接整份分发已就绪的 `.venv`，而非在目标环境重新 sync。

---

## 15. 性能调优建议

| 目标 | 手段 |
|------|------|
| 提高单位时间解题数 | 调大 `--sessions`（受名额与 LLM 配额约束）；保证 `CRUISER_MAX_ACTIVE` 与平台名额一致，避免名额空转 |
| 提高难题成功率 | 提高三级阈值；`--worker-models` 混入更强模型（如 1 个 `deepseek-v4-pro` 带 2 个 flash）；确认 watcher 用 pro 级模型 |
| 降低 token 成本 | 主力用 flash 级模型；黑板/任务板注入已有 3000 字符截断；`--quiet` 减少日志 I/O |
| 减少重复劳动 | 保持黑板注入开启；dirsearch 去重勿绕过；合理温度分片（默认 0.0~0.9）保证视角差异 |
| 缩短容器空转 | warmup 探测保持默认 60s；确保僵尸回收正常（日志中关注 `[Reaper]`） |

---

## 16. 风险与限制

1. **强依赖 `claude` CLI**：引擎构建在其 stream-json 协议与钩子机制上，CLI 版本升级需回归验证。
2. **平台名额硬约束**：`CRUISER_MAX_ACTIVE` 必须与平台实际配额一致，否则出现启动拒绝或名额浪费。
3. **提示扣分**：三级起拉取提示会按比例扣减得分，属设计取舍（宁可扣分也要解出），不适合「禁提示」规则的赛事。
4. **黑盒定位**：当前流程全程黑盒（无源码审计通道）；对需源码辅助的题目依赖 Agent 自行从靶场读源码（文件包含/命令执行后优先读源码已写入提示词）。
5. **watcher 成本**：默认每 4 步一次 pro 级模型调用，token 开销随会话数线性增长（可用 `CRUISER_WATCHER_EVERY` 调稀）。
6. **文件总线规模**：单题黑板依赖 watcher 策展控制体量；极端长会话下黑板仍可能膨胀，注入端以尾部 3000 字符截断兜底。

---

## 17. 演进方向

| 方向 | 说明 |
|------|------|
| 解题画像学习 | 统计各题型的层级分布与耗时，动态调整阈值与模型搭配 |
| 黑板结构化升级 | 从自由文本演进为「端点/凭证/漏洞/结论」分类条目，支持按类检索注入 |
| solver 策略强化 | 根据任务板认领完成率动态扩缩 solver 数；引入方向优先级 |
| 多题知识迁移 | 跨题目沉淀可复用利用模式（当前知识库为静态离线 PoC） |
| 恢复点能力 | 会话中断后基于黑板 + 活动摘要续跑，而非从零开始 |
| 评测报表 | 运行台已覆盖实时队列/黑板/日志；可再汇总每题步数与 token 消耗 |

---

## 18. 附录

### 18.1 关键源文件索引

| 文件 | 职责 |
|------|------|
| `main.py` | CLI 入口、VPN、容器治理、分层调度主循环、worker/solver 生命周期、运行台 |
| `cruiser/claude_agent.py` | claude CLI 驱动、stream-json 解析、watcher 策展、flag 权威校验、`[flag方法]` 写入 |
| `cruiser/dashboard.py` | 运行台 HTTP 服务 |
| `cruiser/runtime.py` | 调度器运行态快照与 `reports/` 汇编 |
| `cruiser/llm.py` | LLM 提供方注册表、模型路由、温度分片 |
| `cruiser/taskboard.py` | 任务板发布/认领/回报/下架（文件锁 + 原子重写 + 相似度判重） |
| `cruiser/prompt.py` | 系统提示词与任务模板（探索 / solver 两套） |
| `cruiser/tools.py` | SDK 客户端、submit_flag、dirsearch、XSS fuzz 等工具实现 |
| `blackboard_hook.py` | SessionStart / PostToolUse 上下文硬注入钩子 |
| `kill_orphans.py` | 悬空进程清理兜底 |
| `doc/SDK_API.md` | tsec-benchmark SDK 接入文档 |

### 18.2 运行时文件布局（`reports/`）

| 文件 | 内容 | 写者 | 读者 |
|------|------|------|------|
| `info_<code>.txt` | 共享黑板 | 各会话 / watcher / 任务回报 | 钩子注入、watcher |
| `tasks_<code>.txt` | 待认领探索方向 | watcher | worker / solver |
| `tasks_<code>.txt.claimed` | 认领日志（45min TTL） | claim_task | publish 判重、watcher |
| `hint_<code>.txt` | 题目提示 | 主进程（三级拉取） | 钩子注入、watcher |
| `desc_<code>.txt` | 题目描述 | 主进程 | 钩子注入、watcher |
| `_runtime.json` | 调度器运行态快照 | 主进程 | 运行台（独立进程模式） |
| `_flagstore.json` | 跨进程正确/错误 flag 记忆 | submit_flag | 提交预检、前缀学习 |

---

*本文档与代码同步维护；机制性变更请同步修订对应章节。*
