# Cruiser

Cruiser 是一个面向 CTF 竞赛评测平台（TSec Benchmark）的自动化 Web/逻辑漏洞挖掘与利用 Agent。它对接跑分平台，自动完成「拉取题目 → 启动靶场容器 → 驱动 Agent 解题 → 提交 flag → 关闭容器」的完整闭环，并通过多进程并发、分层调度与跨会话共享黑板机制提升解题吞吐与成功率。

## 核心架构

Cruiser 的解题引擎基于 [`claude` CLI](https://docs.anthropic.com/en/docs/claude-code)（`--output-format stream-json` 流式模式）驱动一个自主 Agent，Anthropic 兼容端点默认接入 DeepSeek。系统分为三层进程，边界清晰、崩溃可恢复：

1. **调度层（`main.py` 主进程）** — 唯一与平台交互的进程。轮询未解题目、按难度分层调度、启动 worker、监控 `[COUNT]` 步数、回收容器与孤儿进程。
2. **执行层（worker 子进程）** — `main.py --sessions 1 --challenge-code <CODE>` 的副本，带 `CRUISER_WORKER_ID`。调用 `run_auto_scan()`，进而拉起 `claude` CLI 进程。
3. **Agent 层（`claude` CLI 进程）** — 真正的解题智能体，使用其内置的 Bash/Read/Write 等工具执行侦察与利用。

进程链：`main.py（调度器）→ main.py --sessions 1（worker）→ claude CLI → bash/python 工具子进程`。

跨进程协作通过**文件系统**完成（`reports/` 目录），全部以 `fcntl` 文件锁 + 临时文件 `os.replace` 原子重写保证并发安全：

- **共享黑板** `reports/info_<code>.txt` — 各会话已发现的关键事实（口令、路径、端点、结论等）。
- **探索方向任务板** `reports/tasks_<code>.txt` — 待认领的探索方向，认领即擦除，先到先得。
- **共享提示** `reports/hint_<code>.txt` — 从平台拉取的题目提示（各会话共享）。

## 分层调度

新题在四个队列间逐级晋升，每级步数阈值递增；任一会话解出 flag 即整组停止：

| 层级 | 触发条件 | 步数阈值 | 是否带提示 |
|------|----------|----------|------------|
| 预处理 | 新题 | 50 | 否 |
| 一级 | 预处理未解出 | 100 | 否 |
| 二级 | 一级未解出 | 150 | 否 |
| 三级 | 二级未解出 | 200 | 是（从三级起才拉取提示；解不出则放回队尾按 200 步循环重试） |

每一级对同一道题并发拉起 `--sessions` 个**黑盒** worker 会话（全程黑盒，无源码审计），各会话独立探索、以不同会话编号署名，通过共享黑板交换发现以减少重复探索。可用 `--worker-models` 为每个 worker 指定不同模型（如 2 个 `deepseek-v4-flash` + 1 个 `deepseek-v4-pro`）。平台活跃容器名额（默认 3，`CRUISER_MAX_ACTIVE`）会严格限流。

## 共享黑板机制

- **上下文硬注入（`blackboard_hook.py`）** — 在 worker 工作目录写入 `.claude/settings.json` 注册钩子：`SessionStart` 开局注入一次黑板 + 任务板，`PostToolUse` 每 10 次工具调用注入一次最新内容，通过 `additionalContext` 物理进入模型上下文，不依赖模型自觉读取。
- **黑板策展 Watcher** — 每 6 步在后台由独立的 watcher LLM 审阅该会话最近活动，维护黑板质量（提取新关键信息、修正/删除失效条目）并向任务板推荐探索方向。应用变更时按内容模糊匹配定位条目，规避并发行号漂移。watcher 使用 **`deepseek-v4-pro`** 模型（可经 `WATCHER_MODEL` 覆盖），策展与方向规划需要更强的推理能力。

## 项目结构

```
Cruiser/
├── main.py                  # CLI 入口：平台调度、多会话并发、分层调度、容器/进程治理
├── blackboard_hook.py       # Claude Code 钩子：黑板/任务板硬注入模型上下文
├── kill_orphans.py          # 悬空 worker/claude 进程清理兜底
├── frontend/                # 运行监控面板（静态页面：题目队列/worker 状态/黑板/任务板可视化）
├── tools/                   # Agent 调用的 CLI 封装脚本
│   ├── submit_flag.py       # 命令行提交 flag（供 Agent 调用，经 SDK 平台确认）
│   ├── dirsearch_scan.py    # 跨会话去重的目录扫描 CLI（同一 URL 只实扫一次，其余复用）
│   ├── task_board.py        # 探索方向任务板命令行（list/claim/report）
│   └── decompile.py         # PyGhidra 无头反编译 CLI（C 伪码 + 数据引用/switch 分派分析 + 反汇编）
├── pyproject.toml           # 项目配置与依赖声明
├── cruiser/
│   ├── __init__.py          # 包初始化：禁用 LangSmith 追踪、加载 .env
│   ├── claude_agent.py      # 当前解题引擎：claude CLI 驱动 + 黑板 watcher
│   ├── taskboard.py         # 任务板读写（文件锁 + 原子重写）
│   ├── llm.py               # LLM 提供者：解题(DeepSeek) / watcher(deepseek-v4-pro)
│   ├── prompt.py            # 系统提示词与任务模板
│   ├── tools.py             # SDK 客户端、submit_flag、dirsearch/xss 等工具
│   └── agent.py             # 旧版手写 ReAct 引擎（已弃用，保留供参考）
├── resource/                # 用户名/密码/XSS payload 字典
├── kb/                      # 离线漏洞知识库（不入库，需自行准备：vulhub / nuclei-templates / PayloadsAllTheThings / bin/nuclei）
├── vpn/                     # 靶场 VPN 配置（*.ovpn，由平台下发，不入库）
├── doc/                     # SDK_API.md（平台 SDK 文档）+ TECHNICAL_DESIGN.md（技术方案）
└── reports/                 # 运行时共享黑板 / 任务板 / 提示文件（自动生成，不入库）
```

> **离线知识库说明**：`kb/` 未随仓库分发。请自行准备 [vulhub](https://github.com/vulhub/vulhub)、
> [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)、
> [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) 与 nuclei 二进制，
> 或通过 `CRUISER_KB_DIR` 指向已有知识库目录。缺少 `kb/` 不影响主流程，仅降低 PoC 本地检索能力。

> **监控面板**：`frontend/` 为纯静态页面，直接用浏览器打开 `frontend/index.html` 即可预览
> （当前为演示数据；对接实时数据源可自行改造 `app.js`）。

## 环境要求

- Python >= 3.11
- [uv](https://docs.astral.sh/uv/) 包管理器
- **[claude CLI](https://docs.anthropic.com/en/docs/claude-code)**（必须安装且在 PATH 中，否则引擎无法启动）
- 已连接靶场 VPN（`main.py` 主进程会用 `vpn/*.ovpn` 自动连接；`vpn/` 为空时跳过 VPN、直接答题）
- 可选：Ghidra + JDK（供 `tools/decompile.py` PyGhidra 逆向使用）

## 安装

```bash
# 安装 uv（如未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 安装依赖
uv sync
```

> 注:`uv sync` 只安装 `pyproject.toml` 声明的核心依赖；解题过程中 Agent 还会按需临时加装
> 其它 Python 包(如 `web3`/`slither`/`angr` 相关)。离线部署镜像为保证一致性，直接整份分发
> 已就绪的虚拟环境，而非在目标环境重新 `uv sync`。

## 配置

平台凭证与 API 密钥**一律通过环境变量提供**（可写入项目根目录 `.env`，不覆盖已存在的环境变量）；源码中不含任何硬编码密钥。仓库提供 `.env.example` 模板，复制为 `.env` 后填入真实值即可：

```bash
BENCHMARK_BASE_URL=https://<跑分平台地址>   # 平台 API 地址
BENCHMARK_TOKEN=<跑分任务凭证>              # 由平台创建跑分任务后下发
DEEPSEEK_API_KEY=<DeepSeek 密钥>           # 必填：解题引擎(claude CLI) 与 watcher 默认用
KIMI_API_KEY=<Kimi/Moonshot 密钥>          # 选填：当 worker/watcher 指定 kimi 模型时使用
```

`DEEPSEEK_API_KEY` 未配置且未设置 `ANTHROPIC_AUTH_TOKEN` 时，启动会打印告警且 LLM 无法认证。
所有"连哪家模型/端点/用哪把 key"的逻辑集中在 `cruiser/llm.py`,并**按模型名自动路由提供方**:
`kimi-*` 模型走 Moonshot 端点 + `KIMI_API_KEY`,其余(`deepseek-*`)走 DeepSeek 端点 + `DEEPSEEK_API_KEY`。
因此 `--worker-models` 可混搭不同厂商,例如 `deepseek-v4-flash,deepseek-v4-flash,kimi-k3`。

> **端点默认值**:各提供方端点默认使用比赛内网形式(http + `.tsecbench.gw` 后缀,如
> `http://api.deepseek.com.tsecbench.gw/v1`)。本地联网调试时加 `--local` 参数即切回原始官方
> https 域名(如 `https://api.deepseek.com/v1`);两者均可再用 `*_BASE_URL` 环境变量显式覆盖。

> 提示：请勿将含真实密钥的 `.env` 提交到版本库，建议加入 `.gitignore` 并妥善轮换。

## 使用方法

### 自动模式（从平台拉取未解题目，推荐）

```bash
uv run python main.py --sessions 5
```

主进程自动连接 VPN、清理遗留容器，然后持续拉取未解题目并按分层调度并发解题。

### 指定单目标扫描

```bash
uv run python main.py --target http://<IP:端口> --challenge-code <CODE>
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--target` | 无 | 扫描目标地址（未提供时由 SDK 启动容器获取直连地址） |
| `--challenge-code` | 无 | 题目代码 |
| `--sessions` | 1 | 并发工作会话数量（>=2 时进入分层调度） |
| `--worker-models` | 无 | 逗号分隔的各 worker 模型清单（如 `deepseek-v4-flash,deepseek-v4-flash,kimi-k3`）；提供时 worker 数量=清单长度，覆盖 `--sessions`；`kimi-*` 模型自动路由到 Kimi 端点 |
| `--max-steps` | 0 | AI 扫描最大步数（0 = 不在引擎内强制终止，由调度器按阈值监控） |
| `--hint` | 无 | 题目提示（辅助 Agent 推理） |
| `--quiet` | False | 静默中间输出，仅保留最终 JSON |
| `--local` | False | 本地测试模式：大模型端点切回原始官方 https 域名（默认走比赛内网 `.tsecbench.gw` 域名） |
| `--default-timeout` | 0 | `run_command` 默认超时秒数（0 = 内置默认） |
| `--max-timeout` | 0 | `run_command` 超时上限秒数（0 = 内置上限） |

## 环境变量

| 变量 | 说明 |
|------|------|
| `BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` | 平台 API 地址与跑分凭证（必填） |
| `DEEPSEEK_API_KEY` | DeepSeek 密钥（解题引擎与 watcher 默认使用） |
| `KIMI_API_KEY` | Kimi/Moonshot 密钥（当模型为 `kimi-*` 时自动使用） |
| `KIMI_ANTHROPIC_BASE_URL` / `KIMI_BASE_URL` | Kimi 的 Anthropic / OpenAI 兼容端点（默认比赛内网 `http://api.moonshot.cn.tsecbench.gw/anthropic`、`.../v1`；`--local` 切回 `https://api.moonshot.cn/...`） |
| `DEEPSEEK_MODEL` / `ANTHROPIC_MODEL` | 解题引擎模型（默认 `deepseek-v4-flash`） |
| `DEEPSEEK_BASE_URL` | DeepSeek OpenAI 兼容端点（默认比赛内网 `http://api.deepseek.com.tsecbench.gw/v1`；`--local` 切回 `https://api.deepseek.com/v1`） |
| `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN` | claude CLI 接入的 Anthropic 兼容端点与令牌 |
| `CLAUDE_CODE_MAX_CONTEXT_TOKENS` | 声明模型真实上下文窗口（默认 `1000000`，即 DeepSeek 1M，用于校正 auto-compact 触发时机） |
| `CLAUDE_CODE_AUTO_COMPACT_WINDOW` | 提前触发上下文压缩的阈值 token 数（默认 `800000`，留出余量避免逼近硬上限） |
| `WATCHER_MODEL` | 黑板 watcher 模型（默认 `deepseek-v4-pro`） |
| `WATCHER_TEMPERATURE` | watcher 温度（默认不传，交由服务端决定） |
| `CRUISER_MAX_ACTIVE` | 平台活跃容器名额上限（默认 3） |
| `CRUISER_LOCAL` | 设为 `1` 启用本地测试模式（大模型端点切回原始官方 https 域名）；等价于 `--local` |
| `CRUISER_CONTAINER_WARMUP` | 容器就绪探测上限秒数（默认 60）：拿到地址后主动探测目标端口，可连即拉起会话，超时也放行交由 LLM 解题以防卡死 |
| `CRUISER_KB_DIR` | 离线漏洞知识库目录（默认 `kb/`；供 nuclei/PoC 检索使用） |
| `CRUISER_MAX_TURNS` | 单个 claude 会话最大**回合(turn)**数（默认 0 = 不限制；注意 turn ≠ 日志 `[COUNT]`，`[COUNT]` 约为其数倍） |
| `CRUISER_SOLVER_MAX_TURNS` / `CRUISER_MAX_SOLVERS` / `CRUISER_SOLVER_MODEL` | solver 单会话回合上限（默认 40）/ 每题并发 solver 上限（默认 3）/ solver 模型（默认 `deepseek-v4-flash`） |
| `CRUISER_SESSIONS` / `CRUISER_WORKER_ID` | 总会话数 / Worker 会话编号（子进程自动注入） |
| `CRUISER_WORKER_MODELS` | 各 worker 模型清单（等价 `--worker-models`，逗号分隔） |
| `CRUISER_WORKSPACE_DIR` | 会话工作空间目录（子进程自动注入） |
| `CRUISER_TEMP_MIN` / `CRUISER_TEMP_MAX` | 多会话 LLM 温度下限/上限（默认 0.0 / 0.9） |
| `CRUISER_DEFAULT_TIMEOUT` / `CRUISER_MAX_TIMEOUT` | 命令默认/上限超时（秒） |
| `CRUISER_QUIET` | 设为 `1` 抑制中间输出 |
| `CRUISER_DEBUG` | 设为 `1` 开启调试输出 |
| `GHIDRA_INSTALL_DIR` / `JAVA_HOME` | PyGhidra 逆向运行环境 |

## 内置工具与脚本

| 工具/脚本 | 功能 |
|-----------|------|
| `tools/submit_flag.py` | 经 tsec-benchmark SDK 提交并确认 flag |
| `tools/dirsearch_scan.py` | 跨会话去重的目录扫描（多会话对同一 URL 仅实扫一次，其余阻塞复用报告） |
| `tools/task_board.py` | 任务板 `list` / `claim` / `report` |
| `tools/decompile.py` | PyGhidra 无头反编译：输出 C 伪码，并标注被编译器消除的取数、switch 各 case 语义与未确认的 opcode |
| `kill_orphans.py` | 清理父进程已死的悬空 worker/claude 进程组 |
| Web/渗透 | `dirsearch` / `sqlmap` / `fenjing` / `nuclei`（内置模板库）/ `ffuf` / `whatweb` / Metasploit + PostgreSQL |
| 逆向/Pwn | Ghidra + PyGhidra / `radare2` / `pwntools` / `angr` / `ropper` / `one_gadget` / GDB |
| 密码/取证 | `pycryptodome` / `gmpy2` / `sympy` / `z3` / `steghide` / `zsteg` / `binwalk` 等 |
| 智能合约 | Foundry（`forge`/`cast`/`anvil`）/ 多版本 `solc` / `slither` / `web3.py` |
| 离线知识库 | `kb/`：vulhub / nuclei-templates / PayloadsAllTheThings（支持按 CVE/组件本地检索 PoC） |
| `resource/*.txt` | 用户名 / 密码 / XSS payload 字典 |

## 许可证

本项目以 [Apache License 2.0](LICENSE) 开源。

**免责声明**：本项目仅供安全研究与 CTF 竞赛学习使用，请勿用于未授权的目标。使用本项目造成的一切后果由使用者自行承担。
