from cruiser.claude_agent import run_auto_scan
import argparse
import atexit
import fcntl
import glob
import json
import os
import subprocess
import sys
import threading
import time
import re
import signal
import uuid
import random
import requests
from cruiser.tools import get_benchmark_client
from cruiser.taskboard import claim_task
from cruiser.claude_agent import _looks_like_flag
from tsec_benchmark import InvalidState, TSecError


def _fix_pushed_routes(log_path: str) -> None:
    """从 openvpn 日志解析服务端 PUSH_REPLY 推送的路由，经 tun0 逐条修复。

    本环境 openvpn 2.5 的 sitnl 对部分推送路由添加失败（Network is unreachable），
    统一改用 'ip route replace <net>/<mask> dev tun0' 直连设备方式兜底。
    """
    try:
        with open(log_path, "r", errors="ignore") as f:
            content = f.read()
        replies = re.findall(r"PUSH_REPLY[^\n]*", content)
        if not replies:
            return
        for network, netmask in re.findall(r"route (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", replies[-1]):
            subprocess.run(["ip", "route", "replace", f"{network}/{netmask}", "dev", "tun0"], capture_output=True)
    except Exception:
        pass


def close_all_containers() -> None:
    """启动时关闭所有已开启的容器，确保从干净状态开始。

    清理异常退出/崩溃残留的容器（包括已完成题目的——它们不会出现在
    未解列表里，运行中的僵尸回收器覆盖不到）。仅在主进程调用。
    """
    try:
        client = get_benchmark_client()
        running = [ch for ch in client.list_challenges() if ch.container_status != "stopped"]
    except Exception as e:
        try:
            print(f"[Startup] 获取容器状态失败: {e}", flush=True)
        except Exception:
            pass
        return
    for ch in running:
        try:
            client.close_challenge(ch.unique_code)
            print(f"[Startup] 关闭遗留容器 {ch.unique_code}", flush=True)
        except Exception:
            pass
    if running:
        try:
            print(f"[Startup] 已清理 {len(running)} 个遗留容器", flush=True)
        except Exception:
            pass


def ensure_vpn_connected() -> None:
    """确保靶场 VPN 已连接；不通时自动用 vpn/ 下最新的 ovpn 配置连接并修复路由。

    tsec-benchmark SDK 只检测 VPN 连通性（check_vpn），不负责建立连接。
    本函数仅在主进程启动时调用（spawn 的 worker 子进程带 CRUISER_WORKER_ID，会跳过），
    通过文件锁防止并发重复连接。

    当 vpn/ 目录为空（无 *.ovpn 配置）时，默认不连接 VPN，直接答题
    （适用于平台可直连、无需靶场 VPN 的环境）。
    """
    root = os.path.dirname(os.path.abspath(__file__))
    configs = sorted(glob.glob(os.path.join(root, "vpn", "*.ovpn")), key=os.path.getmtime)
    if not configs:
        print("[VPN] vpn/ 目录为空，跳过 VPN 连接，直接答题", flush=True)
        return
    try:
        get_benchmark_client()  # 内部含 VPN 预检，成功即已连接
        return
    except Exception:
        pass
    lock_fd = None
    try:
        lock_fd = os.open("/tmp/cruiser_vpn.lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # 拿锁后复核（可能已被其他进程连上）
        try:
            get_benchmark_client()
            return
        except Exception:
            pass
        cfg = configs[-1]
        print(f"[VPN] 未连接，自动连接: {os.path.basename(cfg)}", flush=True)
        subprocess.run(["pkill", "-x", "openvpn"], capture_output=True)
        time.sleep(1)
        log_path = "/tmp/openvpn.log"
        try:
            os.remove(log_path)
        except OSError:
            pass
        subprocess.Popen(["openvpn", "--config", cfg, "--daemon", "--log", log_path])
        # 等待隧道初始化完成（最多 40 秒）
        for _ in range(20):
            time.sleep(2)
            try:
                with open(log_path, "r", errors="ignore") as f:
                    if "Initialization Sequence Completed" in f.read():
                        break
            except OSError:
                pass
        _fix_pushed_routes(log_path)
    except Exception as e:
        print(f"[VPN] 自动连接异常: {e}", flush=True)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except Exception:
                pass
    try:
        get_benchmark_client()
        print("[VPN] 自动连接成功", flush=True)
    except Exception as e:
        print(f"[VPN] 自动连接后仍不通: {e}，请检查 vpn/ 配置", flush=True)


def main():
    """Start in non-interactive scan mode (auto when --target missing) or multi-session."""
    parser = argparse.ArgumentParser(description="Cruiser - CTF Web agent")
    parser.add_argument("--target", type=str, default=None, help="扫描目标地址（如 http://127.0.0.1:8080 ）")
    parser.add_argument("--max-steps", type=int, default=0, help="AI 扫描最大步数（0=无限）")
    parser.add_argument("--quiet", action="store_true", help="静默中间输出，仅保留最终 JSON")
    parser.add_argument("--sessions", type=int, default=1, help="并发工作会话数量（>=1）")
    parser.add_argument("--default-timeout", type=int, default=0, help="run_command 默认超时（秒），0=使用内置默认")
    parser.add_argument("--max-timeout", type=int, default=0, help="run_command 超时上限（秒），0=使用内置上限")
    parser.add_argument("--hint", type=str, default=None, help="题目提示（可选，用于辅助 AI 推理）")
    parser.add_argument("--challenge-code", type=str, default=None, help="题目代码（由调度器下发）")
    parser.add_argument(
        "--worker-models",
        type=str,
        default=None,
        help="逗号分隔的各 worker 模型清单，如 'deepseek-v4-flash,deepseek-v4-flash,deepseek-v4-pro'；"
             "提供时 worker 数量=清单长度（覆盖 --sessions），第 i 个 worker 用第 i 个模型",
    )
    parser.add_argument(
        "--solver-task",
        type=str,
        default=None,
        help="（内部）solver 专用：本次仅聚焦执行这一条探索方向，不做整题探索",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="本地测试模式：大模型端点改用原始官方 https 域名（默认走比赛内网 .tsecbench.gw 域名）",
    )
    args = parser.parse_args()
    # 本地测试开关：置环境变量供 cruiser.llm 端点解析读取；子进程 env=os.environ.copy() 会继承。
    if args.local:
        os.environ["CRUISER_LOCAL"] = "1"
    # 将超时策略注入环境，供当前/子会话使用
    if args.default_timeout and args.default_timeout > 0:
        os.environ["CRUISER_DEFAULT_TIMEOUT"] = str(args.default_timeout)
    if args.max_timeout and args.max_timeout > 0:
        os.environ["CRUISER_MAX_TIMEOUT"] = str(args.max_timeout)

    # worker 模型搭配：--worker-models 优先，其次环境变量 CRUISER_WORKER_MODELS；
    # 逗号分隔，如 "deepseek-v4-flash,deepseek-v4-flash,deepseek-v4-pro"。
    # 提供时 worker 数量 = 清单长度（覆盖 --sessions），第 i 个 worker 用第 i 个模型。
    # 只在主进程解析：worker 子进程带 CRUISER_WORKER_ID，其模型已由父进程经 ANTHROPIC_MODEL 注入，
    # 若在此重复解析（子进程也会从 .env 继承 CRUISER_WORKER_MODELS）会误入多会话分支递归 spawn。
    _is_worker_proc = os.environ.get("CRUISER_WORKER_ID") is not None
    _wm_raw = "" if _is_worker_proc else (args.worker_models or os.environ.get("CRUISER_WORKER_MODELS", ""))
    worker_models = [m.strip() for m in _wm_raw.split(",") if m.strip()]
    sessions = len(worker_models) if worker_models else args.sessions
    if worker_models:
        print(f"[Main] worker 模型搭配：{worker_models}（共 {sessions} 个 worker）", flush=True)

    # 主进程启动时确保靶场 VPN 已连接（spawn 的 worker 子进程会跳过）
    if os.environ.get("CRUISER_WORKER_ID") is None:
        from cruiser.llm import get_deepseek_api_key, get_kimi_api_key, get_glm_api_key
        if not get_deepseek_api_key() and not get_kimi_api_key() and not get_glm_api_key() and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            print(
                "[Main] 警告：未配置任何 LLM 密钥（DEEPSEEK_API_KEY / KIMI_API_KEY / GLM_API_KEY / ANTHROPIC_AUTH_TOKEN），"
                "claude 解题引擎与 watcher 将无法认证。请在项目根目录 .env 中配置。",
                flush=True,
            )
        ensure_vpn_connected()
        # 关闭所有遗留容器，从干净状态开始
        close_all_containers()

    DIFF_RANK = {"easy": 0, "medium": 1, "hard": 2}

    def fetch_all_unsolved() -> dict[str, dict] | None:
        """Return a map: code -> {challenge_code, target, difficulty, ...} for all unsolved challenges.
        Returns None on fetch/parse errors (do NOT update queues in that case).
        Returns {} when fetched successfully but no unsolved challenges are available.

        注意：SDK 的 list_challenges 仅当容器 available 时才带 container_addr；
        容器 stopped 时 target 为空字符串，由 ensure_challenge_started 在扫描前启动。
        """
        try:
            challenges = get_benchmark_client().list_challenges()
        except Exception as e:
            try:
                print(f"[Fetcher] 获取题目失败: {e}", flush=True)
            except Exception:
                pass
            return None
        try:
            result: dict[str, dict] = {}
            for ch in challenges:
                if ch.is_completed:
                    continue
                urls = [f"http://{addr}" for addr in (ch.container_addr or []) if addr]
                result[ch.unique_code] = {
                    "challenge_code": ch.unique_code,
                    "target": ", ".join(urls),
                    "difficulty": (ch.difficulty or "").lower(),
                    "description": getattr(ch, "description", "") or "",
                    "level": getattr(ch, "level", "") or "",
                    "total_score": getattr(ch, "total_score", 0),
                    "container_status": ch.container_status or "",
                    "flag_count": ch.flag_count,
                    "correct_flag_count": ch.correct_flag_count,
                }
            return result
        except Exception as e:
            try:
                print(f"[Fetcher] 解析题目失败: {e}", flush=True)
            except Exception:
                pass
            return None

    def ensure_challenge_started(code: str, timeout_s: float = 300.0) -> list[str]:
        """确保题目容器已启动，返回直连地址数组（IP:端口）；失败/超时返回 []。

        start_challenge 后容器可能仍处于 pending，需轮询 list_challenges
        直至 container_status == "available" 且拿到 container_addr。
        平台限制活跃容器数量（max active），名额满时快速失败由调度器稍后重试。
        """
        if not code:
            return []
        # 就绪判定：拿到地址后主动探测目标端口是否真正可连（容器 available 不等于
        # 内部服务已监听）。任一地址连通即立即返回；最多等待 CRUISER_CONTAINER_WARMUP
        # 秒（默认 60），到点仍未连通也照常返回地址，交给 LLM 去解题，避免卡死。
        try:
            max_wait_s = float(os.environ.get("CRUISER_CONTAINER_WARMUP", "60") or "60")
        except Exception:
            max_wait_s = 60.0

        def _addr_reachable(addr: str, conn_timeout: float = 3.0) -> bool:
            import socket
            try:
                host, _, port = str(addr).rpartition(":")
                if not host or not port:
                    return False
                with socket.create_connection((host, int(port)), timeout=conn_timeout):
                    return True
            except Exception:
                return False

        def _ready(addrs: list[str]) -> list[str]:
            if not addrs or max_wait_s <= 0:
                return addrs
            try:
                print(f"[Container] {code} 容器就绪，探测目标可达性（最多 {max_wait_s:.0f}s）…", flush=True)
            except Exception:
                pass
            deadline = time.time() + max_wait_s
            while time.time() < deadline:
                if any(_addr_reachable(a) for a in addrs):
                    try:
                        print(f"[Container] {code} 目标已可连，拉起会话", flush=True)
                    except Exception:
                        pass
                    return addrs
                time.sleep(2)
            try:
                print(f"[Container] {code} 目标 {max_wait_s:.0f}s 内仍不可达，仍拉起会话交给 LLM（避免卡死）", flush=True)
            except Exception:
                pass
            return addrs

        try:
            client = get_benchmark_client()
        except Exception as e:
            try:
                print(f"[Container] SDK 初始化失败: {e}", flush=True)
            except Exception:
                pass
            return []
        try:
            started = client.start_challenge(code)
            if started.container_addr:
                return _ready(list(started.container_addr))
        except InvalidState as e:
            if "max active" in str(e).lower():
                # 活跃容器名额已满：快速失败 + 15 秒冷却（覆盖服务端拆除窗口）
                try:
                    start_cooldowns[code] = time.time() + 15
                except Exception:
                    pass
                try:
                    print(f"[Container] {code} 启动被拒：活跃名额已满，15 秒后重试", flush=True)
                except Exception:
                    pass
                return []
            # 其他状态非法（如已启动/启动中）：走轮询拿地址
        except TSecError as e:
            try:
                print(f"[Container] 启动 {code} 失败: {e}", flush=True)
            except Exception:
                pass
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                for ch in client.list_challenges():
                    if ch.unique_code == code:
                        if ch.container_status == "available" and ch.container_addr:
                            return _ready(list(ch.container_addr))
                        break
            except TSecError:
                pass
            time.sleep(2)
        try:
            print(f"[Container] 等待 {code} 容器就绪超时", flush=True)
        except Exception:
            pass
        return []

    def _container_stopped(code: str):
        """用 SDK 查该题容器是否确已 stopped。
        返回 True=已停 / False=仍在 / None=查询失败(状态未知)。
        用 list_challenges 全量列表（含已解/已移除题），故能识别脱离未解列表但容器仍在的僵尸。"""
        try:
            for ch in get_benchmark_client().list_challenges():
                if ch.unique_code == code:
                    return (ch.container_status or "stopped") == "stopped"
            return True  # 平台列表里已无此题，视作无容器
        except Exception:
            return None

    def close_challenge_quiet(code: str) -> None:
        """关闭题目容器并用 SDK 校验是否真的关了；未确认停止则继续重试，
        直到确认已停或用尽次数（平台拆除为异步，故每次关闭后等待再校验）。
        次数用尽仍未确认时打 WARN，交由 reaper 周期性兜底，避免线程无限阻塞。"""
        if not code:
            return
        try:
            max_attempts = max(1, int(os.environ.get("CRUISER_CLOSE_MAX_ATTEMPTS", "6") or "6"))
        except Exception:
            max_attempts = 6
        try:
            verify_wait = float(os.environ.get("CRUISER_CLOSE_VERIFY_WAIT", "10") or "10")
        except Exception:
            verify_wait = 10.0
        for attempt in range(1, max_attempts + 1):
            # 关闭调用本身异常也不放弃：容器可能正在关/状态刚变更，继续校验为准
            try:
                get_benchmark_client().close_challenge(code)
            except Exception:
                pass
            # 平台异步拆除，等待后再核实
            try:
                time.sleep(verify_wait)
            except Exception:
                pass
            stopped = _container_stopped(code)
            if stopped is True:
                try:
                    print(f"[Container] 已确认关闭 {code} 容器（第 {attempt}/{max_attempts} 次）", flush=True)
                except Exception:
                    pass
                return
            try:
                reason = "状态查询失败" if stopped is None else "仍未停止"
                print(f"[Container] {code} 关闭后{reason}，重试 {attempt}/{max_attempts}", flush=True)
            except Exception:
                pass
        try:
            print(f"[Container] [WARN] {code} 关闭在 {max_attempts} 次尝试后仍未确认停止，交由 reaper 兜底", flush=True)
        except Exception:
            pass

    def fetch_hint_text(code: str) -> str:
        """通过 SDK 获取题目提示（注意：查看提示会按比例扣减该题得分）。"""
        base_delay = 0.5
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                res = get_benchmark_client().get_hint(code)
                hint_text = (res.hint or "").strip()
                # hint 为 None 表示该题无提示，直接返回空，不重试
                return hint_text
            except Exception as e:
                try:
                    print(f"[HintFetcher] 获取提示异常: {e}", flush=True)
                except Exception:
                    pass
            if attempt < max_attempts - 1:
                # 随机退避：指数回退 + 抖动
                sleep_seconds = min(8.0, base_delay * (2 ** attempt)) * (0.5 + random.random())
                try:
                    print(f"[HintFetcher] 第 {attempt + 1}/{max_attempts} 次失败，随机退避 {sleep_seconds:.2f}s 后重试…", flush=True)
                except Exception:
                    pass
                time.sleep(sleep_seconds)
        return ""

    # 单会话：使用中心题目获取器获取题目并下发给会话；
    # 若提供了 --challenge-code，则直接按下发的题目运行一次并返回
    if args.sessions <= 1 and not worker_models:
        if args.challenge_code:
            code = args.challenge_code
            target = args.target or ""
            if code:
                os.environ["CRUISER_CHALLENGE_CODE"] = code
            # 未显式指定 target 时，通过 SDK 启动题目容器获取靶场直连地址
            if not target:
                addrs = ensure_challenge_started(code)
                target = ", ".join(f"http://{a}" for a in addrs)
            if not target:
                print(json.dumps({"flag": None, "error": f"题目 {code} 容器未就绪"}, ensure_ascii=False))
                return
            # 为单会话创建独立工作空间
            try:
                base_ws = "/tmp/cruiser_workspaces"
                os.makedirs(base_ws, exist_ok=True)
                ws_dir = os.path.join(base_ws, f"ws_single_{uuid.uuid4().hex[:8]}")
                os.makedirs(ws_dir, exist_ok=True)
                os.environ["CRUISER_WORKSPACE_DIR"] = ws_dir
            except Exception:
                pass
            try:
                result = run_auto_scan(target, max_steps=args.max_steps, quiet=args.quiet, hint=args.hint, challenge_code=code, solver_task=args.solver_task)
            finally:
                # solver 复用 explorer 已启动的容器，绝不能在退出时关闭它（否则拆掉正在用的靶场）
                if not args.solver_task:
                    close_challenge_quiet(code)
            try:
                obj = json.loads(result)
                if isinstance(obj, dict) and "flag" in obj:
                    print(json.dumps(obj, ensure_ascii=False))
                else:
                    print(json.dumps({"flag": result}, ensure_ascii=False))
            except Exception:
                print(json.dumps({"flag": result}, ensure_ascii=False))
            return
        while True:
            chal_map = fetch_all_unsolved()
            chal = None
            # Choose easiest available
            if isinstance(chal_map, dict) and chal_map:
                try:
                    sorted_items = sorted(chal_map.values(), key=lambda it: DIFF_RANK.get((it.get("difficulty") or "easy").lower(), 0))
                    chal = sorted_items[0] if sorted_items else None
                except Exception:
                    chal = None
            if chal_map is None:
                # Fetch error/timeout/abnormal -> do NOT change state, just retry later
                print("[Fetcher] 拉取失败（不更新队列），5 秒后重试…", flush=True)
                time.sleep(5)
                continue
            if not chal:
                try:
                    print("[Fetcher] 暂无可用题目，10 秒后重试…", flush=True)
                except Exception:
                    pass
                time.sleep(10)
                continue
            code = chal.get("challenge_code") or ""
            target = chal.get("target") or (args.target or "")
            if code:
                os.environ["CRUISER_CHALLENGE_CODE"] = code
            # 容器未启动时（target 为空），通过 SDK 启动并等待就绪
            if not target and code:
                addrs = ensure_challenge_started(code)
                target = ", ".join(f"http://{a}" for a in addrs)
            if not target:
                print(f"[Fetcher] {code} 容器未就绪，5 秒后重试…", flush=True)
                time.sleep(5)
                continue
            # 为单会话循环创建独立工作空间
            try:
                base_ws = "/tmp/cruiser_workspaces"
                os.makedirs(base_ws, exist_ok=True)
                ws_dir = os.path.join(base_ws, f"ws_single_{uuid.uuid4().hex[:8]}")
                os.makedirs(ws_dir, exist_ok=True)
                os.environ["CRUISER_WORKSPACE_DIR"] = ws_dir
            except Exception:
                pass
            try:
                result = run_auto_scan(target, max_steps=args.max_steps, quiet=args.quiet, hint=args.hint, challenge_code=code or None)
            finally:
                # 成功或失败后关闭容器，释放活跃名额
                close_challenge_quiet(code)
            try:
                obj = json.loads(result)
                if isinstance(obj, dict) and "flag" in obj:
                    print(json.dumps(obj, ensure_ascii=False))
                else:
                    print(json.dumps({"flag": result}, ensure_ascii=False))
            except Exception:
                print(json.dumps({"flag": result}, ensure_ascii=False))
            # 成功或失败后，继续下一题（由 fetcher 决定是否变更）
            time.sleep(2)
            continue

    # 多会话并发：启动子进程并行扫描，实时将每个会话的输出打印到标准输出；
    # 谁先输出含有 flag 的 JSON，就停止所有会话。
    num = max(1, int(sessions))

    def spawn_worker(idx: int, target: str, code: str | None, hint_text: str | None, env_overrides: dict | None = None, model: str | None = None):
        cmd = [
            sys.executable,
            "-u",  # unbuffered output
            "./main.py",
            "--max-steps",
            str(args.max_steps),
            "--sessions",
            "1",  # 子进程始终以单会话模式运行
        ]
        if target:
            cmd += ["--target", target]
        if code:
            cmd += ["--challenge-code", code]
        if hint_text:
            cmd += ["--hint", hint_text]
        elif args.hint:
            cmd += ["--hint", args.hint]
        if args.quiet:
            cmd.append("--quiet")
        env = os.environ.copy()
        env["CRUISER_WORKER_ID"] = str(idx)
        env["CRUISER_SESSIONS"] = str(num)
        # 子进程一律单会话，绝不能继承 worker 模型清单（否则会误入多会话分支递归 spawn）
        env.pop("CRUISER_WORKER_MODELS", None)
        if code:
            env["CRUISER_CHALLENGE_CODE"] = code
        if env_overrides:
            try:
                for k, v in env_overrides.items():
                    if v is None and k in env:
                        env.pop(k, None)
                    elif v is not None:
                        env[str(k)] = str(v)
            except Exception:
                pass
        # 指定该 worker 使用的模型（供 _claude_env 读取；覆盖默认 ANTHROPIC_MODEL/DEEPSEEK_MODEL）
        if model:
            env["ANTHROPIC_MODEL"] = model
            env["ANTHROPIC_SMALL_FAST_MODEL"] = model
        # 为子会话创建独立工作空间
        try:
            base_ws = "/tmp/cruiser_workspaces"
            os.makedirs(base_ws, exist_ok=True)
            ws_dir = os.path.join(base_ws, f"ws_{(code or 'nocode')}_{idx}_{uuid.uuid4().hex[:8]}")
            os.makedirs(ws_dir, exist_ok=True)
            env["CRUISER_WORKSPACE_DIR"] = ws_dir
        except Exception:
            pass
        # 调试模式：所有输出走标准输出
        if not args.quiet:
            env.pop("CRUISER_DEBUG_STDERR", None)
            env["CRUISER_QUIET"] = "0"
        # 传递超时策略给子进程
        if args.default_timeout and args.default_timeout > 0:
            env["CRUISER_DEFAULT_TIMEOUT"] = str(args.default_timeout)
        if args.max_timeout and args.max_timeout > 0:
            env["CRUISER_MAX_TIMEOUT"] = str(args.max_timeout)
        # 强制子进程无缓冲输出
        env["PYTHONUNBUFFERED"] = "1"
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )
        # 注册到全局进程表，供退出清理使用
        with worker_procs_lock:
            worker_procs.add(p)
        return p

    # -------- solver：watcher 派生的定向执行器（deepseek-v4-flash，单任务≤40 回合，用完即回收）--------
    # 注意：这里的上限卡的是 claude 的「回合(turn)」数（--max-turns），不是日志里的 [COUNT]。
    # [COUNT] 数的是每个 assistant 事件，约为 turn 数的数倍，故一个 40-turn 的 solver 其 [COUNT]
    # 到 ~100+ 属正常，并非未生效（会话触顶时会打印 error_max_turns）。
    SOLVER_MODEL = os.environ.get("CRUISER_SOLVER_MODEL", "deepseek-v4-flash")
    SOLVER_MAX_TURNS = int(os.environ.get("CRUISER_SOLVER_MAX_TURNS", "40") or "40")  # claude 回合(turn)数上限
    MAX_SOLVERS_PER_CHALLENGE = int(os.environ.get("CRUISER_MAX_SOLVERS", "3") or "3")

    def spawn_solver(code: str, target: str, task_text: str, sid: int):
        """派生一个 solver 子进程：只执行 task_text 这一条方向，用 flash 模型、≤SOLVER_MAX_TURNS 个 claude 回合(turn)。"""
        cmd = [
            sys.executable, "-u", "./main.py",
            "--sessions", "1",
            "--challenge-code", code,
            "--target", target,
            "--solver-task", task_text,
            "--max-steps", "0",
        ]
        if args.quiet:
            cmd.append("--quiet")
        env = os.environ.copy()
        env["CRUISER_WORKER_ID"] = f"solver{sid}"   # 视作 worker 子进程：跳过 VPN/容器管理，且不解析 worker_models
        env["CRUISER_SESSIONS"] = str(num)
        env["CRUISER_CHALLENGE_CODE"] = code
        env.pop("CRUISER_WORKER_MODELS", None)
        env["ANTHROPIC_MODEL"] = SOLVER_MODEL
        env["ANTHROPIC_SMALL_FAST_MODEL"] = SOLVER_MODEL
        env["CRUISER_MAX_TURNS"] = str(SOLVER_MAX_TURNS)   # solver 单会话 claude 回合(turn)硬上限（≠日志 [COUNT]）
        env["PYTHONUNBUFFERED"] = "1"
        if not args.quiet:
            env.pop("CRUISER_DEBUG_STDERR", None)
            env["CRUISER_QUIET"] = "0"
        try:
            base_ws = "/tmp/cruiser_workspaces"
            os.makedirs(base_ws, exist_ok=True)
            ws_dir = os.path.join(base_ws, f"ws_solver_{code}_{sid}_{uuid.uuid4().hex[:8]}")
            os.makedirs(ws_dir, exist_ok=True)
            env["CRUISER_WORKSPACE_DIR"] = ws_dir
        except Exception:
            pass
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env, start_new_session=True,
        )
        with worker_procs_lock:
            worker_procs.add(p)
        return p

    # -------- 新流程：预处理(50,不看提示) -> 一级(100,不看提示) -> 二级(150,不看提示) -> 三级(200,四级起看提示) --------
    count_re = re.compile(r"\[COUNT\]\s*(\d+)")
    # 多 flag 判定：解析 submit_flag 工具打印的「flag 进度 X/Y」（来自提交调用的同步返回，无滞后）。
    flag_progress_re = re.compile(r"flag 进度\s*(\d+)\s*/\s*(\d+)")

    def _note_progress_and_win(grp: dict, line: str) -> bool:
        """解析并记录 flag 进度；仅当 X>=Y（全部 flag 到手）时置 winner 返回 True。"""
        m = flag_progress_re.search(line)
        if not m:
            return False
        try:
            x, y = int(m.group(1)), int(m.group(2))
        except Exception:
            return False
        grp["flag_total"] = max(grp.get("flag_total", 0), y)
        grp["flag_correct"] = max(grp.get("flag_correct", 0), x)
        if y >= 1 and x >= y:
            grp["winner"] = line
            return True
        return False

    def _json_flag_is_final(grp: dict) -> bool:
        """worker 输出最终 {"flag"} JSON 时：单 flag/总数未知视为完成；多 flag 未集齐则不停。"""
        total = grp.get("flag_total", 0)
        correct = grp.get("flag_correct", 0)
        return not (total > 1 and correct < total)

    def run_parallel_stage(codes: list[str], items: dict[str, dict], step_threshold: float, prefetch_hint: bool, disable_hint: bool, kill_map: dict[str, threading.Event] | None = None) -> tuple[set[str], set[str]]:
        """并行对多个题目运行一轮，达到阈值或出 flag 即停止每个题目的会话组。
        每题开扫前通过 SDK 启动容器，本轮结束后统一关闭容器释放名额。
        返回 (flagged, remaining, skipped)：
        - flagged: 出 flag 的题
        - remaining: 实际执行了但未解出的题（晋级下一级）
        - skipped: 容器未就绪、本轮根本没执行的题（不算尝试过，留在原层级重试）"""
        groups = {}
        started_codes: list[str] = []
        for code in codes:
            # 优先复用列表中已有地址（容器 available 时），否则启动容器并等待就绪
            target = (items.get(code) or {}).get("target") or ""
            if target:
                # 复用平台侧已在运行的容器（多为异常退出残留）：
                # 同样记入关闭清单，本轮结束统一关闭，避免容器泄漏后本地丢失跟踪
                started_codes.append(code)
            else:
                addrs = ensure_challenge_started(code)
                if addrs:
                    started_codes.append(code)
                target = ", ".join(f"http://{a}" for a in addrs)
            if not target:
                try:
                    print(f"[Stage] {code} 容器未就绪，本轮跳过", flush=True)
                except Exception:
                    pass
                continue
            pre_hint = None
            if prefetch_hint:
                pre_hint = fetch_hint_text(code)
                if pre_hint:
                    try:
                        out_dir = os.path.join(os.getcwd(), "reports")
                        os.makedirs(out_dir, exist_ok=True)
                        with open(os.path.join(out_dir, f"hint_{code}.txt"), "w", encoding="utf-8") as hf:
                            hf.write(pre_hint)
                    except Exception:
                        pass
            # 写入题目描述到共享文件，供 worker/solver（经黑板钩子注入）与 watcher 读取
            try:
                desc = (items.get(code) or {}).get("description") or ""
                if desc.strip():
                    out_dir = os.path.join(os.getcwd(), "reports")
                    os.makedirs(out_dir, exist_ok=True)
                    with open(os.path.join(out_dir, f"desc_{code}.txt"), "w", encoding="utf-8") as df:
                        df.write(desc)
            except Exception:
                pass
            # 基础 env（可禁用提示）
            base_env_overrides = {"CRUISER_DISABLE_HINT": "1"} if disable_hint else {}
            procs = []
            # 单波：num 个黑盒 session（全部计步数阈值）；worker_models 指定各自模型时逐一对应
            for j in range(1, num + 1):
                env_overrides_j = dict(base_env_overrides)
                model_j = worker_models[(j - 1) % len(worker_models)] if worker_models else None
                p = spawn_worker(j, target, code, pre_hint, env_overrides=env_overrides_j, model=model_j)
                procs.append({"proc": p, "wave": 2})
                if j < num:
                    time.sleep(2)
            groups[code] = {
                "procs": procs,
                "counts": {},
                "winner": None,
                "flag_total": 0,
                "flag_correct": 0,
                "stop_threshold": False,
                "start_ts": time.time(),
                "kill_evt": (kill_map.setdefault(code, threading.Event()) if kill_map is not None else threading.Event()),
                "target": target,
                "solver_stop": threading.Event(),
                "solver_threads": [],
            }

        def reader_thread(code: str, p: subprocess.Popen, idx: int, wave: int):
            grp = groups[code]
            prefix = f"[{code}:S{idx}] "
            if not p.stdout:
                return
            for raw in p.stdout:
                if grp["winner"] is not None or grp["stop_threshold"] or grp["kill_evt"].is_set():
                    break
                line = raw.rstrip("\n")
                # JSON flag?（仅接受合法非空 flag，杜绝 {"flag":null}/"|" 之类误判解出）
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and isinstance(obj.get("flag"), str) and _looks_like_flag(obj["flag"]):
                        print(prefix + line, flush=True)
                        # 多 flag 未集齐时不停：仅单 flag/总数未知或已集齐才判胜出
                        if _json_flag_is_final(grp):
                            grp["winner"] = line
                            break
                        continue
                except Exception:
                    pass
                if grp["kill_evt"].is_set():
                    break
                # 多 flag 完成判定：submit_flag 返回「flag 进度 X/Y」，X>=Y 才算整题解出
                if _note_progress_and_win(grp, line):
                    print(prefix + line, flush=True)
                    break
                # COUNT
                m = count_re.search(line)
                if m:
                    try:
                        c = int(m.group(1))
                        grp["counts"][idx] = c
                        # 所有 worker 均为主力波（wave=2），全部计入步数阈值
                        if wave == 2 and c >= step_threshold and grp["winner"] is None:
                            try:
                                print(f"{prefix}[STAGE] 步数达到阈值 {c}/{step_threshold}，结束该题本轮", flush=True)
                            except Exception:
                                pass
                            grp["stop_threshold"] = True
                            break
                    except Exception:
                        pass
                print(prefix + line, flush=True)

        def _solver_stage_over(grp) -> bool:
            return grp["winner"] is not None or grp["stop_threshold"] or grp["kill_evt"].is_set() or grp["solver_stop"].is_set()

        def solver_driver(code: str):
            """每题一个驱动线程：维持 ≤MAX_SOLVERS_PER_CHALLENGE 个 solver，各自 FIFO 领一条任务；
            solver 退出即回收并补位；出 flag / 本轮结束时停止并清杀所有 solver。"""
            grp = groups[code]
            target = grp["target"]
            active: dict[int, subprocess.Popen] = {}
            sid_seq = 0

            def solver_reader(p: subprocess.Popen, sid: int):
                if not p.stdout:
                    return
                prefix = f"[{code}:SOLVER{sid}] "
                for raw in p.stdout:
                    if _solver_stage_over(grp):
                        break
                    line = raw.rstrip("\n")
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and isinstance(obj.get("flag"), str) and _looks_like_flag(obj["flag"]):
                            print(prefix + line, flush=True)
                            if _json_flag_is_final(grp):
                                grp["winner"] = line
                                break
                            continue
                    except Exception:
                        pass
                    if _note_progress_and_win(grp, line):
                        print(prefix + line, flush=True)
                        break
                    print(prefix + line, flush=True)

            while not _solver_stage_over(grp):
                # 回收已退出的 solver
                for sid, p in list(active.items()):
                    if p.poll() is not None:
                        active.pop(sid, None)
                        with worker_procs_lock:
                            worker_procs.discard(p)
                # 补位：FIFO 认领新任务（claim 即擦除，天然去重）
                while len(active) < MAX_SOLVERS_PER_CHALLENGE and not _solver_stage_over(grp):
                    try:
                        claimed = claim_task(code, f"solver")
                    except Exception:
                        claimed = None
                    if not claimed:
                        break
                    sid_seq += 1
                    sid = sid_seq
                    try:
                        p = spawn_solver(code, target, claimed["text"], sid)
                    except Exception as e:
                        try:
                            print(f"[{code}:SOLVER{sid}] 启动失败: {e}", flush=True)
                        except Exception:
                            pass
                        continue
                    active[sid] = p
                    try:
                        print(f"[{code}:SOLVER{sid}] 领取并执行: {claimed['text'][:80]}", flush=True)
                    except Exception:
                        pass
                    threading.Thread(target=solver_reader, args=(p, sid), daemon=True).start()
                time.sleep(1.0)

            # 收尾：清杀所有在跑的 solver
            for p in list(active.values()):
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except Exception:
                        try:
                            p.terminate()
                        except Exception:
                            pass
            time.sleep(1)
            for p in list(active.values()):
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            p.kill()
                        except Exception:
                            pass
                with worker_procs_lock:
                    worker_procs.discard(p)

        threads = []
        for code, grp in groups.items():
            for idx, entry in enumerate(grp["procs"], start=1):
                p = entry["proc"]
                wave = entry["wave"]
                t = threading.Thread(target=reader_thread, args=(code, p, idx, wave), daemon=True)
                t.start()
                threads.append(t)
            # 每题一个 solver 驱动线程（explorer 之外并行拉起，专门消化任务板方向）
            st = threading.Thread(target=solver_driver, args=(code,), daemon=True)
            st.start()
            grp["solver_threads"].append(st)

        # 等待所有题目完成本轮（阈值或 flag）
        while True:
            all_done = True
            for code, grp in groups.items():
                if grp["kill_evt"].is_set():
                    grp["stop_threshold"] = True
                if grp["winner"] is None and not grp["stop_threshold"]:
                    # 检查进程是否全部退出
                    any_alive = False
                    for entry in grp["procs"]:
                        p = entry["proc"]
                        if p.poll() is None:
                            any_alive = True
                            break
                    if any_alive:
                        all_done = False
                        break
            if all_done:
                break
            try:
                time.sleep(0.2)
            except Exception:
                pass

        # 停掉所有进程（整组杀进程：先发 SIGTERM 到进程组，超时再 SIGKILL）
        # 先让每题的 solver 驱动收尾（它会清杀自己派生的 solver 子进程），再等其退出
        for grp in groups.values():
            grp["solver_stop"].set()
        for grp in groups.values():
            for st in grp.get("solver_threads", []):
                try:
                    st.join(timeout=6)
                except Exception:
                    pass
        for grp in groups.values():
            for entry in grp["procs"]:
                p = entry["proc"]
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except Exception:
                        try:
                            p.terminate()
                        except Exception:
                            pass
            # 等待片刻后强制杀
            for entry in grp["procs"]:
                p = entry["proc"]
                try:
                    p.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            p.kill()
                        except Exception:
                            pass

        # 从全局进程表注销（进程已在本轮收尾时终止）
        for grp in groups.values():
            for entry in grp["procs"]:
                with worker_procs_lock:
                    worker_procs.discard(entry["proc"])

        # 关闭本轮启动的题目容器，释放靶场资源与活跃名额
        for code in started_codes:
            close_challenge_quiet(code)

        flagged: set[str] = set()
        remaining: set[str] = set()
        skipped: set[str] = set()
        for code in codes:
            grp = groups.get(code)
            if grp is None:
                # 容器未就绪，本轮未实际执行
                skipped.add(code)
            elif grp["winner"] is not None:
                flagged.add(code)
            else:
                remaining.add(code)
        return flagged, remaining, skipped

    preprocessed: set[str] = set()
    solved: set[str] = set()
    tier1: set[str] = set()
    tier2: list[str] = []
    tier3: list[str] = []
    stage_lock = threading.Lock()
    kill_flags: dict[str, threading.Event] = {}
    preproc_threads: dict[str, threading.Thread] = {}
    tier1_threads: dict[str, threading.Thread] = {}
    tier2_threads: dict[str, threading.Thread] = {}
    tier3_threads: dict[str, threading.Thread] = {}

    # 平台活跃容器名额上限（实测为 3）：同时在跑的题目数不超过该值，
    # 可用 CRUISER_MAX_ACTIVE 覆盖。超过上限的启动请求会被平台拒绝。
    MAX_INFLIGHT = max(1, int(os.environ.get("CRUISER_MAX_ACTIVE", "3") or "3"))

    # 启动冷却：被平台以 max active 拒绝后，该题在此时间戳前不再尝试启动。
    # 覆盖容器关闭的服务端异步拆除窗口（close 后平台仍短暂计数）。
    start_cooldowns: dict[str, float] = {}
    zombie_closing: set[str] = set()  # 正在回收中的僵尸容器

    def _in_cooldown(code: str) -> bool:
        return time.time() < start_cooldowns.get(code, 0.0)

    def _inflight_count() -> int:
        return len(preproc_threads) + len(tier1_threads) + len(tier2_threads) + len(tier3_threads)

    def _inflight_codes() -> set[str]:
        return set(preproc_threads) | set(tier1_threads) | set(tier2_threads) | set(tier3_threads)

    # -------- 退出清理：Ctrl+C / SIGTERM 时整组杀掉全部 worker 并关闭活跃容器 --------
    # worker 以 start_new_session 启动（独立进程组，收不到 Ctrl+C 的 SIGINT），
    # 因此必须由父进程在退出时逐个 killpg 回收，否则会全部漏网成孤儿进程。
    worker_procs: set[subprocess.Popen] = set()
    worker_procs_lock = threading.Lock()

    def _cleanup_workers() -> None:
        # 1) 整组终止所有 worker（worker 组内含其 claude 子进程）
        with worker_procs_lock:
            procs = list(worker_procs)
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)
                except Exception:
                    pass
        time.sleep(1)
        for p in procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except Exception:
                    pass
        if procs:
            print(f"[Main] 已清理 {len(procs)} 个 worker 进程组", flush=True)
        # 2) 关闭所有活跃容器，释放平台名额。
        #    注意：此处不能用 SDK——atexit 阶段 concurrent.futures 已全局关停，
        #    httpx/asyncio 无法调度新任务（RuntimeError: cannot schedule new futures）。
        #    改用 requests 直连 REST 端点（端点格式与 SDK 一致）；
        #    close 在服务端较慢，读超时也视为已发送（服务端异步完成）。
        try:
            base_url = os.environ.get("BENCHMARK_BASE_URL", "").rstrip("/")
            token = os.environ.get("BENCHMARK_TOKEN", "")
            if base_url and token:
                headers = {"BENCHMARK_TOKEN": token}
                resp = requests.get(f"{base_url}/openapi/v1/challenges", headers=headers, timeout=10)
                for ch in resp.json():
                    if ch.get("container_status", "stopped") == "stopped":
                        continue
                    code = ch.get("unique_code", "")
                    if not code:
                        continue
                    try:
                        requests.post(
                            f"{base_url}/openapi/v1/challenges/close",
                            params={"unique_code": code},
                            headers=headers,
                            timeout=20,
                        )
                        print(f"[Main] 已关闭 {code} 容器", flush=True)
                    except Exception:
                        print(f"[Main] 关闭 {code} 请求已发送（响应超时，服务端将异步完成）", flush=True)
        except Exception as e:
            try:
                print(f"[Main] 关闭容器时异常: {type(e).__name__}: {e}", flush=True)
            except Exception:
                pass

    def _shutdown(signum, frame):
        # 抛出 SystemExit 让 with/锁正常展开，atexit 负责实际清理
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    atexit.register(_cleanup_workers)

    def _rank_code(c: str, items_ref: dict[str, dict]) -> int:
        return DIFF_RANK.get((items_ref.get(c, {}).get("difficulty") or "easy").lower(), 0)

    while True:
        items = fetch_all_unsolved()
        if items is None:
            print("[Fetcher] 拉取失败（等待 5 秒）", flush=True)
            time.sleep(5)
            continue
        # 即便列表为空也要做一次清理/强杀判断
        present = set(items.keys()) if isinstance(items, dict) else set()
        with stage_lock:
            preprocessed &= present
            solved &= present
            tier1 &= present
            tier2 = [c for c in tier2 if c in present]
            tier3 = [c for c in tier3 if c in present]
            # 对于已不在平台但仍在运行的题，触发强杀（包含平台列表为空的场景）
            for code in list(kill_flags.keys()):
                if code not in present:
                    try:
                        print(f"[Fetcher] 题目 {code} 已从平台移除，强制停止其会话…", flush=True)
                    except Exception:
                        pass
                    try:
                        kill_flags[code].set()
                    except Exception:
                        pass
        if not present:
            print("[Fetcher] 暂无可用题目，10 秒后重试…", flush=True)
            time.sleep(10)
            continue

        # 僵尸容器回收：平台侧仍在运行但本地无在飞线程的容器（异常退出残留/拆除延迟），
        # 后台线程逐个关闭，避免挤占活跃名额导致误拒新启动
        with stage_lock:
            zombies = [
                c for c in present
                if (items[c].get("container_status") or "stopped") != "stopped"
                and c not in _inflight_codes()
                and c not in zombie_closing
            ]
        for code in zombies:
            zombie_closing.add(code)
            def _reap(cc: str):
                try:
                    print(f"[Reaper] 回收僵尸容器 {cc}", flush=True)
                    close_challenge_quiet(cc)
                finally:
                    zombie_closing.discard(cc)
            threading.Thread(target=_reap, args=(code,), daemon=True).start()

        # 启动预处理（动态、不看提示、每题独立执行器，50步）
        new_codes = [c for c in present if c not in preprocessed and not _in_cooldown(c)]
        for code in new_codes:
            if code in preproc_threads:
                continue
            if _inflight_count() >= MAX_INFLIGHT:
                break  # 活跃名额已满，剩余题目留待下一轮调度
            print(f"[Stage-Preprocess] 启动 {code} 的 50 步预处理…", flush=True)
            def _preproc_one(c: str, items_snap: dict[str, dict]):
                try:
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=50, prefetch_hint=False, disable_hint=True, kill_map=kill_flags)
                    with stage_lock:
                        if c in flagged:
                            preprocessed.add(c)
                            solved.add(c)
                        elif c in remaining:
                            preprocessed.add(c)
                            tier1.add(c)
                        # skipped：未实际执行，不标记 preprocessed，下一轮仍作为新题优先重试
                finally:
                    with stage_lock:
                        preproc_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t = threading.Thread(target=_preproc_one, args=(code, items.copy()), daemon=True)
            preproc_threads[code] = t
            t.start()

        # 启动一级（动态并行、不看提示、每题独立执行器，100步）
        with stage_lock:
            tier1_ready = sorted([c for c in tier1 if c not in tier1_threads and not _in_cooldown(c)], key=lambda c: _rank_code(c, items))
        for code in tier1_ready:
            if _inflight_count() >= MAX_INFLIGHT:
                break
            print(f"[Stage-Tier1] 启动 {code}（不看提示）至 100 步…", flush=True)
            def _tier1_one(c: str, items_snap: dict[str, dict]):
                try:
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=100, prefetch_hint=False, disable_hint=True, kill_map=kill_flags)
                    with stage_lock:
                        if c in flagged:
                            solved.add(c)
                            tier1.discard(c)
                        elif c in remaining:
                            tier1.discard(c)
                            # 晋级到二级
                            tier2.append(c)
                        # skipped：未实际执行，留在一级等待重试
                finally:
                    with stage_lock:
                        tier1_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t = threading.Thread(target=_tier1_one, args=(code, items.copy()), daemon=True)
            with stage_lock:
                tier1_threads[code] = t
            t.start()

        # 启动二级（并行、不看提示、每题独立执行器，150步）
        with stage_lock:
            tier2_ready = [c for c in tier2 if c not in tier2_threads and not _in_cooldown(c)]
        for code in tier2_ready:
            if _inflight_count() >= MAX_INFLIGHT:
                break
            print(f"[Stage-Tier2] 启动 {code}（不看提示）至 150 步…", flush=True)
            def _tier2_one(c: str, items_snap: dict[str, dict]):
                try:
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=150, prefetch_hint=False, disable_hint=True, kill_map=kill_flags)
                    with stage_lock:
                        if c in flagged:
                            try:
                                tier2.remove(c)
                            except ValueError:
                                pass
                            solved.add(c)
                        elif c in remaining:
                            # 晋级到三级
                            try:
                                tier2.remove(c)
                            except ValueError:
                                pass
                            tier3.append(c)
                        # skipped：未实际执行，留在二级等待重试
                finally:
                    with stage_lock:
                        tier2_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t2 = threading.Thread(target=_tier2_one, args=(code, items.copy()), daemon=True)
            with stage_lock:
                tier2_threads[code] = t2
            t2.start()

        # 启动三级（并行、带提示、每题独立执行器，200步；四级起才开始看提示）
        with stage_lock:
            tier3_ready = [c for c in tier3 if c not in tier3_threads and not _in_cooldown(c)]
        for code in tier3_ready:
            if _inflight_count() >= MAX_INFLIGHT:
                break
            print(f"[Stage-Tier3] 启动 {code}（带提示）至 200 步…", flush=True)
            def _tier3_one(c: str, items_snap: dict[str, dict]):
                try:
                    # step_threshold=200：四级带提示、上限 200 步；由 flag / 步数达标 / 平台移除(kill) / 进程退出收敛
                    flagged, remaining, skipped = run_parallel_stage([c], items_snap, step_threshold=200, prefetch_hint=True, disable_hint=False, kill_map=kill_flags)
                    with stage_lock:
                        # 从三级移除
                        try:
                            tier3.remove(c)
                        except ValueError:
                            pass
                        if c in flagged:
                            solved.add(c)
                        else:
                            # 未解出或未实际执行，放回队尾
                            tier3.append(c)
                finally:
                    with stage_lock:
                        tier3_threads.pop(c, None)
                        kill_flags.pop(c, None)
            t3 = threading.Thread(target=_tier3_one, args=(code, items.copy()), daemon=True)
            with stage_lock:
                tier3_threads[code] = t3
            t3.start()

        # 小憩，等待下一轮调度
        time.sleep(1.0)


if __name__ == "__main__":
    main()
