#!/usr/bin/env python
"""清理悬空进程：父调度器/父 worker 已死的 worker 与 claude 进程（整组清理）。

判定逻辑：
- claude 进程：沿 PPID 链向上找，没有任何存活的 main.py 祖先 → 悬空
- worker 进程（main.py --sessions 1 且带 CRUISER_WORKER_ID）：
  父调度器（另一个 main.py 进程）已不存在 → 悬空
- 用户在终端直接运行的单题模式（main.py --challenge-code，无 WORKER_ID）不受影响

用法:
    python kill_orphans.py          # 实际清理
    python kill_orphans.py --dry    # 只列出，不杀
"""
from __future__ import annotations

import os
import signal
import sys


def _read_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _read_ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 1


def _read_environ(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _has_live_main_ancestor(pid: int) -> bool:
    """沿父进程链向上找存活的 main.py 进程（不含自身）。"""
    seen = set()
    p = _read_ppid(pid)
    while p > 1 and p not in seen:
        seen.add(p)
        if "main.py" in _read_cmdline(p):
            return True
        p = _read_ppid(p)
    return False


def main() -> int:
    dry = "--dry" in sys.argv
    self_pid = os.getpid()
    dangling: list[tuple[int, str, str]] = []  # (pid, kind, cmdline 摘要)

    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == self_pid:
            continue
        cmd = _read_cmdline(pid)
        if not cmd:
            continue
        # 用 argv[0] 判定真实可执行文件，避免误匹配 cmdline 文本中包含
        # "claude -p"/"main.py" 字样的 shell 包装进程（如 bash -c '...'）
        argv0 = cmd.split()[0] if cmd.split() else ""
        kind = None
        if (argv0 == "claude" or argv0.endswith("/claude")) and " -p " in cmd:
            kind = "claude"
        elif (
            "python" in os.path.basename(argv0)
            and "main.py" in cmd
            and "--sessions 1" in cmd
            and "CRUISER_WORKER_ID" in _read_environ(pid)
        ):
            kind = "worker"
        if kind is None:
            continue
        if not _has_live_main_ancestor(pid):
            dangling.append((pid, kind, cmd[:100]))

    if not dangling:
        print("没有悬空进程")
        return 0

    killed_groups = set()
    for pid, kind, cmd in dangling:
        try:
            pgid = os.getpgid(pid)
        except Exception:
            pgid = pid
        summary = f"{kind} pid={pid} pgid={pgid} cmd={cmd}"
        if dry:
            print(f"[DRY] 将清理: {summary}")
            continue
        if pgid in killed_groups:
            continue
        killed_groups.add(pgid)
        try:
            os.killpg(pgid, signal.SIGKILL)  # 整组杀：含 claude 的 bash 工具子进程
            print(f"已清理: {summary}")
        except ProcessLookupError:
            pass
        except Exception as e:
            print(f"清理 pid={pid} 失败: {e}")
    if not dry:
        print(f"共清理 {len(killed_groups)} 个悬空进程组")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
