from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys
import tempfile
import fcntl
from pathlib import Path
import json
from typing import Optional, Literal, List, Dict, Any, Union
import shutil
import hashlib
import time
import random

from pydantic import BaseModel, Field
from langchain.tools import tool
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

import requests
from tsec_benchmark import (
    DuplicateSubmit,
    InternalError,
    ResourceUnavailable,
    TSecBenchmark,
    TSecConnectionError,
    TSecError,
)

# 控制台绿色打印（尽量兼容 Windows）
_COLORAMA_READY = False

# ---------------------------------------------------------------------------
# tsec-benchmark SDK 客户端（进程级懒加载单例）
# 凭证从环境变量读取：BENCHMARK_BASE_URL / BENCHMARK_TOKEN（可在 .env 配置）
# ---------------------------------------------------------------------------
_BENCHMARK_CLIENT: Optional[TSecBenchmark] = None
_BENCHMARK_CLIENT_LOCK = threading.Lock()


def get_benchmark_client() -> TSecBenchmark:
    """获取 tsec-benchmark SDK 同步客户端（懒加载单例）。

    - 首次调用时创建客户端并做 VPN 联通预检（失败抛 VpnCheckError）；
    - SDK 内部以独立线程驱动事件循环，多线程调用安全；
    - 进程退出时无需显式关闭（事件循环为守护线程，随进程回收）。
    """
    global _BENCHMARK_CLIENT
    if _BENCHMARK_CLIENT is not None:
        return _BENCHMARK_CLIENT
    with _BENCHMARK_CLIENT_LOCK:
        if _BENCHMARK_CLIENT is not None:
            return _BENCHMARK_CLIENT
        base_url = os.environ.get("BENCHMARK_BASE_URL", "").strip()
        token = os.environ.get("BENCHMARK_TOKEN", "").strip()
        if not base_url or not token:
            raise RuntimeError("缺少 BENCHMARK_BASE_URL / BENCHMARK_TOKEN 环境变量（可在项目根目录 .env 中配置）")
        client = TSecBenchmark(base_url=base_url, token=token)
        client.check_vpn()  # 进入跑分流程前的 VPN 预检，失败抛 VpnCheckError
        _BENCHMARK_CLIENT = client
        return client
def _ensure_color():
    global _COLORAMA_READY
    if _COLORAMA_READY:
        return
    try:  # 尝试在 Windows 上启用 ANSI 支持
        import colorama  # type: ignore

        colorama.just_fix_windows_console()  # 自动启用/修复控制台颜色
        _COLORAMA_READY = True
    except Exception:
        # 未安装 colorama 或不需要，直接使用 ANSI 码
        _COLORAMA_READY = True


def _print_green(msg: str) -> None:
    # 静默模式：在自动扫描时通过环境变量抑制中间输出
    if os.environ.get("CRUISER_QUIET") == "1":
        return
    to_stderr = os.environ.get("CRUISER_DEBUG_STDERR") == "1"
    try:
        _ensure_color()
        colored = f"\x1b[32m{msg}\x1b[0m"
        if to_stderr:
            print(colored, file=sys.stderr, flush=True)
        else:
            print(colored, flush=True)
    except Exception:
        if to_stderr:
            print(msg, file=sys.stderr, flush=True)
        else:
            print(msg, flush=True)

def _print_color(msg: str, color_code: str) -> None:
    """以指定 ANSI 颜色打印高亮消息（尊重 CRUISER_QUIET 与 CRUISER_DEBUG_STDERR）。"""
    if os.environ.get("CRUISER_QUIET") == "1":
        return
    to_stderr = os.environ.get("CRUISER_DEBUG_STDERR") == "1"
    try:
        _ensure_color()
        colored = f"\x1b[{color_code}m{msg}\x1b[0m"
        if to_stderr:
            print(colored, file=sys.stderr, flush=True)
        else:
            print(colored, flush=True)
    except Exception:
        if to_stderr:
            print(msg, file=sys.stderr, flush=True)
        else:
            print(msg, flush=True)


# ===============
# 基础路径工具
# ===============
def get_workspace_root() -> Path:
    """获取当前工作空间根路径（进程当前工作目录）。

    保留为简易封装，便于后续在容器/沙箱中限制访问范围。
    当前实现：返回 os.getcwd() 的解析绝对路径。
    """
    try:
        return Path(os.getcwd()).resolve()
    except Exception:
        return Path(".").resolve()


class ReadFileInput(BaseModel):
    path: str = Field(..., description="要读取的文件路径（相对或绝对）")
    encoding: str = Field("utf-8", description="文件解码使用的编码；默认为 utf-8")
    max_bytes: int = Field(0, ge=0, description="可选：>0 时仅读取前 max_bytes 字节；0 表示不限制")


@tool("read_file", args_schema=ReadFileInput, return_direct=False)
def read_file_tool(path: str, encoding: str = "utf-8", max_bytes: int = 0) -> str:
    """读取本地文本文件内容。

    说明:
    - 支持相对/绝对路径；相对路径基于当前工作目录。
    - 若文件过大可用 max_bytes 限制读取的原始字节数（不截断则设为 0）。
    - 返回纯文本（无法解码的部分以替换字符保留）。
    - 报错统一以 [ERROR] 前缀标识。
    """
    _print_green("[TOOL] read_file" + path)
    try:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = get_workspace_root() / p
        p = p.resolve()
    except Exception as e:
        return f"[ERROR] 路径解析失败: {e}"

    if not p.exists():
        return f"[ERROR] 文件不存在: {p}"
    if p.is_dir():
        return f"[ERROR] 目标是目录: {p}"
    try:
        raw = p.read_bytes()
        if max_bytes and max_bytes > 0:
            raw = raw[:max_bytes]
        text = raw.decode(encoding, errors="replace")
        return text
    except Exception as e:
        return f"[ERROR] 读取失败: {e}"


class RunCommandInput(BaseModel):
    command: str = Field(..., description="要执行的命令（字符串）")
    shell: Literal["none", "powershell", "cmd", "bash"] = Field(
        "powershell",
        description="执行环境：none=直接执行；powershell=PowerShell；cmd=cmd.exe；bash=/bin/bash -lc",
    )
    cwd: Optional[str] = Field(None, description="可选工作目录（任意目录，若不存在将报错）")
    # 不再支持超时与最大输出限制参数，保持工具简单、同步并返回完整输出


@tool("run_command", args_schema=RunCommandInput, return_direct=False)
def run_command_tool(
    command: str,
    shell: Literal["none", "powershell", "cmd", "bash"] = "powershell",
    cwd: Optional[str] = None,
) -> str:
    """在本地执行命令并返回结果（仅限本机；默认不限制超时；默认不截断输出）。

    注意：本工具会执行任意命令，请在可信环境使用；
    - 现在允许任意 cwd（若不存在将报错）。
    - 默认使用 PowerShell（Windows 上更方便），可切换为 cmd/none；Linux 默认会切换到 bash。
    - 不再提供超时与最大输出限制参数；始终同步等待完成并返回完整输出。
    返回格式：以文本方式包含 exit_code/stdout/stderr/timed_out 字段信息。
    """
    _print_green("[TOOL] run_command" + command)
    # 解析工作目录（允许任意目录）
    workspace_root = get_workspace_root()
    run_cwd = workspace_root
    if cwd:
        try:
            rp = Path(cwd)
            rp = rp if rp.is_absolute() else (workspace_root / rp)
            rp = rp.resolve()
            if not rp.exists() or not rp.is_dir():
                return f"[ERROR] 工作目录不存在或不是目录: {cwd}"
            run_cwd = rp
        except Exception as e:  # noqa: BLE001
            return f"[ERROR] 非法工作目录: {cwd} ({e})"

    system = platform.system().lower()

    # 在非 Windows 平台，将默认的 powershell 调整为 bash 更符合常见环境
    if not system.startswith("win") and shell == "powershell":
        shell = "bash"

    if shell == "powershell":
        if system.startswith("win"):
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ]
        else:
            # 非 Windows 上尝试 pwsh
            cmd = [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ]
    elif shell == "cmd":
        if system.startswith("win"):
            cmd = ["cmd.exe", "/C", command]
        else:
            return "[ERROR] 当前系统不支持 cmd.exe 模式"
    elif shell == "bash":
        if system.startswith("win"):
            return "[ERROR] Windows 上不支持 bash 模式（可使用 powershell 或 cmd）"
        cmd = ["/bin/bash", "-lc", command]
    else:  # none
        # 尽量避免 shell=True，进行简单拆分
        try:
            cmd = shlex.split(command, posix=not system.startswith("win"))
        except Exception as e:  # noqa: BLE001
            return f"[ERROR] 命令解析失败: {e}"
        if not cmd:
            return "[ERROR] 空命令"

    try:
        run_kwargs = dict(cwd=str(run_cwd), capture_output=True, text=True)
        # 不设置 timeout，始终等待命令完成
        proc = subprocess.run(
            cmd,
            **run_kwargs,  # type: ignore[arg-type]
        )
        stdout = (proc.stdout or "")
        stderr = (proc.stderr or "")
        out = stdout + ("\n" if stdout and stderr else "") + stderr
        # 若调用的是 dirsearch：返回其“内置报告”的文件路径（从输出中提取 Output File: ...）
        try:
            if isinstance(command, str) and ("dirsearch" in command.lower()):
                import re
                m = re.search(r"Output File:\s*(\S+)", out)
                if not m:
                    m = re.search(r"^Output File:\s*(.+)$", out, flags=re.MULTILINE)
                if m:
                    out = m.group(1).strip()
                else:
                    out = out
        except Exception:
            pass
        truncated = False
        return (
            f"exit_code={proc.returncode}\n"
            f"timed_out=false\n"
            f"truncated={'true' if truncated else 'false'}\n"
            f"cwd={run_cwd}\n"
            f"output=\n{out}"
        )
    except Exception as e:  # noqa: BLE001
        return f"[ERROR] 执行失败: {e}"


class RunPythonInput(BaseModel):
    code: str = Field(..., description="要执行的 Python 代码（多行字符串）")
    timeout: int = Field(
        0,
        ge=0,
        le=7200,
        description="超时秒数；0 表示无限制（不传给子进程）；>0 时按该值作为超时",
    )
    cwd: Optional[str] = Field(None, description="可选工作目录（任意目录，若不存在将报错）")
    max_output: int = Field(0, ge=0, description="默认不截断输出；>0 时按该上限截断")


@tool("run_python", args_schema=RunPythonInput, return_direct=False)
def run_python_tool(
    code: str,
    timeout: int = 0,
    cwd: Optional[str] = None,
    max_output: int = 0,
) -> str:
    """执行一段 Python 代码并返回结果（子进程；默认不限制超时；默认不截断输出）。

    - 使用与当前进程相同的 Python 解释器 (sys.executable) 在子进程中执行；
    - 通过临时脚本文件承载代码，避免 -c 引号转义问题；
    - 可指定工作目录；
    - 超时策略与 run_command 一致：timeout<=0 时不限制；>0 时按该值作为超时；
    - 返回格式：以文本方式包含 exit_code/stdout/stderr/timed_out 等信息。
    """
    _print_green("[TOOL] run_python")

    # 超时：0/None 表示不限制

    # 解析工作目录（允许任意目录）
    workspace_root = get_workspace_root()
    run_cwd = workspace_root
    if cwd:
        try:
            rp = Path(cwd)
            rp = rp if rp.is_absolute() else (workspace_root / rp)
            rp = rp.resolve()
            if not rp.exists() or not rp.is_dir():
                return f"[ERROR] 工作目录不存在或不是目录: {cwd}"
            run_cwd = rp
        except Exception as e:  # noqa: BLE001
            return f"[ERROR] 非法工作目录: {cwd} ({e})"

    # 将代码写入临时脚本
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
            tf.write(code)
            tmp_path = Path(tf.name)

        cmd = [sys.executable, str(tmp_path)]
        run_kwargs = dict(cwd=str(run_cwd), capture_output=True, text=True)
        if timeout and timeout > 0:
            run_kwargs["timeout"] = timeout  # type: ignore[index]
        proc = subprocess.run(
            cmd,
            **run_kwargs,  # type: ignore[arg-type]
        )
        stdout = (proc.stdout or "")
        stderr = (proc.stderr or "")
        out = stdout + ("\n" if stdout and stderr else "") + stderr
        truncated = False
        if max_output and max_output > 0 and len(out) > max_output:
            out = out[:max_output] + f"\n[TRUNCATED] 输出超过 {max_output} 字符，已截断。"
            truncated = True
        return (
            f"exit_code={proc.returncode}\n"
            f"timed_out=false\n"
            f"truncated={'true' if truncated else 'false'}\n"
            f"cwd={run_cwd}\n"
            f"output=\n{out}"
        )
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") + ("\n" if e.stdout and e.stderr else "") + (e.stderr or "")
        if max_output and max_output > 0 and len(partial) > max_output:
            partial = partial[:max_output] + f"\n[TRUNCATED] 输出超过 {max_output} 字符，已截断。"
        return (
            f"exit_code=-1\n"
            f"timed_out=true\n"
            f"truncated=false\n"
            f"cwd={run_cwd}\n"
            f"output=\n{partial}"
        )
    except Exception as e:  # noqa: BLE001
        return f"[ERROR] 执行失败: {e}"
    finally:
        # 清理临时文件
        try:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass


ALL_TOOLS = [
    read_file_tool,
    run_command_tool,
    run_python_tool,
]


# =========================
# 安全工具：枚举与调用
# =========================


def _known_security_tools() -> list[dict]:
    """声明已知的命令行安全工具。可在此扩展更多条目。"""
    return [
        {
            "name": "dirsearch",
            "command": "dirsearch",
            "description": "Web 目录/文件爆破工具。建议仅保留常见有效状态码：使用 -i 200,301,302 以避免输出过大。",
        },
        {
            "name": "sqlmap",
            "command": "sqlmap",
            "description": "自动化 SQL 注入和数据库接管工具",
        },
        {
            "name":"fenjing",
            "command":"fenjing",
            "description":"`python`web框架的模板注入工具",
        },
        {
            "name": "pwntools",
            "command": "pwn",
            "description": "二进制利用框架（CTF pwn 题）：process 交互、ELF 解析、checksec、cyclic 等",
        },
    ]


class ListSecurityToolsInput(BaseModel):
    only_available: bool = Field(
        True, description="为 true 时仅返回当前环境可用（在 PATH 可找到）的工具"
    )
    with_version: bool = Field(
        True, description="尝试读取工具版本（执行 --version，设为 False 可加速）"
    )


@tool("list_security_tools", args_schema=ListSecurityToolsInput, return_direct=False)
def list_security_tools_tool(only_available: bool = True, with_version: bool = True) -> str:
    """列出已知安全工具，并标注当前环境中哪些可用。返回 JSON 字符串。"""
    _print_green("[TOOL] list_security_tools")
    tools = _known_security_tools()
    result: list[dict] = []
    for t in tools:
        cmd = t.get("command")
        path = shutil.which(cmd) if isinstance(cmd, str) else None
        available = path is not None
        if only_available and not available:
            continue
        item = dict(t)
        item.update({"available": available})
        if available and with_version:
            version: Optional[str] = None
            try:
                p = subprocess.run(
                        [cmd, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=2,
                )
                if p.returncode == 0:
                        out = (p.stdout or p.stderr or "").strip().splitlines()
                        version = out[0] if out else None
                else:
                        # 回退尝试 -V（部分工具使用 -V 输出版本）
                        p2 = subprocess.run(
                            [cmd, "-V"],
                            capture_output=True,
                            text=True,
                            timeout=2,
                        )
                        if p2.returncode == 0:
                            out2 = (p2.stdout or p2.stderr or "").strip().splitlines()
                            version = out2[0] if out2 else None
            except Exception:
                version = None
            item["version"] = version
        result.append(item)
    try:
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception:
        return json.dumps(result, ensure_ascii=False)


# 注册 list_security_tools 到工具列表
ALL_TOOLS.append(list_security_tools_tool)

class SubmitFlagInput(BaseModel):
    challenge_code: str = Field(..., description="挑战代码")
    flag: str = Field(..., description="要提交的 flag")


# ---------------------------------------------------------------------------
# 跨进程 flag 存储：所有 worker/solver 子进程共享一份磁盘状态（JSON + flock）。
#   - correct: {flag值: 归属题目code} —— 某 flag 一旦被某题交对，其它题再交同一 flag 直接拒绝
#     （常见误交别题 flag）；同题再交不拦截。
#   - wrong:   {题目code: [错误flag,...]} —— 每题各自维护错误 flag 表（同一 flag 对 A 错、对 B 可能对，
#     故按题隔离）；已知错误 flag 直接判错，不再打平台，避免反复无效提交。
# ---------------------------------------------------------------------------
def _flagstore_paths() -> tuple[str, str]:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports = os.path.join(root, "reports")
    try:
        os.makedirs(reports, exist_ok=True)
    except Exception:
        pass
    return os.path.join(reports, "_flagstore.json"), os.path.join(reports, "_flagstore.lock")


def _flag_norm(flag: str) -> str:
    """归一化 flag 用于比较：去首尾空白。"""
    return (flag or "").strip()


# ---------------------------------------------------------------------------
# flag 形态判定（防误提交：CSS/代码片段等非 flag 文本）
#
# 三层防线：
#   1. 形态正则 + 占位符黑名单（基础形态）；
#   2. 前缀/正文黑名单：HTML 标签、CSS·JS 关键字前缀（div{...}、h1{...}），
#      及 body 呈 CSS 属性:值 / 含分号声明串的模式（opacity:0.8、font-size:1.5em）；
#   3. 前缀学习：flagstore 中已有平台确认的正确 flag 后，新候选前缀必须命中
#      已确认前缀集合（本平台前缀统一，如 flag{/FLAG{）；命中已确认前缀者豁免黑名单。
# ---------------------------------------------------------------------------
_FLAG_FULL_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}")

# 常见模板占位符（小写）：模型有时把提示词里的 flag 格式示例原样吐出
_PLACEHOLDER_FLAGS = {
    "flag{...}", "flag{flag}", "flag{xxx}", "flag{your_flag_here}", "flag{flag_content}",
    "flag{实际flag内容}", "flag{实际内容}", "实际flag内容", "flag_content",
}

# 非 flag 前缀黑名单（小写）：HTML 标签 / CSS 选择器 / JS·CSS 关键字
_NON_FLAG_PREFIXES = {
    "div", "span", "body", "html", "head", "title", "style", "script", "link", "meta",
    "p", "a", "img", "input", "button", "form", "table", "tr", "td", "th",
    "ul", "ol", "li", "nav", "header", "footer", "section", "article", "aside", "main",
    "h1", "h2", "h3", "h4", "h5", "h6", "figure", "video", "audio", "canvas", "svg",
    "select", "option", "textarea", "label", "iframe", "pre", "code", "blockquote",
    "function", "if", "else", "for", "while", "return", "class", "import", "var",
    "let", "const", "new", "media", "keyframes", "font-face", "supports", "root",
    "hover", "active", "focus", "before", "after", "not", "checked", "disabled",
}

# 非 flag body 黑名单模式：CSS「属性:值」（opacity:0.8 / font-size:1.5em / margin:0）与声明串（;）
_NON_FLAG_BODY_RES = [
    re.compile(r"^[a-zA-Z-]+\s*:\s*[0-9.]+%?(px|em|rem|vh|vw|s|deg)?;?$"),
    re.compile(r";"),
    re.compile(
        r"^[a-z-]+\s*:\s*(auto|none|block|inline|inline-block|hidden|visible|absolute|relative|"
        r"fixed|sticky|solid|dashed|bold|normal|center|left|right|both|cover|contain|inherit|"
        r"initial|unset|nowrap|wrap|flex|grid|pointer|default)$",
        re.IGNORECASE,
    ),
]

# 默认可信前缀（小写）：最普遍的 CTF flag 前缀，豁免「前缀学习收紧」
# （即使已确认前缀集合里没有它/与已知前缀不同，也始终放行；但仍受形态与黑名单约束）。
_TRUSTED_PREFIXES = {"flag"}


def _flag_shape_ok(s: str) -> bool:
    """基础形态：PREFIX{body} 字符集 + 非占位符。"""
    if not _FLAG_FULL_RE.fullmatch(s):
        return False
    return s.lower() not in _PLACEHOLDER_FLAGS


def _flag_prefix_blacklisted(prefix: str) -> bool:
    """前缀黑名单：HTML 标签 / CSS 选择器 / JS·CSS 关键字。"""
    return prefix in _NON_FLAG_PREFIXES


def _flag_body_blacklisted(s: str) -> bool:
    """body 黑名单：呈 CSS 声明模式（属性:值 / 含分号）。任何前缀都不豁免。"""
    body = s.split("{", 1)[1][:-1]
    return any(r.search(body) for r in _NON_FLAG_BODY_RES)


def known_flag_prefixes() -> set[str]:
    """从 flagstore 学习本平台已确认正确的 flag 前缀集合（小写，跨题全局）。

    无已确认记录时返回空集（冷启动，前缀学习不生效）。
    """
    try:
        with _FlagStore() as st:
            return {
                f.split("{", 1)[0].lower()
                for f in st.data.get("correct", {})
                if isinstance(f, str) and "{" in f
            }
    except Exception:
        return set()


def looks_flaglike_static(s: str) -> bool:
    """无 IO 静态判定（流解析热路径用）：形态 + 占位符 + 黑名单，不做前缀学习。"""
    s = (s or "").strip()
    if not _flag_shape_ok(s):
        return False
    prefix = s.split("{", 1)[0].lower()
    return not _flag_prefix_blacklisted(prefix) and not _flag_body_blacklisted(s)


def looks_flaglike(s: str) -> bool:
    """完整判定（提交路径用）：静态规则 + flagstore 前缀学习。

    判定顺序：
    1. body CSS 模式黑名单始终生效（任何前缀都不豁免——flag{display:none} 仍是垃圾）；
    2. 前缀命中已确认集合：豁免前缀黑名单与学习收紧（实证优先于规则）；
    3. 前缀黑名单（HTML/CSS/JS 关键字）拦截；
    4. 前缀学习收紧：已有确认前缀时，未知前缀一律不信任——
       但 _TRUSTED_PREFIXES（flag/FLAG）默认放行，不受此限。
    """
    s = (s or "").strip()
    if not _flag_shape_ok(s):
        return False
    if _flag_body_blacklisted(s):
        return False
    prefix = s.split("{", 1)[0].lower()
    known = known_flag_prefixes()
    if known and prefix in known:
        return True
    if _flag_prefix_blacklisted(prefix):
        return False
    if known and prefix not in _TRUSTED_PREFIXES:
        return False
    return True


class _FlagStore:
    """在 flock 保护下对 _flagstore.json 做读改写。"""

    def __init__(self):
        self.store_path, self.lock_path = _flagstore_paths()
        self._lf = None

    def __enter__(self):
        self._lf = open(self.lock_path, "a+")
        fcntl.flock(self._lf, fcntl.LOCK_EX)
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except Exception:
            self.data = {}
        self.data.setdefault("correct", {})
        self.data.setdefault("wrong", {})
        return self

    def save(self):
        tmp = self.store_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.store_path)
        except Exception:
            pass

    def __exit__(self, *exc):
        try:
            if self._lf is not None:
                fcntl.flock(self._lf, fcntl.LOCK_UN)
                self._lf.close()
        except Exception:
            pass


def _flagstore_precheck(code: str, flag: str) -> Optional[str]:
    """提交前查存储：返回非 None 表示应直接短路（不打平台），字符串即返回给调用方。"""
    f = _flag_norm(flag)
    if not f:
        return None
    try:
        with _FlagStore() as st:
            owner = st.data["correct"].get(f)
            if owner is not None and owner != code:
                _print_color(
                    f"[SUBMIT_FLAG][REJECTED] 该 flag 属于其他题目 {owner}，非本题 {code}，拒绝提交", "91;1")
                return (
                    f"chanllege_code:{code} 拒绝提交：该 flag 是其他题目（{owner}）已提交正确的 flag，"
                    f"不属于本题，请勿再提交此 flag，继续为本题寻找正确 flag。"
                )
            if owner == code:
                _print_color(f"[SUBMIT_FLAG][ALREADY SOLVED] 本题该 flag 已交过（本地记录）", "93;1")
                return f"chanllege_code:{code} 这题目已经提交成功过了"
            if f in (st.data["wrong"].get(code) or []):
                _print_color(f"[SUBMIT_FLAG][KNOWN WRONG] 本题已知错误 flag，跳过提交", "91;1")
                return f"chanllege_code:{code} 提交的 flag 错误（本题已知的错误 flag，请勿重复提交，换方向寻找）"
    except Exception:
        return None
    return None


def _flagstore_record_correct(code: str, flag: str) -> None:
    f = _flag_norm(flag)
    if not f:
        return
    try:
        with _FlagStore() as st:
            st.data["correct"][f] = code
            # 若曾被本题误记为错误，纠正
            wl = st.data["wrong"].get(code)
            if wl and f in wl:
                st.data["wrong"][code] = [x for x in wl if x != f]
            st.save()
    except Exception:
        pass


def _flagstore_record_wrong(code: str, flag: str) -> None:
    f = _flag_norm(flag)
    if not f:
        return
    try:
        with _FlagStore() as st:
            # 已被任何题交对的 flag 不记为错误
            if st.data["correct"].get(f):
                return
            wl = st.data["wrong"].setdefault(code, [])
            if f not in wl:
                wl.append(f)
            st.save()
    except Exception:
        pass


@tool("submit_flag", args_schema=SubmitFlagInput, return_direct=False)
def submit_flag(challenge_code: str, flag: str) -> str:
    """提供 challenge_code 和 flag，通过 tsec-benchmark SDK 提交当前 CTF 题目 Flag。
    返回提交结果或错误信息。
    """
    flag = (flag or "").strip()
    _print_color(f"[SUBMIT_FLAG] challenge_code={challenge_code} flag={flag}", "95;1")  # 亮洋红
    # 形态防线：CSS/代码片段等明显非 flag 文本直接拒绝，不打平台、不记 wrong 表
    if not looks_flaglike(flag):
        known = sorted(known_flag_prefixes())
        hint = f"本平台已确认的 flag 前缀为 {'/'.join(k + '{...}' for k in known)}；" if known else ""
        _print_color(f"[SUBMIT_FLAG][REJECTED] 形态可疑，未提交平台: {flag[:80]}", "91;1")
        return (
            f"chanllege_code:{challenge_code} 拒绝提交：该字符串形态可疑，疑似 CSS/代码片段而非真实 flag，"
            f"未提交平台。{hint}请确认它是题目环境（文件/响应/数据库等）中实际存在的完整 flag 后再提交。"
        )
    # 跨进程 flag 存储预检：别题已交对的 flag / 本题已知错误 flag 直接短路，不打平台
    pre = _flagstore_precheck(challenge_code, flag)
    if pre is not None:
        return pre
    try:
        client = get_benchmark_client()
    except Exception as e:
        _print_color(f"[SUBMIT_FLAG][ERROR] SDK 初始化失败: {e}", "91;1")
        return f"[ERROR] Benchmark SDK 初始化失败: {e}"

    base_delay = 0.5
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            res = client.submit_flag(challenge_code, flag)
            if not res.correct:
                _print_color("[SUBMIT_FLAG][INCORRECT] 提交的 flag 错误", "91;1")  # 亮红
                _flagstore_record_wrong(challenge_code, flag)  # 记入本题错误表
                return f"chanllege_code:{challenge_code} 提交的 flag 错误"
            _flagstore_record_correct(challenge_code, flag)  # 记入全局正确表（归属本题）
            _print_color(
                f"[SUBMIT_FLAG][OK] 提交正确，本次得分 {res.awarded}，累计 {res.cumulative_score}，"
                f"flag 进度 {res.correct_flag_count}/{res.total_flag_count}",
                "95;1",
            )
            base = (
                f"chanllege_code:{challenge_code} 提交flag正确,成功获取 {res.awarded} 分 "
                f"(累计 {res.cumulative_score} 分, flag 进度 {res.correct_flag_count}/{res.total_flag_count})"
            )
            try:
                remain = int(res.total_flag_count) - int(res.correct_flag_count)
            except Exception:
                remain = 0
            if remain > 0:
                base += (
                    f"。本题还有 {remain} 个 flag 未提交，请勿停止，继续挖掘其余 flag"
                    f"（多 flag 常在同一立足点下的不同位置/权限/接口）；全部 {res.total_flag_count} 个 flag 到手后再结束。"
                )
            return base
        except DuplicateSubmit:
            # 幂等：同一 flag 已正确提交过 —— 记入全局正确表（归属本题）
            _flagstore_record_correct(challenge_code, flag)
            _print_color("[SUBMIT_FLAG][ALREADY SOLVED] 该 flag 已提交成功过", "93;1")  # 亮黄
            return f"chanllege_code:{challenge_code} 这题目已经提交成功过了"
        except (TSecConnectionError, InternalError, ResourceUnavailable) as e:
            # 瞬时错误：指数退避 + 抖动重试
            if attempt < max_attempts - 1:
                sleep_seconds = min(8.0, base_delay * (2 ** attempt)) * (0.5 + random.random())
                try:
                    _print_color(f"[SUBMIT_FLAG] 第 {attempt + 1}/{max_attempts} 次提交失败（{e}），退避 {sleep_seconds:.2f}s 后重试…", "93;1")
                except Exception:
                    pass
                time.sleep(sleep_seconds)
                continue
            _print_color("[SUBMIT_FLAG][ERROR] 多次重试仍失败，放弃。", "91;1")
            return f"chanllege_code:{challenge_code} 提交失败，请稍后再试: {e}"
        except TSecError as e:
            # 平台业务错误（如题目不存在、状态非法）：不重试
            _print_color(f"[SUBMIT_FLAG][ERROR] 平台错误: {e}", "91;1")
            return f"[ERROR] 提交 flag 失败: {e}"
        except Exception as e:
            # 其他异常：记录并进行有限重试
            try:
                _print_color(f"[SUBMIT_FLAG][ERROR] 提交异常: {e}", "91;1")
            except Exception:
                pass
            if attempt < max_attempts - 1:
                sleep_seconds = min(8.0, base_delay * (2 ** attempt)) * (0.5 + random.random())
                time.sleep(sleep_seconds)
                continue
            return ""
    return ""

ALL_TOOLS.append(submit_flag)


class FindResourceInput(BaseModel):
    name_pattern: str = Field(..., description="要查找的资源名称或模式（支持部分匹配，不是正则）")
    search_paths: Optional[List[str]] = Field(
        None,
        description="可选的路径列表，会按顺序搜索；为空时使用默认常见位置与工作区根",
    )
    extensions: Optional[List[str]] = Field(None, description="可选的后缀列表（例如 ['.txt','.lst']）以缩小范围")
    max_results: int = Field(20, ge=1, description="最大返回结果数量，默认 20")


@tool("find_resource", args_schema=FindResourceInput, return_direct=False)
def find_resource(name_pattern: str, search_paths: Optional[List[str]] = None, extensions: Optional[List[str]] = None, max_results: int = 20) -> str:
    """查找本地文件资源（如密码字典、爆破字典等）。

    - name_pattern: 支持部分匹配（不使用正则），对文件名进行包含匹配（不含路径）
    - search_paths: 可选的路径列表（绝对或相对）；为空时会使用一些常见目录和当前工作区
    - extensions: 可选后缀过滤（小写匹配），例如 ['.txt', '.lst']
    - 返回 JSON 列表（字符串数组），按发现顺序，最多返回 max_results 条
    """
    # 简化实现：返回预定义资源映射中匹配的文件地址
    _print_green(f"[TOOL] find_resource pattern={name_pattern} (predefined lookup)")
    # 相对于本模块文件定位 resource 目录，避免部署路径变化导致漂移
    resource_dir = Path(__file__).resolve().parent.parent / "resource"
    resources = {
        # 你可以在这里添加或修改预定义资源映射
        "常用密码爆破字典": str(resource_dir / "password.txt"),
        "常用用户名爆破字典": str(resource_dir / "username.txt"),
        "XSS payload 字典": str(resource_dir / "xss.txt"),

    }

    pattern = name_pattern.lower()
    matches: List[str] = []
    for k, path in resources.items():
        if pattern in k.lower() or pattern in str(path).lower():
            matches.append(path)
            if len(matches) >= max_results:
                break

    # 如果没有匹配，返回空列表（JSON 格式）
    try:
        return json.dumps(matches, ensure_ascii=False)
    except Exception:
        return str(matches)


# 注册 find_resource
ALL_TOOLS.append(find_resource)

class DirsearchScanInput(BaseModel):
    url: str = Field(..., description="目标地址，例如 http://127.0.0.1:8080 或 http://host:port")


@tool("dirsearch_scan", args_schema=DirsearchScanInput, return_direct=False)
def dirsearch_scan(url: str) -> str:
    """对单个 URL 执行一次性目录扫描（带缓存）。

    - 同一 URL（规范化后）仅会执行一次扫描；后续调用直接返回缓存结果
    - 默认参数：-i 200,301,302 --format=plain
    - 报告输出在会话工作空间（CRUISER_WORKSPACE_DIR）下，同时会写入共享缓存目录 /tmp/cruiser_dirsearch_cache 下
    - 返回值：报告纯文本内容；若工具未生成报告，将创建占位报告文件并返回“未发现有效结果或报告未生成”
    """
    _print_green(f"[TOOL] dirsearch_scan {url}")
    try:
        url_norm = (url or "").strip().rstrip("/")
        if not url_norm.lower().startswith(("http://", "https://")):
            return "[ERROR] 非法 URL（需以 http:// 或 https:// 开头）"
        key = hashlib.sha256(url_norm.encode("utf-8")).hexdigest()[:16]
        cache_root = Path("/tmp/cruiser_dirsearch_cache").resolve()
        cache_dir = cache_root / key
        report_cache = cache_dir / "report.txt"
        lock_path = cache_dir / "lock"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # 命中缓存
        if report_cache.exists():
            try:
                return report_cache.read_text("utf-8", errors="replace")
            except Exception as e:
                return f"[ERROR] 读取缓存失败: {e}"

        # 争抢锁：独占执行一次扫描
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("utf-8", errors="ignore"))
            os.close(fd)
            fd = None
            # 准备工作空间与输出文件
            ws = os.environ.get("CRUISER_WORKSPACE_DIR")
            if not ws:
                base_ws = "/tmp/cruiser_workspaces"
                os.makedirs(base_ws, exist_ok=True)
                ws = os.path.join(base_ws, f"ws_dirsearch_{key}")
                os.makedirs(ws, exist_ok=True)
            out_file = os.path.join(ws, f"dirsearch_{key}.txt")
            # 运行 dirsearch（写入纯文本报告避免进度条）
            cmd = [
                "dirsearch",
                "-u",
                url_norm,
                "-i",
                "200,301,302",
                "--format=plain",
                "-o",
                out_file,
            ]
            p = subprocess.run(cmd, capture_output=True, text=True)
            # 优先读取报告文件；若未生成则在期望位置创建“空报告”
            if os.path.exists(out_file):
                try:
                    content = Path(out_file).read_text("utf-8", errors="replace")
                except Exception:
                    content = ""
                try:
                    report_cache.write_text(content, encoding="utf-8")
                except Exception:
                    pass
                return content
            else:
                # 不回退 stdout/stderr；直接生成一个明确的“未发现结果”报告文件
                content = "本次扫描未发现有效结果\n"
                try:
                    Path(out_file).write_text(content, encoding="utf-8")
                except Exception:
                    pass
                try:
                    report_cache.write_text(content, encoding="utf-8")
                except Exception:
                    pass
                return content
        except FileExistsError:
            # 其他进程正在扫描：等待缓存出结果
            for _ in range(600):  # 最多等 5 分钟
                if report_cache.exists():
                    try:
                        return report_cache.read_text("utf-8", errors="replace")
                    except Exception as e:
                        return f"[ERROR] 读取缓存失败: {e}"
                time.sleep(0.5)
            return "[ERROR] 等待 dirsearch 扫描结果超时"
        finally:
            try:
                if lock_path.exists():
                    # 仅在报告落盘后由持锁方删除；若走到这里无报告也清锁，避免死锁
                    if report_cache.exists():
                        os.unlink(lock_path)
            except Exception:
                pass
    except Exception as e:
        return f"[ERROR] dirsearch 执行异常: {e}"

# 注册 dirsearch_scan
ALL_TOOLS.append(dirsearch_scan)



class FuzzXssInput(BaseModel):
    url: str = Field(..., description="目标 URL，例如 http://127.0.0.1:8080/page")
    get_params: Optional[Union[str, List[str]]] = Field(
        None,
        description="GET 参数名或参数名列表，payload 将自动填充到这些参数中",
    )
    post_params: Optional[Union[str, List[str]]] = Field(
        None,
        description="POST 参数名或参数名列表，若为空则仅发送 GET 请求",
    )
    prefix: str = Field("", description="为每个 payload 添加的前缀字符串")
    thread_count: int = Field(20, ge=1, description="并发线程数，默认为 20")
    timeout: float = Field(10, gt=0, description="单次请求超时时间（秒），默认为 10")
    flag_pattern: str = Field(
        r"flag\{.*?\}",
        description="用于匹配 flag 的正则表达式，默认为 flag{...}",
    )
    payload_file: Optional[str] = Field(
        None,
        description="payload 字典文件路径，默认为项目根目录的 xss.txt",
    )
    show_progress: bool = Field(
        False, description="是否输出进度信息（默认关闭）"
    )
    progress_interval: int = Field(
        500, ge=1, description="进度输出间隔（请求次数），默认为 500"
    )


def _load_fuzz_xss_payloads(path: Optional[str]) -> List[str]:
    default_path = Path(__file__).resolve().parent.parent / "resource" / "xss.txt"
    payload_path = Path(path).expanduser() if path else default_path
    if not payload_path.exists():
        raise FileNotFoundError(f"payload 文件不存在: {payload_path}")
    payloads: List[str] = []
    with payload_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            text = line.strip()
            if not text or text.startswith("<!--"):
                continue
            payloads.append(text)
    if not payloads:
        raise ValueError("未在 payload 文件中找到有效 payload")
    return payloads


def _normalize_param_names(
    names: Optional[Union[str, List[str]]]
) -> Optional[List[str]]:
    if names is None:
        return None
    if isinstance(names, str):
        return [names]
    try:
        return [str(item) for item in names]
    except Exception:
        return [str(names)]


def _render_fuzz_progress(count: int, total: int) -> str:
    if total <= 0:
        return "进度: 0/0 (0.0%)"
    percent = count / total * 100
    return f"进度: {count}/{total} ({percent:5.1f}%)"


@tool("fuzz_xss", args_schema=FuzzXssInput, return_direct=False)
def fuzz_xss_tool(
    url: str,
    get_params: Optional[Union[str, List[str]]] = None,
    post_params: Optional[Union[str, List[str]]] = None,
    prefix: str = "",
    thread_count: int = 20,
    timeout: float = 10.0,
    flag_pattern: str = r"flag\{.*?\}",
    payload_file: Optional[str] = None,
    show_progress: bool = False,
    progress_interval: int = 500,
) -> str:
    """使用 payload 字典对目标执行并发 XSS 测试，命中 flag 时返回 flag 与 payload。"""
    _print_green("[TOOL] fuzz_xss")
    try:
        payloads = _load_fuzz_xss_payloads(payload_file)
    except Exception as exc:
        return f"[ERROR] payload 加载失败: {exc}"

    total = len(payloads)
    get_param_names = _normalize_param_names(get_params)
    post_param_names = _normalize_param_names(post_params)
    method = "POST" if post_param_names else "GET"
    flag_regex = re.compile(flag_pattern, re.IGNORECASE)

    payload_path = str(
        (Path(payload_file).expanduser() if payload_file else Path(__file__).resolve().parent.parent / "resource" / "xss.txt").resolve()
    )
    cache_input = {
        "url": url,
        "get": sorted(get_param_names or []),
        "post": sorted(post_param_names or []),
        "prefix": prefix,
        "payload_file": payload_path,
    }
    try:
        cache_key = hashlib.sha256(
            json.dumps(cache_input, sort_keys=True, ensure_ascii=False).encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
    except Exception as exc:
        return f"[ERROR] 构建缓存键失败: {exc}"

    cache_root = Path("/tmp/cruiser_fuzz_xss_cache").resolve()
    cache_dir = cache_root / cache_key
    cache_result = cache_dir / "result.txt"
    lock_path = cache_dir / "lock"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if cache_result.exists():
        try:
            cached = cache_result.read_text("utf-8", errors="replace")
            return cached.splitlines()[0] if cached else "未成功获取 flag"
        except Exception as exc:
            return f"[ERROR] 读取缓存失败: {exc}"

    locked = False
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode("utf-8", errors="ignore"))
        os.close(fd)
        fd = None
        locked = True

        success_event = threading.Event()
        success_value = {"result": ""}
        processed = 0
        interval = progress_interval if progress_interval > 0 else 1
        quiet_mode = os.environ.get("CRUISER_QUIET") == "1"

        if show_progress and not quiet_mode:
            print(f"共 {total} 个 payload，开始测试...", flush=True)

        def worker(payload: str) -> None:
            if success_event.is_set():
                return
            full_payload = f"{prefix}{payload}"
            params = {name: full_payload for name in get_param_names} if get_param_names else None
            post_data = {name: full_payload for name in post_param_names} if post_param_names else None
            try:
                if method == "POST":
                    resp = requests.post(url, params=params, data=post_data, timeout=timeout)
                else:
                    resp = requests.get(url, params=params, timeout=timeout)
                text = resp.text or ""
                match = flag_regex.search(text)
                if match and not success_event.is_set():
                    success_event.set()
                    success_value["result"] = f"{match.group(0)} {full_payload}"
            except Exception:
                pass

        executor = ThreadPoolExecutor(max_workers=max(1, thread_count))
        try:
            futures = {executor.submit(worker, payload): payload for payload in payloads}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
                processed += 1
                if show_progress and not quiet_mode and (
                    processed == total or processed % interval == 0
                ):
                    print(_render_fuzz_progress(processed, total), flush=True)
                if success_event.is_set():
                    break
        except KeyboardInterrupt:
            success_event.set()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if show_progress and not quiet_mode and processed % interval != 0 and processed != total:
            print(_render_fuzz_progress(processed, total), flush=True)

        result_text = success_value["result"] or "未成功获取 flag"
        try:
            cache_result.write_text(result_text, encoding="utf-8")
        except Exception:
            pass
        return result_text
    except FileExistsError:
        for _ in range(600):
            if cache_result.exists():
                try:
                    cached = cache_result.read_text("utf-8", errors="replace")
                    return cached.splitlines()[0] if cached else "未成功获取 flag"
                except Exception as exc:
                    return f"[ERROR] 读取缓存失败: {exc}"
            time.sleep(0.5)
        return "[ERROR] 等待 fuzz_xss 缓存结果超时"
    finally:
        if locked:
            try:
                if lock_path.exists():
                    os.unlink(lock_path)
            except Exception:
                pass


ALL_TOOLS.append(fuzz_xss_tool)
