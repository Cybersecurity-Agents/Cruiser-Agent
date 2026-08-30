"""Claude Code 驱动的自动扫描引擎（替代手写 ReAct 循环）。

通过 claude CLI 的 stream-json 模式运行自主 Agent：
- 每个 assistant 事件计为一步并打印 [COUNT] n（供 main.py 调度器做步数阈值监控，语义不变）
- 共享关键信息黑板机制不变：reports/info_<code>.txt 与 hint_<code>.txt 的
  文件、格式、读写时机均由提示词约定，Claude Code 用自身文件工具直接读写
- flag 必须经 tools/submit_flag.py（tsec-benchmark SDK）确认后，才输出最终 JSON
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage

from .llm import get_claude_provider_env, get_watcher_llm
from .prompt import (
    CLAUDE_SOLVER_SYSTEM_PROMPT,
    CLAUDE_SOLVER_TASK_TEMPLATE,
    CLAUDE_SYSTEM_PROMPT,
    CLAUDE_TASK_TEMPLATE,
)

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except Exception:
        return default


# Watcher 可见窗口（默认覆盖约 20～24 个回合；可用环境变量再加大）
_WATCHER_RECENT_MAX = max(12, _env_int("CRUISER_WATCHER_RECENT", 48))
_WATCHER_EVERY = max(1, _env_int("CRUISER_WATCHER_EVERY", 4))
_WATCHER_THOUGHT_CHARS = max(200, _env_int("CRUISER_WATCHER_THOUGHT_CHARS", 800))
_WATCHER_OBS_CHARS = max(400, _env_int("CRUISER_WATCHER_OBS_CHARS", 1600))
_WATCHER_ACTIVITY_CHARS = max(4000, _env_int("CRUISER_WATCHER_ACTIVITY_CHARS", 24000))
_WATCHER_BB_CHARS = max(4000, _env_int("CRUISER_WATCHER_BB_CHARS", 12000))
_WATCHER_TASKS_CHARS = 3000
_WATCHER_CLAIMED_CHARS = 2500
_WATCHER_DESC_CHARS = 2500
_WATCHER_HINT_CHARS = 2500
_WATCHER_FULL_ITEMS = 12  # 活动摘要里最近这么多条保留全文，更早的压成短句以腾出历史窗口


# 每个 Claude 会话的最大轮数（claude 的「回合(turn)」数，经 --max-turns 传入；注意 turn ≠ 日志 [COUNT]，
# [COUNT] 数每个 assistant 事件、约为 turn 数的数倍）：<=0 表示不限制（不向 claude 传 --max-turns），
# 由调度器的步数阈值 / flag 确认 / 上下文上限自然收敛。可用 CRUISER_MAX_TURNS 覆盖（默认 0 = 不限制）。
def _max_turns_per_session() -> int:
    try:
        return int(os.environ.get("CRUISER_MAX_TURNS", "0") or "0")
    except Exception:
        return 0


# 提交 flag 成功的外部确认标记（与 tools.submit_flag 输出保持一致）
_FLAG_OK_MARKERS = ("提交flag正确", "已经提交成功过了")
# 只认「调用」submit_flag.py CODE FLAG，不认路径里碰巧出现这个文件名（如 grep .../submit_flag.py）
_SUBMIT_INVOKE_RE = re.compile(
    r"""(?:^|[\s;|&])(?:\S*/)?submit_flag\.py\s+([A-Za-z0-9]+-\d+)\s+(?:'([^']+)'|"([^"]+)"|([^\s'"|;&><`]+))"""
)
# flag{...} 形态候选提取
# 只抠「像真 flag 的外壳+内容」：拒绝源码里 startswith('flag{') 扫到下一个 } 的片段
_FLAG_PATTERN_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}")


# 同一段文本里超过这个数量的 flag{...} 视为爆破/枚举输出，禁止自动提交。
# 略大于 2：多 flag 题一次 cat 出 3～5 枚是常见情况，不应整段跳过。
_AUTO_SUBMIT_MAX_PER_BLOB = 5
_PROGRESS_RE = re.compile(r"flag 进度\s*(\d+)/(\d+)")


def _unique_flag_cands(text: str) -> list[str]:
    """从一段文本提取去重后的合法 flag 候选，保持出现顺序。"""
    out: list[str] = []
    seen: set[str] = set()
    for m in _FLAG_PATTERN_RE.findall(text or ""):
        if not _looks_like_flag(m) or m in seen:
            continue
        seen.add(m)
        out.append(m)
    return out


def _looks_like_flag(s: str) -> bool:
    """热路径静态判定（委托 tools.looks_flaglike_static，无 IO）：
    形态 + 占位符 + HTML/CSS/JS 黑名单。提交判定请用 tools.looks_flaglike（含前缀学习）。"""
    from .tools import looks_flaglike_static
    return looks_flaglike_static(s)


def _submit_flag_directly(code: str, flag: str):
    """程序化提交一个 flag，返回 FlagSubmitOutcome。

    仅自动提交走这里；字符集限制也只加在这一层，不拦模型自己调 submit_flag.py。
    """
    from .tools import FlagSubmitOutcome, looks_flaglike, submit_flag_outcome
    if not code or not flag or not looks_flaglike(flag):
        return FlagSubmitOutcome()
    try:
        return submit_flag_outcome(code, flag)
    except Exception:
        return FlagSubmitOutcome(definitive=False)


def _flags_all_collected(correct: int, total: int) -> bool:
    from .tools import flags_all_collected
    return flags_all_collected(correct, total)


def _progress_from_text(text: str) -> tuple[int, int]:
    m = _PROGRESS_RE.search(text or "")
    if not m:
        return 0, 0
    try:
        return int(m.group(1)), int(m.group(2))
    except Exception:
        return 0, 0


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# 黑板 watcher：每个 worker 进程内周期性由 LLM 审阅最近活动与当前黑板，
# 发现值得共享的新信息则按既定格式追加（机制保障，不依赖 Claude 自觉）。
# ---------------------------------------------------------------------------
_WATCHER_SYSTEM = (
    "你是 CTF 解题会话的黑板观察员。你的职责：审阅某会话最近的操作摘要，维护共享黑板的质量"
    "（提取新关键信息、修正不准确或不完整的条目、删除已被证伪的条目），"
    "并基于当前已知信息为所有会话推荐值得探索的方向。"
    "黑板只记录「什么可行 / 发现了什么」的正向、可复用信息；"
    "绝不记录「什么不可行 / 尝试失败」的负向结论，以免误导其他会话过早放弃可行方向。"
    "绝不把具体 flag 值写入黑板（存在兜底自动提交，错误 flag 会被反复提交）。"
    "不要新增、修改或删除 [flag方法] 条目——那是首次提交成功时由提交会话单独写入的。"
    "只输出 JSON，不要输出任何其他内容。"
)

_WATCHER_PROMPT_TEMPLATE = (
    "【当前共享黑板条目】\n{blackboard}\n\n"
    "【当前待认领的探索方向】\n{tasks}\n"
    "【正在执行中的方向（已被其他会话认领）】\n{claimed_tasks}\n\n"
    "【该会话最近的活动摘要】\n{activity}\n\n"
    "请维护黑板质量并推荐探索方向，规则：\n"
    "1. add：只提取「确认有效 / 已证实存在」的正向关键信息（可用的默认口令/凭据、确实存在的路径或 API 端点、"
    "配置文件位置、已确认成立的漏洞点、验证可行的利用或绕过方式等）；\n"
    "   【严禁写具体 flag 值】绝不要把 flag 内容本身（flag{{...}}、FLAG{{...}}、SEKAI{{...}}、HTB{{...}} 等任何疑似 flag 串）"
    "写入黑板——存在兜底提交机制会自动抓取黑板里的 flag 反复提交，写错的 flag 会导致无休止地重复错误提交。\n"
    "   【不要动 [flag方法]】首次提交成功时会单独写入获取方法，你不要 add / update / remove 这类条目；\n"
    "   普通条目不超过 80 字；一次最多 3 条；\n"
    "   重要：不要记录负向/排除性结论或失败尝试——例如「xx payload 无效」「基础注入失败」「爆破未成功」"
    "「该路径不存在/404」「xx 被过滤」等一切「什么不行」的内容一律不写，"
    "因为它们可能误导其他会话过早放弃本可行的方向；只有当某个过滤/限制已连同「确认可行的绕过」一起给出时，"
    "才作为正向信息记录（重点写可行的绕过，而非限制本身）；\n"
    "   黑板上已存在的条目（含大小写差异、尾部斜杠等变体）不要重复；\n"
    "2. update：若某条目被最近活动证实不准确或不完整（如口令错误、路径笔误、结论过时），"
    "old 填该条目现有内容的关键片段，new 填修正后的完整内容；\n"
    "3. remove：若某条目被证实完全错误、没有价值，或属于上述「什么不行」的负向/失败结论"
    "（可能误导其他会话），填该条目内容的关键片段予以删除；"
    "特别地：黑板中任何含具体 flag 值（flag{{...}}/FLAG{{...}}/SEKAI{{...}}/HTB{{...}} 等疑似 flag 串）的条目，"
    "无论对错一律删除（防止兜底机制反复提交），如需保留请只留「怎么拿到的」而非 flag 值本身；\n"
    "4. 服务器指纹、版本号等基础信息不要收录（除非是与特定漏洞相关的版本）；\n"
    "   题目入口/服务地址不要写死具体 IP:端口（如 http://<IP>:<端口>/probe）——靶场容器每次重启 IP 会变，"
    "且同题不同队列共用同一黑板，写死的旧 IP 会误导其他会话。记录端点时只写相对路径或逻辑名"
    "（如「SSRF 端点 POST /probe」「入口应用为 Smart Logistics 看板」），具体地址由各会话用当前注入的 target；\n"
    "5. suggest_tasks：基于黑板已知信息与最近活动，推荐接下来值得探索的方向"
    "（方向级、可执行、一句话，例如「测试 /upload 的文件上传绕过」「用已发现口令尝试后台登录」）；"
    "已在待认领或执行中列表里的方向不要重复；没有好建议就留空；一次最多 2 条；"
    "若题目提示给出了有序步骤，只发布能映射到某一步的方向，映射不上的（尤其扫 /24、枚举 Host、爆破 operator、调 OCR 等提示未点名的支线）一律不发布；\n"
    "6. retire_tasks：若待认领方向列表中有明显重复（语义相同仅措辞不同）、已被黑板事实覆盖"
    "（如早已完成）或已过时无价值的方向，填其任务 id（t-xxxxxx）予以移除，保持任务板精炼；"
    "题目提示已点名利用原语/路径时，主动下架『爆破 admin/operator、扫同段 /24、枚举 Host、调 OCR』等偏离提示的方向；\n"
    "7. 没有任何变化时，各字段都返回空列表。\n"
    '严格输出 JSON：{{"add": ["..."], "update": [{{"old": "...", "new": "..."}}], '
    '"remove": ["..."], "suggest_tasks": ["..."], "retire_tasks": ["t-xxxxxx"]}}'
)

_WATCHER_LLM = None
_WATCHER_LLM_LOCK = threading.Lock()


def _get_watcher_llm():
    """watcher 专用 LLM 单例（使用 DeepSeek deepseek-v4-pro，可经 WATCHER_MODEL 覆盖）。"""
    global _WATCHER_LLM
    if _WATCHER_LLM is None:
        with _WATCHER_LLM_LOCK:
            if _WATCHER_LLM is None:
                llm, provider, _ = get_watcher_llm()
                _WATCHER_LLM = llm
                try:
                    print(f"[Watcher] 后端模型: {provider}", flush=True)
                except Exception:
                    pass
    return _WATCHER_LLM


def _parse_blackboard(content: str) -> list[dict]:
    """解析黑板文件为条目列表：[{"header": 头部行, "info": 关键信息文本}]。"""
    sep = "-" * 60
    entries: list[dict] = []
    for part in content.split(sep):
        part = part.strip()
        if not part:
            continue
        lines = part.splitlines()
        header = lines[0] if lines else ""
        info = ""
        for line in lines:
            if "关键信息:" in line:
                info = line.split("关键信息:", 1)[-1].strip()
                break
        entries.append({"header": header, "info": info})
    return entries


def _normalize_info(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower().strip()).rstrip("/")


def _find_best_match(entries: list[dict], target: str) -> Optional[int]:
    """在条目里找与 target 内容最匹配的索引（包含关系或词面相似度 >= 0.6），找不到返回 None。"""
    t = _normalize_info(target)
    if not t:
        return None
    best_idx: Optional[int] = None
    best_score = 0.0
    for i, e in enumerate(entries):
        s = _normalize_info(e.get("info", ""))
        if not s:
            continue
        if t == s:
            return i
        if t in s or s in t:
            score = 0.85
        else:
            tw, sw = set(t.split()), set(s.split())
            if not tw or not sw:
                continue
            score = len(tw & sw) / min(len(tw), len(sw))
        if score > best_score:
            best_idx, best_score = i, score
    return best_idx if best_score >= 0.6 else None


def _strip_flag_literals(text: str) -> str:
    """去掉具体 flag 串，避免写入黑板后被兜底提交反复打平台。"""
    return _FLAG_PATTERN_RE.sub("<flag>", text or "")


def _format_watcher_activity(recent: deque[str] | list[str], budget: int = _WATCHER_ACTIVITY_CHARS) -> str:
    """拼 watcher 活动窗口：最近若干条全文，更早的压短（头尾各留一段），整体不超过 budget。"""
    items = [x for x in recent if x]
    if not items:
        return ""

    def _compress(x: str, n: int = 240) -> str:
        s = re.sub(r"\s+", " ", x).strip()
        if len(s) <= n:
            return s
        head = n // 2 - 2
        return s[:head] + "..." + s[-(n - head - 3):]

    keep = min(_WATCHER_FULL_ITEMS, len(items))
    if len(items) > keep:
        text = "\n".join([_compress(x) for x in items[:-keep]] + items[-keep:])
    else:
        text = "\n".join(items)
    return text[-budget:] if len(text) > budget else text


def _is_flag_method(info: str) -> bool:
    return (info or "").lstrip().startswith("[flag方法]")


def _flag_method_key(info: str) -> str:
    """同一枚 flag 的方法条目键（'1'、'2'…）。识别不了则空串。"""
    text = info or ""
    m = re.search(r"进度\s*(\d+)\s*/\s*\d+", text)
    if m:
        return m.group(1)
    m = re.search(r"(?:flag|FLAG)\s*(\d+)", text)
    if m:
        return m.group(1)
    m = re.search(r"第\s*(\d+)\s*[枚个份]", text)
    if m:
        return m.group(1)
    return ""


def _flag_method_dbg(msg: str) -> None:
    try:
        print(f"\x1b[96;1m[flag方法DEBUG]\x1b[0m {msg}", flush=True)
    except Exception:
        pass


def _write_blackboard_entries(info_path: str, entries: list[dict]) -> None:
    sep = "-" * 60
    tmp_path = info_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(f"{e['header']}\n")
            f.write(f"关键信息: {e['info']}\n")
            f.write(sep + "\n")
    os.replace(tmp_path, info_path)


def _append_blackboard_info(code: str, worker_id: str, info: str) -> bool:
    """向共享黑板追加一条（文件锁 + 模糊去重）。成功写入返回 True。"""
    info = (info or "").strip()
    if not code or not info:
        _flag_method_dbg(f"append 拒绝: code={code!r} info_empty={not info} worker={worker_id}")
        return False
    import fcntl

    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    info_path = os.path.join(reports_dir, f"info_{code}.txt")
    lock_path = info_path + ".lock"
    _flag_method_dbg(
        f"append 开始 worker={worker_id} cwd={os.getcwd()!r} path={info_path} "
        f"uid={os.geteuid()} writable_dir={os.access(reports_dir, os.W_OK)} "
        f"info_len={len(info)} preview={info[:120]!r}"
    )
    try:
        with open(lock_path, "w", encoding="utf-8") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                try:
                    with open(info_path, "r", encoding="utf-8") as f:
                        current = f.read()
                except FileNotFoundError:
                    current = ""
                except Exception as e:
                    _flag_method_dbg(f"append 读黑板失败 path={info_path} err={type(e).__name__}: {e}")
                    current = ""
                entries = _parse_blackboard(current)
                matched = _find_best_match(entries, info)
                if matched is not None:
                    old = (entries[matched].get("info") or "")[:120]
                    _flag_method_dbg(f"append 跳过: 模糊匹配已有条目 idx={matched} old={old!r}")
                    return False
                if _is_flag_method(info):
                    key = _flag_method_key(info)
                    if key and any(
                        _is_flag_method(e.get("info") or "")
                        and _flag_method_key(e.get("info") or "") == key
                        for e in entries
                    ):
                        _flag_method_dbg(f"append 跳过: 同进度键已有 [flag方法] key={key}")
                        return False
                entries.append({
                    "header": f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 会话: {worker_id}",
                    "info": info,
                })
                _write_blackboard_entries(info_path, entries)
                _flag_method_dbg(f"append 成功 path={info_path} bytes={os.path.getsize(info_path)}")
                return True
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
    except Exception as e:
        _flag_method_dbg(
            f"append 异常 path={info_path} err={type(e).__name__}: {e} "
            f"cwd={os.getcwd()!r} euid={os.geteuid()}"
        )
        return False


_FLAG_METHOD_WRITER_PROMPT = (
    "根据下面会话刚拿到 flag 时的活动摘要，写一条可让其他会话复现的获取方法。\n"
    "进度：{prog}\n"
    "只输出一行，不要 markdown，不要具体 flag 值：\n"
    "[flag方法] 进度 {prog}。漏洞点 + 请求/路径/命令 + 关键步骤（不超过 200 字）\n\n"
    "活动摘要：\n{activity}\n"
)

_FLAG_METHOD_SPAWNED: "set[str]" = set()
_FLAG_METHOD_SPAWNED_LOCK = threading.Lock()


def _compose_flag_method(prog: str, activity: str) -> str:
    """一次性把活动摘要收成一条完整 [flag方法]；LLM 不可用时退回压缩摘要。"""
    activity = _strip_flag_literals(activity or "")
    llm = _get_watcher_llm()
    _flag_method_dbg(
        f"compose 开始 prog={prog} llm={'yes' if llm is not None else 'None'} "
        f"activity_len={len(activity)}"
    )
    if llm is not None and activity.strip():
        try:
            prompt = (
                _FLAG_METHOD_WRITER_PROMPT
                .replace("{prog}", prog)
                .replace("{activity}", activity[-_WATCHER_ACTIVITY_CHARS:])
            )
            _flag_method_dbg(f"compose 调用 LLM prompt_len={len(prompt)}")
            resp = llm.invoke([
                SystemMessage(content="只输出一行 [flag方法]，不要 flag 值，不要其他内容。"),
                HumanMessage(content=prompt),
            ])
            text = resp.content if isinstance(resp.content, str) else ""
            _flag_method_dbg(f"compose LLM 返回 type={type(resp.content).__name__} len={len(text or '')} head={(text or '')[:160]!r}")
            line = ""
            for raw in (text or "").splitlines():
                if "[flag方法]" in raw:
                    line = raw.strip()
                    break
            if not line and (text or "").strip():
                line = text.strip().splitlines()[0].strip()
            line = _strip_flag_literals(line)
            if line:
                if not _is_flag_method(line):
                    line = f"[flag方法] 进度 {prog}。{line}"
                _flag_method_dbg(f"compose LLM 成稿 len={len(line[:400])}")
                return line[:400]
            _flag_method_dbg("compose LLM 输出无法解析，改走摘要回退")
        except Exception as e:
            _flag_method_dbg(f"compose LLM 异常 {type(e).__name__}: {e}")
    snippet = re.sub(r"\s+", " ", activity).strip()[:800]
    if not snippet:
        _flag_method_dbg("compose 失败: 活动摘要为空且无 LLM 成稿")
        return ""
    _flag_method_dbg(f"compose 回退摘要 len={len(snippet)}")
    return f"[flag方法] 进度 {prog}。{snippet}"


def _write_flag_method_once(code: str, worker_id: str, prog: str, activity: str) -> None:
    """分叉任务：写完一条 [flag方法] 即退出。"""
    _flag_method_dbg(f"writer 线程启动 worker={worker_id} prog={prog} activity_len={len(activity or '')} ident={threading.current_thread().name}")
    try:
        info = _compose_flag_method(prog, activity)
        if not info:
            _flag_method_dbg(f"writer 退出: compose 空稿 worker={worker_id} prog={prog}")
            return
        ok = _append_blackboard_info(code, worker_id, info)
        _flag_method_dbg(f"writer append 结果 ok={ok} worker={worker_id} prog={prog}")
        if ok:
            print(f"[flag方法] 会话 {worker_id} 已写入（进度 {prog}）", flush=True)
    except Exception as e:
        _flag_method_dbg(f"writer 异常 worker={worker_id} prog={prog} {type(e).__name__}: {e}")


def _spawn_flag_method_writer(
    code: str, worker_id: str, correct: int, total: int, recent_items: list[str]
) -> Optional[threading.Thread]:
    """首次提交成功：快照活动后丢到一次性线程，写完即弃。重复提交不会进来。"""
    if not code:
        _flag_method_dbg(f"spawn 拒绝: 无 challenge code worker={worker_id}")
        return None
    prog = f"{correct}/{total}" if int(total or 0) >= 1 else (str(correct) if int(correct or 0) >= 1 else "?")
    key = f"{code}|{int(correct or 0)}|{int(total or 0)}"
    with _FLAG_METHOD_SPAWNED_LOCK:
        if key in _FLAG_METHOD_SPAWNED:
            _flag_method_dbg(f"spawn 跳过: 本进程已分叉过 key={key} worker={worker_id}")
            return None
        _FLAG_METHOD_SPAWNED.add(key)
    activity = _format_watcher_activity(recent_items)
    _flag_method_dbg(
        f"spawn 启动线程 worker={worker_id} key={key} prog={prog} "
        f"recent_n={len(recent_items)} activity_len={len(activity)}"
    )
    t = threading.Thread(
        target=_write_flag_method_once,
        args=(code, worker_id, prog, activity),
        daemon=True,
        name=f"flag-method-{worker_id}-{prog}",
    )
    t.start()
    _flag_method_dbg(f"spawn 线程已 start alive={t.is_alive()} name={t.name}")
    return t


# 进程级已尝试提交的 flag 去重（避免 watcher 每次触发都重复提交同一 flag）
_ATTEMPTED_FLAGS: "set[str]" = set()
_ATTEMPTED_FLAGS_LOCK = threading.Lock()


def _watcher_try_submit_flags(code: str, worker_id: str, *texts: str) -> Optional[str]:
    """watcher 兜底提交：从给定文本中提取 flag{...} 候选，进程内去重后程序化提交。

    会交完本批所有候选（不因第一枚正确就返回），仅当平台进度已齐才打印最终 JSON。
    可用 CRUISER_WATCHER_SUBMIT=0 关闭。
    """
    if os.environ.get("CRUISER_WATCHER_SUBMIT", "1") != "1" or not code:
        return None
    cands: "set[str]" = set()
    for t in texts:
        blob = _unique_flag_cands(t)
        # 一段里出现一堆 flag 是爆破输出，不自动交
        if len(blob) > _AUTO_SUBMIT_MAX_PER_BLOB:
            continue
        cands.update(blob)
    last_js: Optional[str] = None
    for cand in sorted(cands, key=len, reverse=True):
        key = f"{code}|{cand}"
        with _ATTEMPTED_FLAGS_LOCK:
            if key in _ATTEMPTED_FLAGS:
                continue
        outcome = _submit_flag_directly(code, cand)
        if outcome.definitive:
            with _ATTEMPTED_FLAGS_LOCK:
                _ATTEMPTED_FLAGS.add(key)
        if not outcome.ok:
            continue
        js = json.dumps({"flag": cand}, ensure_ascii=False)
        try:
            prog = f"{outcome.correct}/{outcome.total}" if outcome.total >= 1 else "?"
            print(
                f"\x1b[95;1m[WATCHER SUBMIT] 会话 {worker_id} 补交成功 ({prog}): {cand}\x1b[0m",
                flush=True,
            )
        except Exception:
            pass
        if _flags_all_collected(outcome.correct, outcome.total):
            last_js = js
            try:
                print(js, flush=True)
            except Exception:
                pass
            return last_js
    return last_js


def _watcher_curate_blackboard(code: str, worker_id: str, activity: str) -> None:
    """LLM 审阅最近活动与当前黑板，维护黑板质量：新增/修正/删除条目。

    并发安全：LLM 审阅基于无锁快照；应用变更时持文件锁重读最新内容，
    按内容模糊匹配定位条目（不用行号，避免并发漂移），临时文件 + os.replace 原子重写。
    附带：从最近活动 + 黑板里提取 flag 候选并程序化兜底提交（watcher 也能交 flag）。
    """
    if not code or not activity.strip():
        return
    try:
        reports_dir = os.path.join(os.getcwd(), "reports")
        info_path = os.path.join(reports_dir, f"info_{code}.txt")
        lock_path = info_path + ".lock"
        try:
            with open(info_path, "r", encoding="utf-8") as f:
                blackboard = f.read()
        except Exception:
            blackboard = ""
        # watcher 兜底提交：先于策展执行，即便无可用 watcher LLM 也能补交
        _watcher_try_submit_flags(code, worker_id, activity, blackboard)
        llm = _get_watcher_llm()
        if llm is None:
            return
        entries_snapshot = _parse_blackboard(blackboard)
        numbered = "\n".join(f"- {e['info']}" for e in entries_snapshot if e["info"]) or "（空）"
        from .taskboard import list_claimed, list_tasks, publish_task, retire_task
        pending_tasks = list_tasks(code)
        claimed_tasks = list_claimed(code)
        tasks_text = "\n".join(f"- [{t['id']}] {t['text']}" for t in pending_tasks) or "（空）"
        claimed_text = "\n".join(f"- {c['text']}（会话 {c['worker']} 执行中）" for c in claimed_tasks) or "（空）"
        prompt = (
            _WATCHER_PROMPT_TEMPLATE
            .replace("{activity}", activity[-_WATCHER_ACTIVITY_CHARS:])
            .replace("{blackboard}", numbered[-_WATCHER_BB_CHARS:])
            .replace("{tasks}", tasks_text[-_WATCHER_TASKS_CHARS:])
            .replace("{claimed_tasks}", claimed_text[-_WATCHER_CLAIMED_CHARS:])
        )
        # 题目描述 + 提示（若已获取）：让 watcher 结合它们策展黑板、发布更贴合的探索方向
        context_header = ""
        try:
            with open(os.path.join(reports_dir, f"desc_{code}.txt"), "r", encoding="utf-8") as f:
                _desc = f.read().strip()
            if _desc:
                context_header += f"【题目描述】\n{_desc[:_WATCHER_DESC_CHARS]}\n\n"
        except Exception:
            pass
        try:
            with open(os.path.join(reports_dir, f"hint_{code}.txt"), "r", encoding="utf-8") as f:
                _hint = f.read().strip()
            if _hint:
                context_header += f"【题目提示】\n{_hint[:_WATCHER_HINT_CHARS]}\n\n"
        except Exception:
            pass
        if context_header:
            prompt = context_header + prompt
        resp = llm.invoke([
            SystemMessage(content=_WATCHER_SYSTEM),
            HumanMessage(content=prompt),
        ])
        text = resp.content if isinstance(resp.content, str) else json.dumps(resp.content, ensure_ascii=False)
        s, e = text.find("{"), text.rfind("}")
        if s == -1 or e == -1:
            return
        obj = json.loads(text[s: e + 1])
        adds = [str(x).strip() for x in (obj.get("add") or []) if str(x).strip()][:3]
        updates = [u for u in (obj.get("update") or []) if isinstance(u, dict) and u.get("old") and u.get("new")][:3]
        removes = [str(x).strip() for x in (obj.get("remove") or []) if str(x).strip()][:3]
        suggests = [str(x).strip() for x in (obj.get("suggest_tasks") or []) if str(x).strip()][:2]
        retires = [str(x).strip() for x in (obj.get("retire_tasks") or []) if str(x).strip()][:3]
        # 发布探索方向到任务板（内部含去重与板上限）
        published = 0
        for s_text in suggests:
            try:
                if publish_task(code, s_text):
                    published += 1
            except Exception:
                pass
        # 策展任务板：下架重复/过时的方向（可按任务 id 精确移除）
        retired = 0
        for r in retires:
            try:
                if retire_task(code, r):
                    retired += 1
            except Exception:
                pass
        if published or retired:
            try:
                print(f"[Watcher] 会话 {worker_id} 任务板: 发布 {published} / 下架 {retired}", flush=True)
            except Exception:
                pass
        if not adds and not updates and not removes:
            return

        # 锁内重读最新内容并应用变更
        import fcntl

        os.makedirs(reports_dir, exist_ok=True)
        with open(lock_path, "w", encoding="utf-8") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                try:
                    with open(info_path, "r", encoding="utf-8") as f:
                        current = f.read()
                except Exception:
                    current = ""
                entries = _parse_blackboard(current)
                changed = False

                # 删除：按内容模糊匹配；[flag方法] 除非漏了具体 flag 值，否则不删
                for target in removes:
                    idx = _find_best_match(entries, target)
                    if idx is None:
                        continue
                    cur = entries[idx].get("info") or ""
                    if _is_flag_method(cur) and not _FLAG_PATTERN_RE.search(cur):
                        continue
                    entries.pop(idx)
                    changed = True

                # 修正：保留原头部（时间戳/会话归属），替换信息内容；不改 [flag方法]
                for u in updates:
                    if _is_flag_method(str(u.get("new") or "")):
                        continue
                    idx = _find_best_match(entries, str(u["old"]))
                    if idx is None:
                        continue
                    if _is_flag_method(entries[idx].get("info") or ""):
                        continue
                    entries[idx]["info"] = str(u["new"]).strip()
                    changed = True

                # 新增：程序化去重后追加；[flag方法] 由首次提交分叉写入，watcher 不 add
                for info in adds:
                    if _is_flag_method(info):
                        continue
                    if _find_best_match(entries, info) is not None:
                        continue
                    entries.append({
                        "header": f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 会话: {worker_id}",
                        "info": info,
                    })
                    changed = True

                if not changed:
                    return
                _write_blackboard_entries(info_path, entries)
                try:
                    print(f"[Watcher] 会话 {worker_id} 维护黑板: 新增 {len(adds)} / 修正 {len(updates)} / 删除 {len(removes)}", flush=True)
                except Exception:
                    pass
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
    except Exception:
        # watcher 失败不影响主流程
        pass


def _claude_env() -> dict:
    """构造 claude 子进程环境。

    LLM 提供方配置（端点/密钥/模型）集中在 cruiser.llm.get_claude_provider_env；
    此处只负责 claude 自身的运行期开关（沙箱、上下文压缩窗口、逆向环境）。
    """
    env = os.environ.copy()
    # 提供方配置（ANTHROPIC_BASE_URL / AUTH_TOKEN / MODEL / SMALL_FAST_MODEL）
    # 注意：单会话 worker 由 main.py 预置 ANTHROPIC_MODEL 指定各自模型，此处会如实沿用。
    env.update(get_claude_provider_env())
    env["IS_SANDBOX"] = "1"  # 允许 root 下使用 bypassPermissions
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    # 经 Anthropic 兼容端点接入时，Claude Code 会把非 claude 模型 ID 当作未知模型并假设
    # 错误的窗口大小（默认 200K），导致 auto-compact 触发时机不当（太晚则撞上真实上限
    # 报错，太早则频繁压缩浪费）。上下文窗口按提供方取默认值（DeepSeek 1M；GLM 旗舰
    # glm-5.2/5.3 同为 1M），声明真实窗口后按对应阈值提前压缩；用户显式设置优先。
    from .llm import get_context_defaults, get_solve_model, provider_for_model
    _model = get_solve_model()
    _max_ctx, _compact_win = get_context_defaults(_model)
    env.setdefault("CLAUDE_CODE_MAX_CONTEXT_TOKENS", str(_max_ctx))
    env.setdefault("CLAUDE_CODE_AUTO_COMPACT_WINDOW", str(_compact_win))
    # GLM-5.x（TokenHub）为始终思考模型：裸 Anthropic 协议请求缺省 thinking 会被网关拒绝
    # （实测报 "该模型始终思考，不支持关闭思考；请使用 low、high 或 max"）。claude CLI
    # 2.1.x 默认请求已能正常通过，此处显式 setdefault MAX_THINKING_TOKENS 作为防御层：
    # 兼容不默认携带 thinking 的老版本 CLI，并给思考链一个明确上限（budget 为上限而非
    # 实际消耗，计费按实际 token；32000 已实测通过 TokenHub 校验，不影响正常输出）。
    if provider_for_model(_model) == "glm":
        env.setdefault("MAX_THINKING_TOKENS", "32000")
    # PyGhidra 运行环境（Ghidra 本体 + JDK），供 Claude 编写的 pyghidra 脚本直接使用
    env.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra_12.1.2_PUBLIC")
    env.setdefault("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64")
    return env


def _extract_text_and_tools(message: dict) -> tuple[str, list[str]]:
    """从 assistant 事件中提取文本与工具调用摘要（用于进度展示）。"""
    texts: list[str] = []
    tools: list[str] = []
    content = message.get("content")
    if isinstance(content, str):
        return content, tools
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                texts.append(str(block.get("text") or ""))
            elif btype == "tool_use":
                name = block.get("name") or "?"
                inp = block.get("input") or {}
                summary = ""
                if isinstance(inp, dict):
                    summary = inp.get("command") or inp.get("file_path") or inp.get("pattern") or ""
                tools.append(f"{name}: {str(summary)[:150]}")
    return "\n".join(texts), tools


def _iter_tool_result_texts(message: dict) -> list[str]:
    """从 user 事件（工具结果）中提取全部文本块。"""
    out: list[str] = []
    content = message.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                c = block.get("content")
                if isinstance(c, str):
                    out.append(c)
                elif isinstance(c, list):
                    for sub in c:
                        if isinstance(sub, dict) and sub.get("type") == "text":
                            out.append(str(sub.get("text") or ""))
    return out


def _write_hooks_settings(ws_dir: str) -> None:
    """在工作目录写入 .claude/settings.json，注册黑板注入钩子。

    SessionStart 开局注入一次；PostToolUse 每 10 次工具调用注入一次最新黑板，
    通过 additionalContext 物理进入模型上下文，不依赖模型自觉读取。
    """
    try:
        claude_dir = os.path.join(ws_dir, ".claude")
        os.makedirs(claude_dir, exist_ok=True)
        hook_cmd = f'"{sys.executable}" {os.path.join(_project_root(), "blackboard_hook.py")}'
        settings = {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": hook_cmd}]}],
                "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": hook_cmd}]}],
            }
        }
        with open(os.path.join(claude_dir, "settings.json"), "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _capture_submitted_flag(message: dict) -> Optional[str]:
    """若本 assistant 事件调用了 submit_flag.py，提取命令行中的 flag 参数。"""
    content = message.get("content")
    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        inp = block.get("input") or {}
        cmdline = str(inp.get("command") or "") if isinstance(inp, dict) else ""
        m = _SUBMIT_INVOKE_RE.search(cmdline)
        if not m:
            continue
        flag = m.group(2) or m.group(3) or m.group(4) or ""
        if _looks_like_flag(flag):
            return flag
    return None


def _run_one_session(target: str, hint: str, code: str, worker_id: str, ws_dir: str, quiet: bool, step_counter: list[int], solver_task: Optional[str] = None) -> Optional[str]:
    """运行一个 Claude 会话直至本题 flag 全部确认 / 达到轮数上限 / 被外部杀死。

    step_counter 为跨会话共享的单元素列表：[COUNT] 计数在多次会话间单调递增，
    保证 main.py 调度器的步数阈值（可超过单会话 100 轮上限）能够触发。
    返回确认后的 flag JSON 字符串（仅当平台进度已齐）；未齐或未解出返回 None，由上层开新会话继续。
    """
    root = _project_root()
    reports_dir = os.path.join(os.getcwd(), "reports")
    tools_dir = os.path.join(root, "tools")
    submit_cmd = f'"{sys.executable}" {os.path.join(tools_dir, "submit_flag.py")}'
    dirsearch_cmd = f'"{sys.executable}" {os.path.join(tools_dir, "dirsearch_scan.py")}'
    decompile_script = os.path.join(tools_dir, "decompile.py")
    res_dir = os.path.join(root, "resource")
    if solver_task:
        # solver 定向模式：只做一条方向，用聚焦的系统提示与任务模板
        system_prompt = CLAUDE_SOLVER_SYSTEM_PROMPT
        prompt = CLAUDE_SOLVER_TASK_TEMPLATE.format(
            target=target or "(未提供)",
            code=code or "unknown",
            task=solver_task,
            info_file=os.path.join(reports_dir, f"info_{code}.txt"),
            submit_cmd=submit_cmd,
            res_dir=res_dir,
            decompile_script=decompile_script,
            dirsearch_cmd=dirsearch_cmd,
        )
    else:
        system_prompt = CLAUDE_SYSTEM_PROMPT
        prompt = CLAUDE_TASK_TEMPLATE.format(
            target=target or "(未提供，先从黑板与提示获取)",
            code=code or "unknown",
            hint=hint or "暂无",
            info_file=os.path.join(reports_dir, f"info_{code}.txt"),
            hint_file=os.path.join(reports_dir, f"hint_{code}.txt"),
            submit_cmd=submit_cmd,
            res_dir=res_dir,
            decompile_script=decompile_script,
            dirsearch_cmd=dirsearch_cmd,
        )
    claude_bin = shutil.which("claude")
    if not claude_bin:
        raise RuntimeError("claude CLI 未安装或不在 PATH 中")
    _write_hooks_settings(ws_dir)

    cmd = [
        claude_bin,
        "-p", prompt,
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "bypassPermissions",
        "--append-system-prompt", system_prompt,
        # CTF 比赛禁止联网检索：从工具集中移除 WebSearch/WebFetch（headless 下 bypassPermissions 会自动放行）。
        "--disallowedTools", "WebSearch,WebFetch",
    ]
    # 仅当显式配置了正整数轮数上限时才限制单会话轮数；默认不限制。
    max_turns = _max_turns_per_session()
    if max_turns > 0:
        cmd += ["--max-turns", str(max_turns)]
    # 不使用 start_new_session：claude 及其子进程留在本进程组，
    # main.py 调度器 killpg 时可整组回收
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=ws_dir,
        env=_claude_env(),
    )

    session_step = 0
    flag_json: Optional[str] = None
    last_submitted_flag = ""
    confirmed_flag: Optional[str] = None       # 最近一次被平台接受的 flag
    flag_candidates: "set[str]" = set()        # 会话中出现过的合法 flag 候选（供权威校验）
    verified: "set[str]" = set()               # 已得到确定性结果的候选（瞬时失败不计入，以便重试）
    progress = {"correct": 0, "total": 0}      # 平台进度；仅 X>=Y 才结束本会话
    # 黑板 watcher 状态：滚动活动摘要 + 单 watcher 并发闸（busy 时挂起最新快照，不丢周期）
    recent: deque[str] = deque(maxlen=_WATCHER_RECENT_MAX)
    watcher_state = {"busy": False, "pending": None}
    watcher_lock = threading.Lock()
    flag_method_threads: list[threading.Thread] = []

    def _challenge_done() -> bool:
        return _flags_all_collected(progress["correct"], progress["total"])

    def _note_flag_outcome(cand: str, outcome) -> None:
        if not outcome.ok:
            return
        nonlocal confirmed_flag
        confirmed_flag = cand
        if outcome.total >= 1:
            progress["correct"] = max(progress["correct"], outcome.correct)
            progress["total"] = max(progress["total"], outcome.total)
        elif code:
            from .tools import query_flag_progress
            qc, qt = query_flag_progress(code)
            if qt >= 1:
                progress["correct"] = max(progress["correct"], qc)
                progress["total"] = max(progress["total"], qt)
        prog = f"{progress['correct']}/{progress['total']}" if progress["total"] >= 1 else "?"
        try:
            if _challenge_done():
                print(f"\x1b[95;1m[FLAG] 会话 {worker_id} 全部 flag 已齐 ({prog}): {cand}\x1b[0m", flush=True)
            else:
                print(f"\x1b[93;1m[FLAG PARTIAL] 会话 {worker_id} 进度 {prog}，继续挖掘: {cand}\x1b[0m", flush=True)
        except Exception:
            pass
        fresh = bool(getattr(outcome, "fresh", False))
        _flag_method_dbg(
            f"note_outcome worker={worker_id} fresh={fresh} ok={outcome.ok} "
            f"correct={getattr(outcome, 'correct', None)} total={getattr(outcome, 'total', None)} "
            f"progress={prog} has_fresh_attr={hasattr(outcome, 'fresh')} "
            f"recent_n={len(recent)} code={code!r}"
        )
        if fresh:
            t = _spawn_flag_method_writer(
                code, worker_id, progress["correct"], progress["total"], list(recent)
            )
            if t is not None:
                flag_method_threads.append(t)
        else:
            _flag_method_dbg(f"note_outcome 不写条目: fresh=False worker={worker_id} prog={prog}")

    def _apply_outcome(cand: str, outcome) -> bool:
        """应用一次提交结果。返回 True 当且仅当本题 flag 已全部确认。"""
        if outcome.definitive:
            verified.add(cand)
        if outcome.ok:
            _note_flag_outcome(cand, outcome)
        return _challenge_done()

    def _verify_flag(cand: str) -> bool:
        """权威校验：框架亲自向平台提交。True 只表示本题已齐，不是「这一枚对了」。"""
        from .tools import looks_flaglike
        if not code or not cand or not looks_flaglike(cand):
            return _challenge_done()
        if cand in verified:
            return _challenge_done()
        return _apply_outcome(cand, _submit_flag_directly(code, cand))

    def _ingest_cands(cands: list[str]) -> bool:
        """按顺序提交本批候选。第一枚正确但未齐时继续交后续；齐了才返回 True。"""
        seen: set[str] = set()
        for fm in cands:
            if not fm or fm in seen:
                continue
            seen.add(fm)
            flag_candidates.add(fm)
            if _verify_flag(fm):
                return True
        return _challenge_done()

    def _mark_done(cand: str) -> None:
        nonlocal flag_json, confirmed_flag
        confirmed_flag = cand or last_submitted_flag or confirmed_flag or "ok"
        flag_json = json.dumps({"flag": confirmed_flag}, ensure_ascii=False)

    def _absorb_tool_progress(text: str) -> None:
        """模型自己调用 submit_flag.py 的回执里若带 X/Y，同步进 progress（覆盖形态过滤漏掉的串）。"""
        if not any(marker in (text or "") for marker in _FLAG_OK_MARKERS):
            return
        c, t = _progress_from_text(text)
        if t >= 1:
            progress["correct"] = max(progress["correct"], c)
            progress["total"] = max(progress["total"], t)
        if "提交flag正确" in (text or "") and "已经提交成功过了" not in (text or ""):
            _flag_method_dbg(
                f"absorb 模型提交正确 worker={worker_id} progress={progress} "
                f"recent_n={len(recent)} text_head={(text or '')[:80]!r}"
            )
            t = _spawn_flag_method_writer(
                code, worker_id, progress["correct"], progress["total"], list(recent)
            )
            if t is not None:
                flag_method_threads.append(t)

    def _maybe_trigger_watcher() -> None:
        if not code:
            return
        snapshot = _format_watcher_activity(recent)
        start = False
        with watcher_lock:
            if watcher_state["busy"]:
                watcher_state["pending"] = snapshot
                return
            watcher_state["busy"] = True
            start = True
        if start:
            threading.Thread(target=_watcher_job, args=(snapshot,), daemon=True).start()

    def _watcher_job(snapshot: str) -> None:
        while True:
            try:
                _watcher_curate_blackboard(code, worker_id, snapshot)
            except Exception:
                pass
            with watcher_lock:
                snapshot = watcher_state["pending"]
                watcher_state["pending"] = None
                if snapshot is None:
                    watcher_state["busy"] = False
                    return

    try:
        for raw in proc.stdout or []:
            line = raw.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except Exception:
                continue
            etype = evt.get("type")
            if etype == "assistant":
                session_step += 1
                step_counter[0] += 1
                print(f"[COUNT] {step_counter[0]}", flush=True)
                msg = evt.get("message") or {}
                text, tools = _extract_text_and_tools(msg)
                if not quiet:
                    for t in tools:
                        print(f"[TOOL] {t}", flush=True)
                    if text.strip():
                        # 压成单行，避免 Thought 里的 JSON 被父进程按行误判为最终 {"flag"}
                        preview = text.strip()[:300].replace("\n", " ").replace("\r", " ")
                        print(f"[Claude] {preview}", flush=True)
                digest_parts = []
                if text.strip():
                    digest_parts.append("Thought: " + text.strip()[:_WATCHER_THOUGHT_CHARS])
                digest_parts.extend("Action: " + t for t in tools)
                if digest_parts:
                    recent.append("\n".join(digest_parts))
                ingest: list[str] = []
                submitted = _capture_submitted_flag(msg)
                if submitted and _looks_like_flag(submitted):
                    last_submitted_flag = submitted
                    ingest.append(submitted)
                blob = _unique_flag_cands(text or "")
                if len(blob) <= _AUTO_SUBMIT_MAX_PER_BLOB:
                    ingest.extend(blob)
                if _ingest_cands(ingest):
                    _mark_done(confirmed_flag or last_submitted_flag or (ingest[-1] if ingest else "ok"))
                    break
                if session_step % _WATCHER_EVERY == 0:
                    _maybe_trigger_watcher()
            elif etype == "user":
                msg = evt.get("message") or {}
                ingest: list[str] = []
                for rt in _iter_tool_result_texts(msg):
                    blob = _unique_flag_cands(rt or "")
                    if len(blob) <= _AUTO_SUBMIT_MAX_PER_BLOB:
                        ingest.extend(blob)
                    if rt.strip():
                        recent.append("Observation: " + rt.strip()[:_WATCHER_OBS_CHARS])
                    _absorb_tool_progress(rt or "")
                if _ingest_cands(ingest) or _challenge_done():
                    _mark_done(confirmed_flag or last_submitted_flag or "ok")
                    break
            elif etype == "result":
                # 会话结束（success / error_max_turns / error_*）
                if not quiet:
                    subtype = evt.get("subtype") or ""
                    print(f"[Session] Claude 会话结束: {subtype}", flush=True)
                break
    finally:
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        # 首次提交的 [flag方法] 分叉优先收尾，避免会话退出时 daemon 被直接丢掉
        for t in flag_method_threads:
            try:
                _flag_method_dbg(f"join 等待 {t.name} alive={t.is_alive()}")
                t.join(timeout=25)
                _flag_method_dbg(f"join 结束 {t.name} alive={t.is_alive()}")
            except Exception as e:
                _flag_method_dbg(f"join 异常 {t.name} {type(e).__name__}: {e}")
        # 收尾：会话结束（出 flag / 达轮数上限 / 自然结束）时强制再采集一次，
        # 补齐"最后一次周期 watcher 之后"到会话结束之间的尾部新发现（否则会漏采）。
        # 同步执行但带超时：避免子进程退出前 daemon watcher 线程被杀导致丢失，同时防止 LLM 卡死拖住回收。
        if code and recent:
            snapshot = _format_watcher_activity(recent)
            try:
                ft = threading.Thread(
                    target=_watcher_curate_blackboard, args=(code, worker_id, snapshot), daemon=True
                )
                ft.start()
                ft.join(timeout=30)
            except Exception:
                pass

    if flag_json:
        return flag_json
    # 会话结束：对本会话见过的候选全部补交（不因第一枚正确就停），仅当平台进度已齐才返回 JSON。
    if code:
        last_ok = confirmed_flag
        for cand in sorted((c for c in flag_candidates if _looks_like_flag(c)), key=len, reverse=True):
            if _verify_flag(cand):
                last_ok = cand
                break
            if cand in verified and progress["total"] >= 1:
                last_ok = last_ok or cand
        if _challenge_done():
            try:
                print(f"\x1b[95;1m[FLAG RECOVERED] 会话结束后程序化补交，进度已齐: {last_ok}\x1b[0m", flush=True)
            except Exception:
                pass
            return json.dumps({"flag": last_ok or "ok"}, ensure_ascii=False)
    return None


def run_auto_scan(target: str, max_steps: int = 0, quiet: bool = False, hint: Optional[str] = None, challenge_code: Optional[str] = None, solver_task: Optional[str] = None) -> str:
    """运行 Claude Code 自动扫描，直到本题全部 flag 被平台确认（或被外部调度器终止）。

    - 返回值为含 flag 字段的 JSON 字符串（仅当平台进度已齐）；
    - max_steps 不在此强制终止（步数阈值由 main.py 调度器通过 [COUNT] 监控执行）；
    - 单枚正确但未齐时会话继续；会话自然结束后基于黑板成果开新会话继续挖剩余 flag。

    solver 模式（solver_task 非空）：只跑一个聚焦该方向的会话即返回，不循环开新会话；
    回合(turn)上限由环境变量 CRUISER_MAX_TURNS 控制（main.py 的 solver 驱动设为 40）。
    注意：这是 claude 的回合(turn)数，非日志里的 [COUNT]（[COUNT] 约为其数倍）。
    """
    if shutil.which("claude") is None:
        return json.dumps({"flag": None, "error": "claude CLI 未安装"}, ensure_ascii=False)

    worker_id = os.environ.get("CRUISER_WORKER_ID", "single")
    code = challenge_code or os.environ.get("CRUISER_CHALLENGE_CODE") or ""
    ws_dir = os.environ.get("CRUISER_WORKSPACE_DIR") or ""
    if not ws_dir:
        base_ws = "/tmp/cruiser_workspaces"
        os.makedirs(base_ws, exist_ok=True)
        ws_dir = os.path.join(base_ws, f"ws_claude_{uuid.uuid4().hex[:8]}")
    os.makedirs(ws_dir, exist_ok=True)

    # solver 定向模式：只跑一个会话，完成/达轮数上限即返回，不循环
    if solver_task:
        try:
            flag_json = _run_one_session(
                target=target, hint="", code=code, worker_id=worker_id,
                ws_dir=ws_dir, quiet=quiet, step_counter=[0], solver_task=solver_task,
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            return json.dumps({"flag": None, "error": str(e)}, ensure_ascii=False)
        if flag_json:
            try:
                print(f"\x1b[95;1m[FOUND FLAG] {flag_json}\x1b[0m", flush=True)
            except Exception:
                pass
            return flag_json
        return json.dumps({"flag": None}, ensure_ascii=False)

    attempt = 0
    step_counter = [0]  # 跨会话单调递增的全局步数计数器
    while True:
        attempt += 1
        try:
            flag_json = _run_one_session(
                target=target,
                hint=hint or "",
                code=code,
                worker_id=worker_id,
                ws_dir=ws_dir,
                quiet=quiet,
                step_counter=step_counter,
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            try:
                print(f"[Error] Claude 会话异常: {e}", flush=True)
            except Exception:
                pass
            time.sleep(5)
            continue
        if flag_json:
            try:
                print(f"\x1b[95;1m[FOUND FLAG] {flag_json}\x1b[0m", flush=True)
            except Exception:
                pass
            return flag_json
        try:
            _mt = _max_turns_per_session()
            _limit_desc = f"{_mt} 轮上限" if _mt > 0 else "会话自然结束"
            print(f"[Session] 第 {attempt} 个会话未齐（{_limit_desc}），基于黑板成果开启新会话…", flush=True)
        except Exception:
            pass
