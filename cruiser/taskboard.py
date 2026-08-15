"""探索方向任务板：watcher 发布方向，worker 认领（认领即擦除）与回报。

每题一个文件 reports/tasks_<code>.txt，行格式：
    [t-xxxxxx] 方向内容（一行）
所有读写均在文件锁内完成，重写走临时文件 + os.replace 原子替换，
多 worker 并发认领同一方向时只有一个能成功。
"""
from __future__ import annotations

import fcntl
import os
import re
import time
import uuid
from typing import Optional

_MAX_PENDING = 5  # 板上最多待认领方向数，超过不再发布
_TASK_LINE_RE = re.compile(r"^\[(t-[0-9a-f]{6})\]\s*(.*)$")
# 认领记忆时长：认领擦除后的方向在这段时间内仍参与判重（防止 watcher 重复发布）；
# 超时自动解冻，避免认领方异常死亡导致方向永久锁死
_CLAIMED_TTL_S = 45 * 60


def _reports_dir() -> str:
    # 基于项目根目录定位，与调用方 cwd 无关
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "reports")


def _tasks_path(code: str) -> str:
    return os.path.join(_reports_dir(), f"tasks_{code}.txt")


def _lock_path(code: str) -> str:
    return _tasks_path(code) + ".lock"


def _claimed_path(code: str) -> str:
    return _tasks_path(code) + ".claimed"


def _normalize(text: str) -> str:
    # 小写 + 只保留字母/数字/中日韩字符，消除路径分隔符、标点与空白差异
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (text or "").lower())


def _bigrams(s: str) -> set[str]:
    if len(s) < 2:
        return {s} if s else set()
    return {s[i: i + 2] for i in range(len(s) - 1)}


def _similar(a: str, b: str) -> bool:
    """归一化包含关系，或字符 bigram 重叠系数 >= 0.6，视为同一方向。"""
    na, nb = _normalize(a), _normalize(b)
    if not na or not nb:
        return False
    if na == nb or na in nb or nb in na:
        return True
    ba, bb = _bigrams(na), _bigrams(nb)
    if not ba or not bb:
        return False
    return len(ba & bb) / min(len(ba), len(bb)) >= 0.6


def _read_lines_unlocked(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]
    except Exception:
        return []


def _write_lines_atomic(path: str, lines: list[str]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
    os.replace(tmp, path)


def list_tasks(code: str) -> list[dict]:
    """返回待认领方向列表：[{"id": "t-xxxxxx", "text": "..."}]。"""
    if not code:
        return []
    out = []
    for ln in _read_lines_unlocked(_tasks_path(code)):
        m = _TASK_LINE_RE.match(ln.strip())
        if m:
            out.append({"id": m.group(1), "text": m.group(2).strip()})
    return out


def list_claimed(code: str, ttl_s: float = _CLAIMED_TTL_S) -> list[dict]:
    """返回近期被认领（正在执行中）的方向：[{"ts": int, "worker": str, "text": str}]。

    只保留 TTL 内的记录；超龄记录视为已解冻，不再返回。
    """
    if not code:
        return []
    now = time.time()
    out = []
    for ln in _read_lines_unlocked(_claimed_path(code)):
        parts = ln.split("|", 2)
        if len(parts) != 3:
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        if now - ts <= ttl_s:
            out.append({"ts": ts, "worker": parts[1], "text": parts[2].strip()})
    return out


def publish_task(code: str, text: str) -> bool:
    """watcher 发布方向：与「待认领板 + 近期已认领」去重，板满（>=5）不再发布。
    返回是否实际写入。"""
    text = (text or "").strip()
    if not code or not text:
        return False
    os.makedirs(_reports_dir(), exist_ok=True)
    with open(_lock_path(code), "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = _read_lines_unlocked(_tasks_path(code))
            existing = []
            for ln in lines:
                m = _TASK_LINE_RE.match(ln.strip())
                if m:
                    existing.append(m.group(2).strip())
            if len(existing) >= _MAX_PENDING:
                return False
            # 判重范围 = 待认领 + 近期已认领（防止认领擦除后 watcher 重复发布）
            pool = existing + [c["text"] for c in list_claimed(code)]
            if any(_similar(text, e) for e in pool):
                return False
            tid = f"t-{uuid.uuid4().hex[:6]}"
            lines.append(f"[{tid}] {text}")
            _write_lines_atomic(_tasks_path(code), lines)
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def claim_task(code: str, worker_id: str, task_id: Optional[str] = None) -> Optional[dict]:
    """认领方向：锁内找到并擦除该条目后返回它；已被别人认领/不存在返回 None。

    task_id 为空时认领板上第一个方向。
    """
    if not code:
        return None
    os.makedirs(_reports_dir(), exist_ok=True)
    with open(_lock_path(code), "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = _read_lines_unlocked(_tasks_path(code))
            keep: list[str] = []
            claimed: Optional[dict] = None
            for ln in lines:
                m = _TASK_LINE_RE.match(ln.strip())
                if m and claimed is None and (task_id is None or m.group(1) == task_id):
                    claimed = {"id": m.group(1), "text": m.group(2).strip()}
                    continue  # 擦除
                keep.append(ln)
            if claimed is None:
                return None
            _write_lines_atomic(_tasks_path(code), keep)
            # 写入认领日志（同时清理超龄记录），供发布判重与 watcher 参考
            claimed_lines = [
                f"{c['ts']}|{c['worker']}|{c['text']}"
                for c in list_claimed(code)
            ]
            claimed_lines.append(f"{int(time.time())}|{worker_id}|{claimed['text']}")
            _write_lines_atomic(_claimed_path(code), claimed_lines)
            return claimed
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def retire_task(code: str, ref: str) -> bool:
    """watcher 策展用：移除板上某个方向。ref 优先按任务 id（t-xxxxxx）精确匹配，
    否则按内容相似度匹配。返回是否实际移除。"""
    ref = (ref or "").strip()
    if not code or not ref:
        return False
    os.makedirs(_reports_dir(), exist_ok=True)
    id_match = re.fullmatch(r"t-[0-9a-f]{6}", ref)
    with open(_lock_path(code), "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = _read_lines_unlocked(_tasks_path(code))
            keep: list[str] = []
            removed = False
            for ln in lines:
                m = _TASK_LINE_RE.match(ln.strip())
                if m and not removed:
                    if (id_match and m.group(1) == ref) or (not id_match and _similar(ref, m.group(2).strip())):
                        removed = True
                        continue
                keep.append(ln)
            if not removed:
                return False
            _write_lines_atomic(_tasks_path(code), keep)
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def report_task(code: str, worker_id: str, text: str) -> bool:
    """回报完成情况：作为一条黑板条目追加到 info_<code>.txt（与 watcher 策展共用同一把锁）。"""
    text = (text or "").strip()
    if not code or not text:
        return False
    info_path = os.path.join(_reports_dir(), f"info_{code}.txt")
    os.makedirs(_reports_dir(), exist_ok=True)
    with open(info_path + ".lock", "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            with open(info_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 会话: {worker_id}\n")
                f.write(f"关键信息: [任务回报] {text}\n")
                f.write("-" * 60 + "\n")
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)
