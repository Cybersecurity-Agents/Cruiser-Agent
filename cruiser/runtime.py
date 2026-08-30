"""调度器运行态快照：供监控面板读取。

调度主进程写入内存；dashboard 进程若独立启动则读 reports/_runtime.json，
并始终从 reports/ 汇编黑板、任务板、flag 与题目描述。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import deque
from typing import Any, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPORTS = os.path.join(_ROOT, "reports")
_RUNTIME_PATH = os.path.join(_REPORTS, "_runtime.json")
_LOG_FILE = os.environ.get("CRUISER_LOG_FILE", "/tmp/cruiser.log")

_LOCK = threading.RLock()
_HEARTBEAT = 0.0
_SCHEDULER: dict[str, Any] = {}
_STAGES: dict[str, dict[str, Any]] = {}
_LAST_RUNS: dict[str, dict[str, Any]] = {}
_LOG_SEQ = 0
_LOGS: deque[dict[str, Any]] = deque(maxlen=4000)

_STAGE_LABEL = {
    "preprocess": "预处理 · 50 步",
    "tier1": "一级 · 100 步",
    "tier2": "二级 · 150 步",
    "tier3": "三级 · 200 步",
}
_STAGE_BY_THRESHOLD = {50: "preprocess", 100: "tier1", 150: "tier2", 200: "tier3"}

_HEADER_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*会话:\s*(.+)$"
)
_TASK_LINE_RE = re.compile(r"^\[(t-[0-9a-f]{6})\]\s*(.*)$")
_LOG_PREFIX_RE = re.compile(r"^\[([^:\]]+)(?::([^\]]+))?\]\s*(.*)$")
_INFO_NAME_RE = re.compile(r"^(?:info|desc|hint|tasks)_(.+)\.txt$")
_FLAG_PROG_RE = re.compile(r"进度\s*(\d+)\s*/\s*(\d+)")


def reports_dir() -> str:
    return _REPORTS


def stage_name_for_threshold(threshold: int) -> str:
    return _STAGE_BY_THRESHOLD.get(int(threshold), f"t{threshold}")


def touch() -> None:
    global _HEARTBEAT
    with _LOCK:
        _HEARTBEAT = time.time()


def set_scheduler(
    *,
    items: dict[str, dict],
    solved: list[str],
    queues: dict[str, Any],
    max_active: int,
    inflight: int,
    worker_models: list[str],
    solver_model: str,
    local: bool,
) -> None:
    with _LOCK:
        _SCHEDULER.clear()
        _SCHEDULER.update({
            "items": items or {},
            "solved": list(solved or []),
            "queues": queues or {},
            "max_active": int(max_active),
            "inflight": int(inflight),
            "worker_models": list(worker_models or []),
            "solver_model": solver_model or "",
            "local": bool(local),
        })
        touch()
        _dump_runtime_unlocked()


def stage_begin(
    code: str,
    *,
    stage: str,
    threshold: int,
    target: str,
    hint_enabled: bool,
    workers: list[dict[str, Any]],
) -> None:
    if not code:
        return
    now = time.time()
    with _LOCK:
        _STAGES[code] = {
            "code": code,
            "stage": stage,
            "threshold": int(threshold),
            "target": target or "",
            "hint_enabled": bool(hint_enabled),
            "started_at": now,
            "winner": None,
            "flag_correct": 0,
            "flag_total": 0,
            "workers": {str(w.get("id")): dict(w) for w in workers},
            "solvers": {},
        }
        touch()


def stage_count(code: str, worker_id: str, n: int) -> None:
    with _LOCK:
        st = _STAGES.get(code)
        if not st:
            return
        wid = str(worker_id)
        w = st["workers"].get(wid)
        if w is None:
            w = st["solvers"].get(wid)
        if w is not None:
            w["count"] = int(n)
            w["alive"] = True
        touch()


def stage_flags(code: str, correct: int, total: int) -> None:
    with _LOCK:
        st = _STAGES.get(code)
        if not st:
            return
        st["flag_correct"] = max(st.get("flag_correct") or 0, int(correct or 0))
        st["flag_total"] = max(st.get("flag_total") or 0, int(total or 0))


def stage_winner(code: str, winner: str) -> None:
    with _LOCK:
        st = _STAGES.get(code)
        if st is not None:
            st["winner"] = winner


def solver_up(code: str, sid: int, *, pid: int, task: str, model: str, ws: str) -> None:
    with _LOCK:
        st = _STAGES.get(code)
        if not st:
            return
        st["solvers"][f"solver{sid}"] = {
            "id": f"solver{sid}",
            "kind": "solver",
            "pid": int(pid),
            "model": model or "",
            "ws": ws or "",
            "task": task or "",
            "alive": True,
            "count": 0,
        }
        touch()


def solver_down(code: str, sid: int) -> None:
    with _LOCK:
        st = _STAGES.get(code)
        if not st:
            return
        rec = st["solvers"].get(f"solver{sid}")
        if rec is not None:
            rec["alive"] = False


def worker_down(code: str, worker_id: str) -> None:
    with _LOCK:
        st = _STAGES.get(code)
        if not st:
            return
        rec = st["workers"].get(str(worker_id))
        if rec is not None:
            rec["alive"] = False


def stage_end(code: str, *, flagged: bool) -> None:
    with _LOCK:
        st = _STAGES.pop(code, None)
        if st is None:
            return
        counts = [int(w.get("count") or 0) for w in st.get("workers", {}).values()]
        counts += [int(w.get("count") or 0) for w in st.get("solvers", {}).values()]
        _LAST_RUNS[code] = {
            "stage": st.get("stage"),
            "threshold": st.get("threshold"),
            "max_count": max(counts) if counts else 0,
            "flagged": bool(flagged),
            "ended_at": time.time(),
            "winner": st.get("winner"),
        }
        touch()
        _dump_runtime_unlocked()


def push_log(code: str, worker: str, text: str) -> None:
    global _LOG_SEQ
    line = (text or "").rstrip("\n")
    if len(line) > 2000:
        line = line[:2000] + "…"
    with _LOCK:
        _LOG_SEQ += 1
        _LOGS.append({
            "seq": _LOG_SEQ,
            "t": time.time(),
            "code": code or "",
            "worker": worker or "",
            "text": line,
        })


def logs_since(after: int = 0, code: str = "", limit: int = 300) -> dict[str, Any]:
    limit = max(1, min(int(limit or 300), 800))
    after = int(after or 0)
    with _LOCK:
        items = [x for x in _LOGS if x["seq"] > after]
        cursor = _LOG_SEQ
    if code:
        items = [x for x in items if x.get("code") == code]
    if len(items) > limit:
        items = items[-limit:]
    if items or cursor > 0:
        return {"items": items, "cursor": cursor, "source": "memory"}
    return _logs_from_file(after=after, code=code, limit=limit)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def parse_blackboard(content: str) -> list[dict[str, Any]]:
    sep = "-" * 60
    out: list[dict[str, Any]] = []
    for part in (content or "").split(sep):
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
        ts, worker = "", ""
        m = _HEADER_RE.match(header.strip())
        if m:
            ts, worker = m.group(1), m.group(2).strip()
        kind = "fact"
        if info.startswith("[flag方法]"):
            kind = "flag_method"
        elif info.startswith("[任务回报]"):
            kind = "task_report"
        out.append({
            "ts": ts,
            "worker": worker,
            "info": info,
            "kind": kind,
        })
    return out


def _parse_tasks(content: str) -> list[dict[str, str]]:
    out = []
    for ln in (content or "").splitlines():
        m = _TASK_LINE_RE.match(ln.strip())
        if m:
            out.append({"id": m.group(1), "text": m.group(2).strip()})
    return out


def _parse_claimed(content: str) -> list[dict[str, Any]]:
    now = time.time()
    out = []
    for ln in (content or "").splitlines():
        parts = ln.split("|", 2)
        if len(parts) != 3:
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        out.append({
            "ts": ts,
            "age_s": max(0, int(now - ts)),
            "worker": parts[1],
            "text": parts[2].strip(),
        })
    return out


def load_flagstore() -> dict[str, Any]:
    raw = _read_text(os.path.join(_REPORTS, "_flagstore.json"))
    if not raw.strip():
        return {"correct": {}, "wrong": {}}
    try:
        obj = json.loads(raw)
    except Exception:
        return {"correct": {}, "wrong": {}}
    correct = obj.get("correct") if isinstance(obj.get("correct"), dict) else {}
    wrong = obj.get("wrong") if isinstance(obj.get("wrong"), dict) else {}
    return {"correct": correct, "wrong": wrong}


def list_report_codes() -> set[str]:
    codes: set[str] = set()
    try:
        names = os.listdir(_REPORTS)
    except OSError:
        return codes
    for name in names:
        m = _INFO_NAME_RE.match(name)
        if m:
            codes.add(m.group(1))
    return codes


def _flag_counts_by_code(store: dict[str, Any]) -> dict[str, dict[str, int]]:
    by: dict[str, dict[str, int]] = {}
    for flag, code in (store.get("correct") or {}).items():
        rec = by.setdefault(str(code), {"ok": 0, "wrong": 0})
        rec["ok"] += 1
    for code, flags in (store.get("wrong") or {}).items():
        rec = by.setdefault(str(code), {"ok": 0, "wrong": 0})
        rec["wrong"] += len(flags or [])
    return by


def challenge_files(code: str) -> dict[str, Any]:
    info = _read_text(os.path.join(_REPORTS, f"info_{code}.txt"))
    desc = _read_text(os.path.join(_REPORTS, f"desc_{code}.txt")).strip()
    hint = _read_text(os.path.join(_REPORTS, f"hint_{code}.txt")).strip()
    tasks = _parse_tasks(_read_text(os.path.join(_REPORTS, f"tasks_{code}.txt")))
    claimed = _parse_claimed(_read_text(os.path.join(_REPORTS, f"tasks_{code}.txt.claimed")))
    entries = parse_blackboard(info)
    return {
        "description": desc,
        "hint": hint,
        "hint_ready": bool(hint),
        "blackboard": entries,
        "blackboard_n": len(entries),
        "flag_methods": [e for e in entries if e["kind"] == "flag_method"],
        "pending_tasks": tasks,
        "claimed_tasks": claimed,
    }


def _dump_runtime_unlocked() -> None:
    try:
        os.makedirs(_REPORTS, exist_ok=True)
        payload = {
            "ts": time.time(),
            "heartbeat": _HEARTBEAT,
            "scheduler": {
                k: v for k, v in _SCHEDULER.items() if k != "items"
            },
            "items": _SCHEDULER.get("items") or {},
            "stages": _STAGES,
            "last_runs": _LAST_RUNS,
        }
        tmp = _RUNTIME_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp, _RUNTIME_PATH)
    except Exception:
        pass


def _load_runtime_file() -> dict[str, Any]:
    raw = _read_text(_RUNTIME_PATH)
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _alive(heartbeat: float) -> bool:
    return heartbeat > 0 and (time.time() - heartbeat) < 8.0


def snapshot() -> dict[str, Any]:
    with _LOCK:
        heartbeat = _HEARTBEAT
        sched = dict(_SCHEDULER)
        stages = {k: json.loads(json.dumps(v)) for k, v in _STAGES.items()}
        last_runs = dict(_LAST_RUNS)
    file_rt = {}
    if not _alive(heartbeat):
        file_rt = _load_runtime_file()
        heartbeat = float(file_rt.get("heartbeat") or 0)
        if file_rt:
            sched = {
                **(file_rt.get("scheduler") or {}),
                "items": file_rt.get("items") or {},
            }
            stages = file_rt.get("stages") or {}
            last_runs = file_rt.get("last_runs") or last_runs
    items: dict[str, dict] = dict(sched.get("items") or {})
    store = load_flagstore()
    by_flags = _flag_counts_by_code(store)
    codes = set(items) | set(stages) | list_report_codes() | set(sched.get("solved") or [])
    queues = sched.get("queues") or {}
    queue_of: dict[str, str] = {}
    for qname, bucket in queues.items():
        if isinstance(bucket, dict):
            for c in bucket.get("running") or []:
                queue_of[str(c)] = qname
            for c in bucket.get("waiting") or []:
                queue_of.setdefault(str(c), qname)
        elif isinstance(bucket, list):
            for c in bucket:
                queue_of.setdefault(str(c), qname)

    challenges = []
    for code in sorted(codes):
        meta = items.get(code) or {}
        st = stages.get(code) or {}
        files = challenge_files(code)
        fc = by_flags.get(code) or {"ok": 0, "wrong": 0}
        sdk_ok = int(meta.get("correct_flag_count") or 0)
        sdk_total = int(meta.get("flag_count") or 0)
        live_ok = int(st.get("flag_correct") or 0)
        live_total = int(st.get("flag_total") or 0)
        method_ok, method_total = 0, 0
        for e in files["flag_methods"]:
            m = _FLAG_PROG_RE.search(e.get("info") or "")
            if not m:
                continue
            method_ok = max(method_ok, int(m.group(1)))
            method_total = max(method_total, int(m.group(2)))
        ok = max(sdk_ok, live_ok, fc["ok"], method_ok)
        total = max(sdk_total, live_total, method_total)
        workers = list((st.get("workers") or {}).values())
        solvers = list((st.get("solvers") or {}).values())
        counts = [int(w.get("count") or 0) for w in workers + solvers]
        stage = st.get("stage") or queue_of.get(code) or ""
        if code in (sched.get("solved") or []) and not st:
            stage = "solved"
        threshold = int(st.get("threshold") or 0)
        challenges.append({
            "code": code,
            "difficulty": (meta.get("difficulty") or "").lower(),
            "level": meta.get("level") or "",
            "description": (meta.get("description") or files["description"] or "")[:240],
            "target": st.get("target") or meta.get("target") or "",
            "container_status": meta.get("container_status") or "",
            "score": meta.get("total_score") or 0,
            "stage": stage,
            "stage_label": _STAGE_LABEL.get(stage, "已解" if stage == "solved" else (stage or "闲置")),
            "threshold": threshold,
            "hint_enabled": bool(st.get("hint_enabled")),
            "hint_ready": files["hint_ready"],
            "flag_correct": ok,
            "flag_total": total,
            "flag_wrong": fc["wrong"],
            "max_count": max(counts) if counts else int((last_runs.get(code) or {}).get("max_count") or 0),
            "running": bool(st),
            "started_at": st.get("started_at"),
            "workers": workers,
            "solvers": solvers,
            "explorer_alive": sum(1 for w in workers if w.get("alive")),
            "solver_alive": sum(1 for w in solvers if w.get("alive")),
            "blackboard_n": files["blackboard_n"],
            "pending_n": len(files["pending_tasks"]),
            "claimed_n": len(files["claimed_tasks"]),
            "last_run": last_runs.get(code),
            "winner": st.get("winner"),
        })

    running = sum(1 for c in challenges if c["running"])
    solved_n = len(sched.get("solved") or [])
    return {
        "ts": time.time(),
        "alive": _alive(heartbeat),
        "local": bool(sched.get("local")),
        "max_active": int(sched.get("max_active") or 0),
        "inflight": int(sched.get("inflight") or running),
        "worker_models": sched.get("worker_models") or [],
        "solver_model": sched.get("solver_model") or "",
        "queues": queues,
        "solved": sched.get("solved") or [],
        "flags_ok": len(store.get("correct") or {}),
        "running": running,
        "solved_n": solved_n,
        "challenges": challenges,
    }


def challenge_detail(code: str) -> Optional[dict[str, Any]]:
    snap = snapshot()
    card = next((c for c in snap["challenges"] if c["code"] == code), None)
    if card is None:
        return None
    files = challenge_files(code)
    store = load_flagstore()
    correct = [
        {"flag": f, "code": c}
        for f, c in (store.get("correct") or {}).items()
        if c == code
    ]
    wrong = list((store.get("wrong") or {}).get(code) or [])
    return {
        **card,
        **files,
        "correct_flags": correct,
        "wrong_flags": wrong,
        "description": files["description"] or card.get("description") or "",
    }


def _logs_from_file(*, after: int, code: str, limit: int) -> dict[str, Any]:
    path = _LOG_FILE
    try:
        size = os.path.getsize(path)
    except OSError:
        return {"items": [], "cursor": after, "source": "none"}
    start = max(0, size - 512_000)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if start:
                f.seek(start)
                f.readline()
            lines = f.readlines()
    except OSError:
        return {"items": [], "cursor": after, "source": "none"}
    items: list[dict[str, Any]] = []
    seq = 0
    for raw in lines:
        seq += 1
        m = _LOG_PREFIX_RE.match(raw.rstrip("\n"))
        if not m:
            continue
        left, right, rest = m.group(1), m.group(2), m.group(3)
        entry_code, worker, text = "", "", raw.rstrip("\n")
        if right:
            entry_code, worker, text = left, right, rest
        else:
            text = rest
            worker = left
        if code and entry_code != code:
            continue
        if seq <= after:
            continue
        if len(text) > 2000:
            text = text[:2000] + "…"
        items.append({
            "seq": seq,
            "t": 0,
            "code": entry_code,
            "worker": worker,
            "text": text,
        })
    if len(items) > limit:
        items = items[-limit:]
    return {"items": items, "cursor": seq, "source": "file"}
