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
# 常见模板占位符（小写）：模型有时把提示词里的 flag 格式示例原样吐出，一律不当真 flag
_PLACEHOLDER_FLAGS = {
    "flag{...}", "flag{flag}", "flag{xxx}", "flag{your_flag_here}", "flag{flag_content}",
    "flag{实际flag内容}", "flag{实际内容}", "实际flag内容", "flag_content", "flag{...}",
}


# 同一段文本里超过这个数量的 flag{...} 视为爆破/枚举输出，禁止自动提交
_AUTO_SUBMIT_MAX_PER_BLOB = 2


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
    """PREFIX{body}：body 只允许 flag 常见字符，拒绝引号/空格/括号等源码碎片。"""
    s = (s or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{2,20}\{[A-Za-z0-9_+\-./:=]{8,300}\}", s):
        return False
    if s.lower() in _PLACEHOLDER_FLAGS:
        return False
    return True


def _submit_flag_directly(code: str, flag: str) -> str:
    """程序化提交一个 flag（复用 tools.submit_flag 的 SDK+重试+标记）。返回其输出字符串。
    仅自动提交走这里；字符集限制也只加在这一层，不拦模型自己调 submit_flag.py。"""
    if not code or not flag or not _looks_like_flag(flag):
        return ""
    try:
        from .tools import submit_flag as _submit_flag_tool
        out = _submit_flag_tool.invoke({"challenge_code": code, "flag": flag})
        return out if isinstance(out, str) else str(out)
    except Exception:
        return ""


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# 黑板 watcher：每个 worker 进程内每 6 步由 LLM 审阅一次最近活动与当前黑板，
# 发现值得共享的新信息则按既定格式追加（机制保障，不依赖 Claude 自觉）。
# ---------------------------------------------------------------------------
_WATCHER_SYSTEM = (
    "你是 CTF 解题会话的黑板观察员。你的职责：审阅某会话最近的操作摘要，维护共享黑板的质量"
    "（提取新关键信息、修正不准确或不完整的条目、删除已被证伪的条目），"
    "并基于当前已知信息为所有会话推荐值得探索的方向。"
    "黑板只记录「什么可行 / 发现了什么」的正向、可复用信息；"
    "绝不记录「什么不可行 / 尝试失败」的负向结论，以免误导其他会话过早放弃可行方向。"
    "绝不把具体 flag 值写入黑板（存在兜底自动提交，错误 flag 会被反复提交）——只记录 flag 是如何拿到的（详细方法）。"
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
    "写入黑板——存在兜底提交机制会自动抓取黑板里的 flag 反复提交，写错的 flag 会导致无休止地重复错误提交。"
    "应改为详细记录「这个 flag 是怎么拿到的」：用到的漏洞点、请求/参数/payload、文件路径、关键命令与步骤，"
    "写清楚到足以让其他会话复现（尤其多 flag 题据此找剩余 flag）；\n"
    "   重要：不要记录负向/排除性结论或失败尝试——例如「xx payload 无效」「基础注入失败」「爆破未成功」"
    "「该路径不存在/404」「xx 被过滤」等一切「什么不行」的内容一律不写，"
    "因为它们可能误导其他会话过早放弃本可行的方向；只有当某个过滤/限制已连同「确认可行的绕过」一起给出时，"
    "才作为正向信息记录（重点写可行的绕过，而非限制本身）；\n"
    "   黑板上已存在的条目（含大小写差异、尾部斜杠等变体）不要重复；每条不超过 50 字，一次最多 3 条；\n"
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


# 进程级已尝试提交的 flag 去重（避免 watcher 每次触发都重复提交同一 flag）
_ATTEMPTED_FLAGS: "set[str]" = set()
_ATTEMPTED_FLAGS_LOCK = threading.Lock()


def _watcher_try_submit_flags(code: str, worker_id: str, *texts: str) -> Optional[str]:
    """watcher 兜底提交：从给定文本中提取 flag{...} 候选，进程内去重后程序化提交。

    命中平台确认时，打印 [WATCHER SUBMIT]（调度器只认平台确认标记，不认裸 {"flag"} JSON）。
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
    for cand in sorted(cands, key=len, reverse=True):
        key = f"{code}|{cand}"
        with _ATTEMPTED_FLAGS_LOCK:
            if key in _ATTEMPTED_FLAGS:
                continue
            _ATTEMPTED_FLAGS.add(key)
        out = _submit_flag_directly(code, cand)
        if any(marker in out for marker in _FLAG_OK_MARKERS):
            js = json.dumps({"flag": cand}, ensure_ascii=False)
            try:
                print(f"\x1b[95;1m[WATCHER SUBMIT] 会话 {worker_id} 从黑板/活动补交成功: {cand}\x1b[0m", flush=True)
                print(js, flush=True)
            except Exception:
                pass
            return js
    return None


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
            .replace("{activity}", activity[-4000:])
            .replace("{blackboard}", numbered[-4000:])
            .replace("{tasks}", tasks_text[-1500:])
            .replace("{claimed_tasks}", claimed_text[-1000:])
        )
        # 题目描述 + 提示（若已获取）：让 watcher 结合它们策展黑板、发布更贴合的探索方向
        context_header = ""
        try:
            with open(os.path.join(reports_dir, f"desc_{code}.txt"), "r", encoding="utf-8") as f:
                _desc = f.read().strip()
            if _desc:
                context_header += f"【题目描述】\n{_desc[:1500]}\n\n"
        except Exception:
            pass
        try:
            with open(os.path.join(reports_dir, f"hint_{code}.txt"), "r", encoding="utf-8") as f:
                _hint = f.read().strip()
            if _hint:
                context_header += f"【题目提示】\n{_hint[:1500]}\n\n"
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

                # 删除：按内容模糊匹配
                for target in removes:
                    idx = _find_best_match(entries, target)
                    if idx is not None:
                        entries.pop(idx)
                        changed = True

                # 修正：保留原头部（时间戳/会话归属），替换信息内容
                for u in updates:
                    idx = _find_best_match(entries, str(u["old"]))
                    if idx is not None:
                        entries[idx]["info"] = str(u["new"]).strip()
                        changed = True

                # 新增：程序化去重后追加
                for info in adds:
                    if _find_best_match(entries, info) is not None:
                        continue
                    entries.append({
                        "header": f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 会话: {worker_id}",
                        "info": info,
                    })
                    changed = True

                if not changed:
                    return
                sep = "-" * 60
                tmp_path = info_path + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    for e in entries:
                        f.write(f"{e['header']}\n")
                        f.write(f"关键信息: {e['info']}\n")
                        f.write(sep + "\n")
                os.replace(tmp_path, info_path)
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
    """运行一个 Claude 会话直至出 flag / 达到轮数上限 / 被外部杀死。

    step_counter 为跨会话共享的单元素列表：[COUNT] 计数在多次会话间单调递增，
    保证 main.py 调度器的步数阈值（可超过单会话 100 轮上限）能够触发。
    返回确认后的 flag JSON 字符串；未解出返回 None。
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
    confirmed_flag: Optional[str] = None       # 平台确认正确的那个 flag
    flag_candidates: "set[str]" = set()        # 会话中出现过的合法 flag 候选（供权威校验）
    verified: "set[str]" = set()               # 已由框架向平台核实过的候选（去重，避免重复提交）
    # 黑板 watcher 状态：滚动活动摘要 + 单 watcher 并发闸
    recent: deque[str] = deque(maxlen=12)
    watcher_state = {"busy": False}

    def _verify_flag(cand: str) -> bool:
        """权威校验：由框架亲自向平台提交该 flag，仅当平台回 correct/duplicate 才算真。
        不信任模型输出/文本标记；对同一候选只核实一次。"""
        if not code or not cand or not _looks_like_flag(cand) or cand in verified:
            return False
        verified.add(cand)
        out = _submit_flag_directly(code, cand)
        return any(marker in out for marker in _FLAG_OK_MARKERS)

    def _maybe_trigger_watcher() -> None:
        if not code or watcher_state["busy"]:
            return
        watcher_state["busy"] = True
        activity_snapshot = "\n".join(recent)

        def _job() -> None:
            try:
                _watcher_curate_blackboard(code, worker_id, activity_snapshot)
            finally:
                watcher_state["busy"] = False

        threading.Thread(target=_job, daemon=True).start()

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
                submitted = _capture_submitted_flag(msg)
                if submitted and _looks_like_flag(submitted):
                    last_submitted_flag = submitted
                    flag_candidates.add(submitted)
                    # 权威校验：模型一提交 flag，框架就亲自向平台核实（不信任文本标记/占位符）
                    if flag_json is None and _verify_flag(submitted):
                        confirmed_flag = submitted
                        flag_json = json.dumps({"flag": submitted}, ensure_ascii=False)
                        break
                # 文本里的 flag{...} 只收集、不当场交（源码/爆破输出会误匹配）
                blob = _unique_flag_cands(text or "")
                if len(blob) <= _AUTO_SUBMIT_MAX_PER_BLOB:
                    flag_candidates.update(blob)
                if not quiet:
                    for t in tools:
                        print(f"[TOOL] {t}", flush=True)
                    if text.strip():
                        # 压成单行，避免 Thought 里的 JSON 被父进程按行误判为最终 {"flag"}
                        preview = text.strip()[:300].replace("\n", " ").replace("\r", " ")
                        print(f"[Claude] {preview}", flush=True)
                # 记录活动摘要供 watcher 审阅
                digest_parts = []
                if text.strip():
                    digest_parts.append("Thought: " + text.strip()[:300])
                digest_parts.extend("Action: " + t for t in tools)
                if digest_parts:
                    recent.append("\n".join(digest_parts))
                # 每 6 步触发一次黑板 watcher（后台线程，不阻塞流解析）
                if session_step % 6 == 0:
                    _maybe_trigger_watcher()
            elif etype == "user":
                msg = evt.get("message") or {}
                for rt in _iter_tool_result_texts(msg):
                    blob = _unique_flag_cands(rt or "")
                    if len(blob) <= _AUTO_SUBMIT_MAX_PER_BLOB:
                        flag_candidates.update(blob)
                    if rt.strip():
                        recent.append("Observation: " + rt.strip()[:400])
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
        # 收尾：会话结束（出 flag / 达轮数上限 / 自然结束）时强制再采集一次，
        # 补齐"最后一次周期 watcher 之后"到会话结束之间的尾部新发现（否则会漏采）。
        # 同步执行但带超时：避免子进程退出前 daemon watcher 线程被杀导致丢失，同时防止 LLM 卡死拖住回收。
        if code and recent:
            snapshot = "\n".join(recent)
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
    # 会话结束：对所有合法候选做权威校验（框架亲自提交，平台 correct/duplicate 才算），命中即返回。
    # 覆盖"flag 在最后一回合找到、提交命令被 --max-turns 切断"及"标记出现但未当场校验"等情况。
    if code:
        for cand in sorted((c for c in flag_candidates if _looks_like_flag(c)), key=len, reverse=True):
            if _verify_flag(cand):
                try:
                    print(f"\x1b[95;1m[FLAG RECOVERED] 会话结束后程序化补交成功: {cand}\x1b[0m", flush=True)
                except Exception:
                    pass
                return json.dumps({"flag": cand}, ensure_ascii=False)
    return None


def run_auto_scan(target: str, max_steps: int = 0, quiet: bool = False, hint: Optional[str] = None, challenge_code: Optional[str] = None, solver_task: Optional[str] = None) -> str:
    """运行 Claude Code 自动扫描，直到拿到平台确认的 flag（或被外部调度器终止）。

    与旧 ReAct 引擎语义一致：
    - 返回值为含 flag 字段的 JSON 字符串；
    - max_steps 不在此强制终止（步数阈值由 main.py 调度器通过 [COUNT] 监控执行）；
    - 每个会话结束（默认不限制轮数，自然结束或达到上下文上限）后，基于黑板成果开启新会话继续。

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
            print(f"[Session] 第 {attempt} 个会话未解出（{_limit_desc}），基于黑板成果开启新会话…", flush=True)
        except Exception:
            pass
