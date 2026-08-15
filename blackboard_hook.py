#!/usr/bin/env python
"""Claude Code 钩子：把题目描述/提示/共享黑板硬性注入会话上下文（不依赖模型自觉读取）。

- SessionStart：会话开始时注入一次题目描述 + 题目提示 + 当前黑板（各若非空）
- PostToolUse：按工具调用计数，每 10 次注入一次最新内容（约等于每 10 步）

题目代码从环境变量 CRUISER_CHALLENGE_CODE 获取（worker/solver 进程已注入）。
输出 hookSpecificOutput.additionalContext；无内容可注入时不输出任何东西。
"""
from __future__ import annotations

import json
import os
import sys

_MAX_INJECT_CHARS = 3000


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    event = payload.get("hook_event_name") or ""
    code = os.environ.get("CRUISER_CHALLENGE_CODE", "")
    if not code or event not in ("SessionStart", "PostToolUse"):
        return 0

    root = os.path.dirname(os.path.abspath(__file__))
    reports = os.path.join(root, "reports")
    desc_path = os.path.join(reports, f"desc_{code}.txt")
    hint_path = os.path.join(reports, f"hint_{code}.txt")
    info_path = os.path.join(reports, f"info_{code}.txt")

    def build_context() -> str:
        """组装注入内容：题目描述 + 题目提示 + 共享黑板（均为空则不注入）。"""
        parts = []
        desc = _read_text(desc_path)
        if desc:
            parts.append(f"【题目描述】\n{desc[:_MAX_INJECT_CHARS]}")
        hint = _read_text(hint_path)
        if hint:
            parts.append(f"【题目提示（已按比例扣分获取，请充分利用）】\n{hint[:_MAX_INJECT_CHARS]}")
        bb = _read_text(info_path)
        if bb:
            parts.append(f"【共享黑板当前内容】\n{bb[-_MAX_INJECT_CHARS:]}")
        return "\n\n".join(parts)

    def emit(ctx: str) -> None:
        print(json.dumps(
            {"hookSpecificOutput": {"hookEventName": event, "additionalContext": ctx}},
            ensure_ascii=False,
        ))

    if event == "SessionStart":
        ctx = build_context()
        if ctx:
            emit(ctx)
        return 0

    # PostToolUse：每 10 次工具调用注入一次
    session = payload.get("session_id") or "unknown"
    counter_path = f"/tmp/cruiser_bbhook_{session}.count"
    try:
        with open(counter_path, "r") as f:
            n = int(f.read().strip()) + 1
    except Exception:
        n = 1
    try:
        with open(counter_path, "w") as f:
            f.write(str(n))
    except Exception:
        pass
    if n % 10 == 0:
        ctx = build_context()
        if ctx:
            emit(f"（以下内容每 10 步自动注入，请关注并利用其他会话的新发现）\n{ctx}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
