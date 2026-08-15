#!/usr/bin/env python
"""探索方向任务板命令行（供 Claude Code worker 调用）。

用法:
    python tools/task_board.py list <code>                        # 查看待认领方向
    python tools/task_board.py claim <code> <worker_id> [task_id] # 认领（认领即擦除；不带 id 认领第一条）
    python tools/task_board.py report <code> <worker_id> <结果>   # 回报完成情况（写入共享黑板）

claim 成功时打印该方向内容并以退出码 0 结束；没有可认领方向时退出码 3。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cruiser.taskboard import claim_task, list_tasks, report_task


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    action, code = sys.argv[1], sys.argv[2]

    if action == "list":
        tasks = list_tasks(code)
        if not tasks:
            print("（当前没有待认领的探索方向）")
            return 0
        for t in tasks:
            print(f"{t['id']}: {t['text']}")
        return 0

    if action == "claim":
        if len(sys.argv) < 4:
            print("用法: python tools/task_board.py claim <code> <worker_id> [task_id]")
            return 2
        worker_id = sys.argv[3]
        task_id = sys.argv[4] if len(sys.argv) > 4 else None
        # 容错：worker 可能把 task_id 放到了 worker_id 的位置（claim <code> t-xxxxxx）
        import re as _re
        if _re.fullmatch(r"t-[0-9a-f]{6}", worker_id or "") and task_id is None:
            task_id = worker_id
            worker_id = os.environ.get("CRUISER_WORKER_ID", "unknown")
        claimed = claim_task(code, worker_id, task_id)
        if claimed is None:
            print("没有可认领的方向（或该方向已被其他会话认领）")
            return 3
        print(f"已认领 {claimed['id']}: {claimed['text']}")
        print("完成后请执行: python tools/task_board.py report <code> <worker_id> '<完成情况>'")
        return 0

    if action == "report":
        if len(sys.argv) < 5:
            print("用法: python tools/task_board.py report <code> <worker_id> <完成情况>")
            return 2
        worker_id = sys.argv[3]
        text = sys.argv[4]
        if report_task(code, worker_id, text):
            print("已回报，结果已共享到黑板")
            return 0
        return 1

    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
