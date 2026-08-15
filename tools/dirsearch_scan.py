#!/usr/bin/env python
"""跨会话去重的目录扫描（供 Claude Code worker 调用，替代直接运行 dirsearch）。

多个会话对同一 URL 调用时，仅有一个实际执行 dirsearch，其余阻塞等待并复用其报告，
避免对同一靶场重复扫描、浪费时间与触发目标限流。

用法:
    python tools/dirsearch_scan.py <url>

行为与 cruiser.tools.dirsearch_scan 一致：
- 结果按规范化 URL 的 sha256 缓存于 /tmp/cruiser_dirsearch_cache；
- 首个调用者持锁执行一次（内置 -i 200,301,302 --format=plain），其余会话等待缓存出结果（最多 5 分钟）；
- 标准输出打印报告纯文本内容。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cruiser.tools import dirsearch_scan as _dirsearch_scan_tool


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python tools/dirsearch_scan.py <url>")
        return 2
    url = sys.argv[1]
    out = _dirsearch_scan_tool.invoke({"url": url})
    print(out if isinstance(out, str) else str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
