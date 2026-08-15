#!/usr/bin/env python
"""命令行提交 flag（供 Claude Code 引擎在解题过程中调用）。

用法:
    python tools/submit_flag.py <challenge_code> <flag>

输出与 cruiser.tools.submit_flag 工具一致，包含平台确认标记：
- 「提交flag正确」/「已经提交成功过了」表示平台确认成功
- 其他输出表示失败或错误
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cruiser.tools import submit_flag as _submit_flag_tool


def main() -> int:
    if len(sys.argv) < 3:
        print("用法: python tools/submit_flag.py <challenge_code> <flag>")
        return 2
    challenge_code = sys.argv[1]
    flag = sys.argv[2]
    out = _submit_flag_tool.invoke({"challenge_code": challenge_code, "flag": flag})
    print(out if isinstance(out, str) else str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
