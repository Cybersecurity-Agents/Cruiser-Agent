"""Cruiser package init.

全局禁用 LangSmith/LangChain 追踪以避免外网请求与配额问题。
在导入任何子模块前执行，确保子进程默认也继承禁用状态。

"""

from __future__ import annotations

import os


# 强制关闭追踪（覆盖外部环境设置）
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

# 同时移除可能存在的 API Key，避免误触发 SDK 初始化
for _k in ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"):
    os.environ.pop(_k, None)


def _load_dotenv() -> None:
    """加载项目根目录的 .env（若存在）；不覆盖已存在的环境变量。

    用于提供 BENCHMARK_BASE_URL / BENCHMARK_TOKEN 等配置，
    保证 main.py 及其 spawn 的子进程都能拿到凭证。
    """
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env_path = os.path.join(root, ".env")
        if not os.path.exists(env_path):
            return
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


_load_dotenv()




__all__ = [
    "tools",
]
