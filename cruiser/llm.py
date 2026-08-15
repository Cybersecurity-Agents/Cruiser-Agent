from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Optional, Tuple

# ---------------------------------------------------------------------------
# LLM 提供方配置（单一事实源，表驱动）
#
# 原则：
#   1. 所有密钥一律从环境变量读取（可在项目根目录 .env 配置），源码中不含任何硬编码密钥。
#   2. 提供方（provider）由「模型名前缀」映射决定，见 MODEL_PREFIX_TO_PROVIDER。
#   3. 每个提供方的端点/密钥环境变量集中登记在 PROVIDERS 注册表里；
#      新接一家：在 PROVIDERS 增一条 + 在 MODEL_PREFIX_TO_PROVIDER 增前缀即可，无需改调用方。
#
# 当前登记：
#   - deepseek：解题引擎(claude CLI) 与 watcher 默认；
#   - kimi(moonshot)：worker/watcher 指定 kimi-* 模型时自动路由；
#   - glm(腾讯 TokenHub)：worker/watcher 指定 glm-* 模型时自动路由。
#     默认走比赛内网网关（tokenhub.tencentmaas.com.tsecbench.gw），--local 切回
#     TokenHub 公网 https 端点；亦可用 GLM_ANTHROPIC_BASE_URL / GLM_BASE_URL 覆盖。
# ---------------------------------------------------------------------------

# 默认模型（可分别用环境变量覆盖）
DEFAULT_SOLVE_MODEL = "deepseek-v4-flash"     # 解题引擎默认模型
DEFAULT_WATCHER_MODEL = "deepseek-v4-pro"     # 黑板 watcher 默认模型（策展需更强推理）


@dataclass(frozen=True)
class ProviderConfig:
    """一家 LLM 提供方的接入配置。端点地址支持用对应环境变量覆盖默认值。"""
    name: str
    api_key_env: str              # 密钥环境变量名
    anthropic_base_url: str       # Anthropic 兼容端点默认地址（claude CLI 用）
    openai_base_url: str          # OpenAI 兼容端点默认地址（langchain watcher 用）
    anthropic_base_url_env: str   # 覆盖 Anthropic 端点的环境变量名
    openai_base_url_env: str      # 覆盖 OpenAI 端点的环境变量名
    anthropic_base_url_local: str = ""  # 本地测试端点（--local / CRUISER_LOCAL=1 时用；原始官方域名）
    openai_base_url_local: str = ""     # 同上（OpenAI 兼容）
    max_context_tokens: int = 1_000_000    # 模型真实上下文窗口（供 claude CLI 校正 auto-compact）
    auto_compact_window: int = 800_000     # 提前触发上下文压缩的阈值


def _local_mode() -> bool:
    """本地测试模式：走原始官方 https 域名而非比赛内网 .tsecbench.gw 域名。
    由 main.py 的 --local 参数设置 CRUISER_LOCAL=1 开启。"""
    return (os.environ.get("CRUISER_LOCAL", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _resolve_anthropic_base_url(cfg: "ProviderConfig") -> str:
    """Anthropic 端点解析：显式环境变量覆盖 > 本地模式原域名 > 默认(比赛内网)域名。"""
    override = os.environ.get(cfg.anthropic_base_url_env)
    if override:
        return override
    if _local_mode() and cfg.anthropic_base_url_local:
        return cfg.anthropic_base_url_local
    return cfg.anthropic_base_url


def _resolve_openai_base_url(cfg: "ProviderConfig") -> str:
    """OpenAI 兼容端点解析：显式环境变量覆盖 > 本地模式原域名 > 默认(比赛内网)域名。"""
    override = os.environ.get(cfg.openai_base_url_env)
    if override:
        return override
    if _local_mode() and cfg.openai_base_url_local:
        return cfg.openai_base_url_local
    return cfg.openai_base_url


# 提供方注册表：provider 名 -> 配置
PROVIDERS: dict[str, ProviderConfig] = {
    "deepseek": ProviderConfig(
        name="deepseek",
        api_key_env="DEEPSEEK_API_KEY",
        anthropic_base_url="http://api.deepseek.com.tsecbench.gw/anthropic",
        openai_base_url="http://api.deepseek.com.tsecbench.gw/v1",
        anthropic_base_url_env="ANTHROPIC_BASE_URL",
        openai_base_url_env="DEEPSEEK_BASE_URL",
        anthropic_base_url_local="https://api.deepseek.com/anthropic",
        openai_base_url_local="https://api.deepseek.com/v1",
    ),
    # Kimi / Moonshot（国内域名；国际站为 api.moonshot.ai，可用下列 *_env 覆盖）
    "kimi": ProviderConfig(
        name="kimi",
        api_key_env="KIMI_API_KEY",
        anthropic_base_url="http://api.moonshot.cn.tsecbench.gw/anthropic",
        openai_base_url="http://api.moonshot.cn.tsecbench.gw/v1",
        anthropic_base_url_env="KIMI_ANTHROPIC_BASE_URL",
        openai_base_url_env="KIMI_BASE_URL",
        anthropic_base_url_local="https://api.moonshot.cn/anthropic",
        openai_base_url_local="https://api.moonshot.cn/v1",
    ),
    # GLM（智谱）经腾讯 TokenHub 聚合网关：统一兼容 Anthropic Messages 与 OpenAI Chat 协议。
    # Anthropic 协议鉴权头为 x-api-key（与 ANTHROPIC_AUTH_TOKEN 发送方式一致）；
    # OpenAI 协议为 Authorization: Bearer（langchain ChatOpenAI 默认）。key 通用。
    "glm": ProviderConfig(
        name="glm",
        api_key_env="GLM_API_KEY",
        anthropic_base_url="http://tokenhub.tencentmaas.com.tsecbench.gw",
        openai_base_url="http://tokenhub.tencentmaas.com.tsecbench.gw/v1",
        anthropic_base_url_env="GLM_ANTHROPIC_BASE_URL",
        openai_base_url_env="GLM_BASE_URL",
        anthropic_base_url_local="https://tokenhub.tencentmaas.com",
        openai_base_url_local="https://tokenhub.tencentmaas.com/v1",
        # TokenHub 文档：glm-5.3 / glm-5.2 上下文 1M、最大输出 128K，与 DeepSeek 同规格。
        # 注意 glm-5.1 / glm-5 / glm-5-turbo 仅 200K：使用这些老模型时请显式设置
        # CLAUDE_CODE_MAX_CONTEXT_TOKENS=200000（与 AUTO_COMPACT_WINDOW 相应调低）。
        max_context_tokens=1_000_000,
        auto_compact_window=800_000,
    ),
}

# 模型名前缀 -> 提供方（小写匹配）。命中即路由到该提供方；都不命中用 DEFAULT_PROVIDER。
MODEL_PREFIX_TO_PROVIDER: dict[str, str] = {
    "deepseek": "deepseek",
    "kimi": "kimi",
    "moonshot": "kimi",
    "glm": "glm",
    "chatglm": "glm",
    "zhipu": "glm",
}
DEFAULT_PROVIDER = "deepseek"

_GLM_MODEL_RE = re.compile(r"^glm-?(\d.*)$", re.IGNORECASE)


def _normalize_glm_model(model: str) -> str:
    """glm 模型名规范化：TokenHub 模型 ID 为 glm-5.3 形式，容忍 glm5.3 / GLM5.3 写法。"""
    m = _GLM_MODEL_RE.match((model or "").strip())
    return f"glm-{m.group(1)}" if m else model


# ---------------------------------------------------------------------------
# 提供方解析
# ---------------------------------------------------------------------------
def provider_for_model(model: str) -> str:
    """按模型名判定提供方：命中 MODEL_PREFIX_TO_PROVIDER 中任一前缀即用其映射，否则默认。"""
    m = (model or "").lower()
    for prefix, provider in MODEL_PREFIX_TO_PROVIDER.items():
        if m.startswith(prefix) or prefix in m:
            return provider
    return DEFAULT_PROVIDER


def get_provider_config(name: str) -> ProviderConfig:
    return PROVIDERS.get(name) or PROVIDERS[DEFAULT_PROVIDER]


def _provider_api_key(cfg: ProviderConfig) -> str:
    return (os.environ.get(cfg.api_key_env) or "").strip()


def get_deepseek_api_key() -> str:
    """DeepSeek 密钥（仅从环境变量读取，缺失返回空串）。"""
    return _provider_api_key(PROVIDERS["deepseek"])


def get_kimi_api_key() -> str:
    """Kimi / Moonshot 密钥（仅从环境变量读取，缺失返回空串）。"""
    return _provider_api_key(PROVIDERS["kimi"])


def get_glm_api_key() -> str:
    """GLM（腾讯 TokenHub）密钥（仅从环境变量读取，缺失返回空串）。"""
    return _provider_api_key(PROVIDERS["glm"])


def get_solve_model() -> str:
    """解题引擎（claude CLI）使用的模型。

    优先级：CRUISER_MODEL > ANTHROPIC_MODEL > DEEPSEEK_MODEL > 默认。
    glm 系模型名做规范化（glm5.3 -> glm-5.3），以匹配 TokenHub 的模型 ID。
    """
    model = os.environ.get("CRUISER_MODEL") or os.environ.get("ANTHROPIC_MODEL") or os.environ.get("DEEPSEEK_MODEL") or DEFAULT_SOLVE_MODEL
    if provider_for_model(model) == "glm":
        return _normalize_glm_model(model)
    return model


def get_watcher_model() -> str:
    """黑板 watcher 使用的模型（WATCHER_MODEL 覆盖，默认 deepseek-v4-pro）。glm 系做规范化。"""
    model = os.environ.get("WATCHER_MODEL", DEFAULT_WATCHER_MODEL)
    if provider_for_model(model) == "glm":
        return _normalize_glm_model(model)
    return model


def get_context_defaults(model: str) -> tuple[int, int]:
    """返回 (最大上下文 token 数, auto-compact 触发窗口) 的提供方默认值。

    供 claude_agent._claude_env 对 CLAUDE_CODE_MAX_CONTEXT_TOKENS /
    CLAUDE_CODE_AUTO_COMPACT_WINDOW 做 setdefault：DeepSeek 1M 窗口，GLM 约 200K。
    用户显式设置的环境变量始终优先。
    """
    cfg = get_provider_config(provider_for_model(model))
    return cfg.max_context_tokens, cfg.auto_compact_window


# ---------------------------------------------------------------------------
# 解题引擎：claude CLI 的 Anthropic 兼容端点配置
# ---------------------------------------------------------------------------
def get_claude_provider_env() -> dict[str, str]:
    """返回 claude CLI 接入 Anthropic 兼容端点所需的环境变量。

    只负责"连哪个模型/端点/用哪把 key"这一层；claude 运行期开关（沙箱、上下文
    压缩窗口、逆向环境等）由 claude_agent._claude_env 负责，二者职责分离。
    提供方按模型名自动路由；密钥取该提供方密钥，缺失时回退显式的 ANTHROPIC_AUTH_TOKEN。
    """
    model = get_solve_model()
    cfg = get_provider_config(provider_for_model(model))
    base_url = _resolve_anthropic_base_url(cfg)
    key = (_provider_api_key(cfg) or os.environ.get("ANTHROPIC_AUTH_TOKEN") or "").strip()
    return {
        "ANTHROPIC_BASE_URL": base_url,
        "ANTHROPIC_AUTH_TOKEN": key,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_SMALL_FAST_MODEL": model,
    }


# ---------------------------------------------------------------------------
# langchain（watcher / 旧 ReAct 引擎）：OpenAI 兼容端点
# ---------------------------------------------------------------------------
def _compute_temperature() -> float:
    """根据并发会话编号与总数，按序号从低到高分配温度（仅 langchain 路径使用）。

    - 当 CRUISER_SESSIONS<=1 或未设置时，返回 CRUISER_TEMP_MIN（默认 0.0）。
    - 线性区间 [CRUISER_TEMP_MIN, CRUISER_TEMP_MAX]，按 worker_id 在 [1..sessions] 等分。
    """
    try:
        wid = int(os.environ.get("CRUISER_WORKER_ID", "1") or "1")
    except Exception:
        wid = 1
    try:
        total = int(os.environ.get("CRUISER_SESSIONS", "1") or "1")
    except Exception:
        total = 1
    try:
        tmin = float(os.environ.get("CRUISER_TEMP_MIN", "0.0") or "0.0")
    except Exception:
        tmin = 0.0
    try:
        tmax = float(os.environ.get("CRUISER_TEMP_MAX", "0.9") or "0.9")
    except Exception:
        tmax = 0.9
    if total <= 1:
        return max(0.0, min(1.0, tmin))
    wid = max(1, min(wid, total))
    step = (tmax - tmin) / max(1, total - 1)
    temp = tmin + (wid - 1) * step
    return max(0.0, min(1.0, temp))


def _build_chat_openai(model: str, temperature: Optional[float]) -> Optional[Any]:
    """构造一个 OpenAI 兼容的 langchain ChatOpenAI 实例（watcher / 旧引擎用）。

    提供方按模型名自动路由（端点与密钥取自 PROVIDERS 注册表）。
    无密钥或依赖缺失/构造失败时返回 None（不抛异常）。
    temperature 为 None 时不传该参数（交由服务端默认）。
    """
    cfg = get_provider_config(provider_for_model(model))
    key = _provider_api_key(cfg)
    if not key:
        return None
    base_url = _resolve_openai_base_url(cfg)
    try:
        from langchain_openai import ChatOpenAI  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    kwargs: dict = {"model": model, "base_url": base_url, "api_key": key}
    if temperature is not None:
        kwargs["temperature"] = temperature
    try:
        return ChatOpenAI(**kwargs)
    except Exception:  # noqa: BLE001
        return None


def get_llm() -> Tuple[Optional[Any], str, bool]:
    """解题用 langchain 模型（旧 ReAct 引擎路径；当前主引擎为 claude CLI，通常不走此处）。

    返回三元组 (llm, provider, supports_tool_calls)；无可用密钥/依赖时返回 (None, "none", False)。
    标记不支持原生 tool calling，走 JSON 决策路径。
    """
    model = os.environ.get("DEEPSEEK_MODEL", DEFAULT_SOLVE_MODEL)
    llm = _build_chat_openai(model, _compute_temperature())
    if llm is None:
        return None, "none", False
    return llm, provider_for_model(model), False


def get_watcher_llm() -> Tuple[Optional[Any], str, bool]:
    """黑板 watcher（策展/任务发布）专用 LLM，默认 DeepSeek deepseek-v4-pro（WATCHER_MODEL 覆盖）。

    模型为 kimi-* 时自动走 Kimi 端点。WATCHER_TEMPERATURE 未设置时不传温度。
    无密钥时回退 get_llm()。
    """
    temp_env = os.environ.get("WATCHER_TEMPERATURE", "").strip()
    try:
        temperature: Optional[float] = float(temp_env) if temp_env else None
    except Exception:
        temperature = None
    model = get_watcher_model()
    llm = _build_chat_openai(model, temperature)
    if llm is None:
        return get_llm()
    return llm, model, False
