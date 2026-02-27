"""配置模块 - 使用账号密码登录，自动管理 Token"""

import os
import threading
import logging

logger = logging.getLogger(__name__)

# --- Onyx settings (固定值) ---
ONYX_BASE_URL = "https://cloud.onyx.app"
ONYX_PERSONA_ID = 0
ONYX_ORIGIN = "webapp"
ONYX_REFERER = "https://cloud.onyx.app/app"

# --- 多账号（账号密码登录）---
_raw_accounts = os.getenv("ONYX_ACCOUNTS", "")
ONYX_ACCOUNT_LIST = [a.strip() for a in _raw_accounts.split(",") if a.strip()]
ONYX_PASSWORD = os.getenv("ONYX_PASSWORD", "")

if not ONYX_ACCOUNT_LIST:
    logger.warning("⚠️ ONYX_ACCOUNTS is empty! Please set it in Secrets.")
if not ONYX_PASSWORD:
    logger.warning("⚠️ ONYX_PASSWORD is empty! Please set it in Secrets.")

# --- 动态 Token 列表（由 auth_manager 维护）---
# AUTH_TOKEN_LIST 现在是动态的，通过 auth_manager 获取
AUTH_TOKEN_LIST: list = []

# 线程安全的轮询索引
_token_index = 0
_token_lock = threading.Lock()


def get_next_token() -> str:
    """轮询返回下一个 token，如果没有 token 则抛出异常"""
    global _token_index
    if not AUTH_TOKEN_LIST:
        raise RuntimeError(
            "No valid auth tokens available! Check ONYX_ACCOUNTS and ONYX_PASSWORD in Secrets."
        )
    with _token_lock:
        token = AUTH_TOKEN_LIST[_token_index % len(AUTH_TOKEN_LIST)]
        _token_index += 1
        return token


def get_all_tokens_from(start_token: str) -> list:
    """从 start_token 开始，返回所有 token 的有序列表"""
    if not AUTH_TOKEN_LIST:
        return []
    try:
        idx = AUTH_TOKEN_LIST.index(start_token)
    except ValueError:
        idx = 0
    n = len(AUTH_TOKEN_LIST)
    return [AUTH_TOKEN_LIST[(idx + i) % n] for i in range(n)]


# --- Server settings ---
API_KEY = os.getenv("API_KEY", "")
# config.py 修改后
PORT = int(os.environ.get("PORT", 8080))
LOG_LEVEL = "INFO"
REQUEST_TIMEOUT = 300

# --- Model mapping ---
MODEL_MAP = {
    "claude-opus-4.6": ("Anthropic", "claude-opus-4-6"),
    "claude-opus-4.5": ("Anthropic", "claude-opus-4-5"),
    "claude-sonnet-4.5": ("Anthropic", "claude-sonnet-4-5"),
    "gpt-5.2": ("OpenAI", "gpt-5.2"),
    "gpt-5-mini": ("OpenAI", "gpt-5-mini"),
    "gpt-4.1": ("OpenAI", "gpt-4.1"),
    "gpt-4o": ("OpenAI", "gpt-4o"),
    "o3": ("OpenAI", "o3"),

}

