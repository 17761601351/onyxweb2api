"""配置模块 - 使用账号密码登录，自动管理 Token"""

import os
import threading

# ── Onyx 相关固定设置 ──────────────────────────────────────────
ONYX_BASE_URL = "https://cloud.onyx.app"
ONYX_PERSONA_ID = 0
ONYX_ORIGIN = "webapp"
ONYX_REFERER = "https://cloud.onyx.app/app"

# ── 多账号配置（从环境变量读取） ────────────────────────────────
_raw_accounts = os.getenv("ONYX_ACCOUNTS", "")
ONYX_ACCOUNT_LIST = [a.strip() for a in _raw_accounts.split(",") if a.strip()]
ONYX_PASSWORD = os.getenv("ONYX_PASSWORD", "")

if not ONYX_ACCOUNT_LIST:
    print("⚠️ ONYX_ACCOUNTS is empty! Please set it in Secrets.")
if not ONYX_PASSWORD:
    print("⚠️ ONYX_PASSWORD is empty! Please set it in Secrets.")

# ── 动态 Token 列表（由 auth_manager 维护） ─────────────────────
AUTH_TOKEN_LIST = []
_token_index = 0
_token_lock = threading.Lock()


def get_next_token():
    """轮询返回下一个 token"""
    global _token_index
    if not AUTH_TOKEN_LIST:
        raise RuntimeError(
            "No valid auth tokens available! "
            "Check ONYX_ACCOUNTS and ONYX_PASSWORD in Secrets."
        )
    with _token_lock:
        token = AUTH_TOKEN_LIST[_token_index % len(AUTH_TOKEN_LIST)]
        _token_index += 1
    return token


def get_all_tokens_from(start_token):
    """从 start_token 开始返回所有 token 的有序列表"""
    with _token_lock:
        n = len(AUTH_TOKEN_LIST)
        if n == 0:
            return []
        try:
            idx = AUTH_TOKEN_LIST.index(start_token)
        except ValueError:
            idx = 0
        return [AUTH_TOKEN_LIST[(idx + i) % n] for i in range(n)]


# ── 运行时动态添加账号 ─────────────────────────────────────────
_account_lock = threading.Lock()


def add_accounts(emails):
    """动态添加账号到 ONYX_ACCOUNT_LIST（去重），返回新增的账号列表"""
    added = []
    with _account_lock:
        existing = set(ONYX_ACCOUNT_LIST)
        for email in emails:
            e = email.strip()
            if e and e not in existing:
                ONYX_ACCOUNT_LIST.append(e)
                existing.add(e)
                added.append(e)
    return added


def get_all_accounts():
    """返回当前所有账号列表的副本"""
    with _account_lock:
        return list(ONYX_ACCOUNT_LIST)


# ── 服务器设置 ──────────────────────────────────────────────────
API_KEY = os.getenv("API_KEY", "")
PORT = int(os.environ.get("PORT", 8080))
LOG_LEVEL = "INFO"
REQUEST_TIMEOUT = 300

# ── 模型映射 ────────────────────────────────────────────────────
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
