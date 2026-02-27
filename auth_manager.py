"""
账号认证管理器
- 多账号自动登录 cloud.onyx.app 获取 fastapiusersauth
- 每个账号使用不同的浏览器指纹
- 每 2 小时自动检测 Token 可用性，失效自动重新登录
- 提供手动检测/刷新 API
- 支持运行时动态添加账号
"""

import asyncio
import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import httpx

import config
import stats

logger = logging.getLogger(__name__)

# ── 浏览器指纹生成 ──────────────────────────────────────────────

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
]

_ACCEPT_LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "ja,en-US;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "zh-TW,zh;q=0.9,en-US;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
]

_SEC_CH_UA_POOL = [
    '"Chromium";v="131", "Not_A Brand";v="24"',
    '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    '"Chromium";v="130", "Not_A Brand";v="24"',
    '"Google Chrome";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
    '"Microsoft Edge";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
    '"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    '"Google Chrome";v="132", "Chromium";v="132", "Not_A Brand";v="24"',
    '"Chromium";v="132", "Not_A Brand";v="24"',
    '"Microsoft Edge";v="131", "Chromium";v="131"',
    '"Google Chrome";v="131", "Not_A Brand";v="24"',
    '"Brave";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
]

_PLATFORM_POOL = [
    '"Windows"', '"Windows"', '"Windows"', '"Windows"', '"Windows"',
    '"macOS"', '"macOS"', '"macOS"', '"macOS"',
    '"Linux"', '"Linux"', '"Linux"',
]


def _generate_fingerprint(account_email: str, index: int) -> dict:
    seed_str = f"{account_email}:{index}:fingerprint_salt_v1"
    seed_hex = hashlib.sha256(seed_str.encode()).hexdigest()[:8]
    seed_int = int(seed_hex, 16)

    ua = _UA_POOL[seed_int % len(_UA_POOL)]
    lang = _ACCEPT_LANGUAGE_POOL[(seed_int >> 4) % len(_ACCEPT_LANGUAGE_POOL)]
    sec_ua = _SEC_CH_UA_POOL[(seed_int >> 8) % len(_SEC_CH_UA_POOL)]
    plat = _PLATFORM_POOL[(seed_int >> 12) % len(_PLATFORM_POOL)]

    return {
        "user-agent": ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": lang,
        "accept-encoding": "gzip, deflate, br",
        "origin": "https://cloud.onyx.app",
        "referer": "https://cloud.onyx.app/auth/login",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-ch-ua": sec_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": plat,
        "dnt": "1" if seed_int % 3 == 0 else "0",
        "connection": "keep-alive",
    }


# ── 账号状态数据类 ───────────────────────────────────────────────

@dataclass
class AccountState:
    email: str
    index: int
    token: Optional[str] = None
    fingerprint: Dict[str, str] = field(default_factory=dict)
    last_login_time: Optional[float] = None
    last_check_time: Optional[float] = None
    status: str = "pending"  # pending / active / expired / error
    error_msg: Optional[str] = None
    disabled: bool = False


# ── 认证管理器 ───────────────────────────────────────────────────

class AuthManager:
    CHECK_INTERVAL = 2 * 60 * 60  # 2 小时

    def __init__(self):
        self._accounts: Dict[str, AccountState] = {}
        self._lock = threading.Lock()
        self._check_task = None

        for idx, email in enumerate(config.ONYX_ACCOUNT_LIST):
            fp = _generate_fingerprint(email, idx)
            self._accounts[email] = AccountState(
                email=email, index=idx, fingerprint=fp
            )

    # ── 辅助 ─────────────────────────────────────────────────────

    @staticmethod
    def _mask_email(email: str) -> str:
        parts = email.split("@")
        if len(parts) == 2:
            name = parts[0]
            if len(name) <= 3:
                masked = name[0] + "***"
            else:
                masked = name[:3] + "***"
            return f"{masked}@{parts[1]}"
        return email[:4] + "***"

    # ── 登录单个账号 ─────────────────────────────────────────────

    async def _login_account(self, email: str):
        account = self._accounts.get(email)
        if not account:
            return
        masked = self._mask_email(email)
        stats.add_system_log("INFO", f"🔑 Logging in {masked} ...")
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30, connect=15.0),
                follow_redirects=True,
                trust_env=False,
            ) as client:
                headers = {
                    **account.fingerprint,
                    "content-type": "application/x-www-form-urlencoded",
                }
                data = {"username": email, "password": config.ONYX_PASSWORD}
                response = await client.post(
                    f"{config.ONYX_BASE_URL}/api/auth/login",
                    headers=headers,
                    data=data,
                )
                if response.status_code in (204, 200):
                    token_value = None
                    for cookie in response.cookies.jar:
                        if cookie.name == "fastapiusersauth":
                            token_value = cookie.value
                            break
                    if not token_value:
                        sc = response.headers.get("set-cookie", "")
                        if "fastapiusersauth=" in sc:
                            token_value = sc.split("fastapiusersauth=")[1].split(";")[0]

                    if token_value:
                        with self._lock:
                            account.token = token_value
                            account.last_login_time = time.time()
                            account.last_check_time = time.time()
                            account.status = "active"
                            account.error_msg = None
                        stats.add_system_log("SUCCESS", f"✅ {masked} logged in successfully")
                    else:
                        with self._lock:
                            account.status = "error"
                            account.error_msg = "Login succeeded but no token found in cookies"
                        stats.add_system_log("ERROR", f"❌ {masked}: no token in cookies")
                elif response.status_code in (400, 401):
                    with self._lock:
                        account.status = "error"
                        account.error_msg = f"Invalid credentials (HTTP {response.status_code})"
                    stats.add_system_log("ERROR", f"❌ {masked}: invalid credentials")
                else:
                    body = response.text[:200]
                    with self._lock:
                        account.status = "error"
                        account.error_msg = f"HTTP {response.status_code}: {body}"
                    stats.add_system_log("ERROR", f"❌ {masked}: HTTP {response.status_code}")
        except Exception as e:
            with self._lock:
                account.status = "error"
                account.error_msg = str(e)[:200]
            stats.add_system_log("ERROR", f"❌ {masked}: {str(e)[:100]}")

    # ── 检测单个 Token ───────────────────────────────────────────

    async def _check_token_valid(self, email: str) -> bool:
        account = self._accounts.get(email)
        if not account or not account.token:
            return False
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(15, connect=10.0)
            ) as client:
                response = await client.get(
                    f"{config.ONYX_BASE_URL}/api/me",
                    headers=account.fingerprint,
                    cookies={"fastapiusersauth": account.token},
                )
                if response.status_code == 200:
                    with self._lock:
                        account.last_check_time = time.time()
                        account.status = "active"
                    return True
                else:
                    with self._lock:
                        account.status = "expired"
                        account.error_msg = f"Token check failed (HTTP {response.status_code})"
                    return False
        except Exception as e:
            with self._lock:
                account.status = "error"
                account.error_msg = str(e)[:200]
            return False

    # ── 批量操作 ─────────────────────────────────────────────────

    async def login_all(self):
        tasks = [self._login_account(email) for email in self._accounts]
        await asyncio.gather(*tasks, return_exceptions=True)
        active = sum(1 for a in self._accounts.values() if a.status == "active")
        stats.add_system_log("INFO", f"📊 Login complete: {active}/{len(self._accounts)} active")
        self._sync_tokens_to_config()

    async def check_and_refresh_all(self):
        stats.add_system_log("INFO", "🔍 Checking all tokens...")
        for email, account in self._accounts.items():
            if account.status == "active" and account.token:
                valid = await self._check_token_valid(email)
                if not valid:
                    masked = self._mask_email(email)
                    stats.add_system_log("INFO", f"🔄 Re-logging {masked}...")
                    await self._login_account(email)
        self._sync_tokens_to_config()
        active = sum(1 for a in self._accounts.values() if a.status == "active")
        stats.add_system_log("INFO", f"📊 Check complete: {active}/{len(self._accounts)} active")

    def _sync_tokens_to_config(self):
        with self._lock:
            valid_tokens = [
                acc.token
                for acc in self._accounts.values()
                if acc.status == "active" and acc.token and not acc.disabled
            ]
            config.AUTH_TOKEN_LIST.clear()
            config.AUTH_TOKEN_LIST.extend(valid_tokens)
        logger.info("Synced %d valid tokens to config", len(valid_tokens))

    # ── 定时检测 ─────────────────────────────────────────────────

    async def _periodic_check_loop(self):
        try:
            while True:
                await asyncio.sleep(self.CHECK_INTERVAL)
                try:
                    await self.check_and_refresh_all()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    stats.add_system_log("ERROR", f"Periodic check error: {e}")
                    await asyncio.sleep(60)
        except asyncio.CancelledError:
            pass

    def start_periodic_check(self):
        self._check_task = asyncio.create_task(self._periodic_check_loop())

    def stop_periodic_check(self):
        if self._check_task:
            self._check_task.cancel()

    # ── 手动操作 API ─────────────────────────────────────────────

    async def manual_check_all(self):
        await self.check_and_refresh_all()
        return self.get_status()

    async def manual_refresh_all(self):
        for acc in self._accounts.values():
            acc.status = "expired"
            acc.token = None
        await self.login_all()
        return self.get_status()

    async def manual_refresh_single(self, email: str):
        if email not in self._accounts:
            raise ValueError(f"Account {email} not found")
        acc = self._accounts[email]
        acc.status = "expired"
        acc.token = None
        await self._login_account(email)
        self._sync_tokens_to_config()
        return self.get_status()

    async def toggle_disable(self, email: str):
        if email not in self._accounts:
            raise ValueError(f"Account {email} not found")
        acc = self._accounts[email]
        acc.disabled = not acc.disabled
        masked = self._mask_email(email)
        action = "disabled" if acc.disabled else "enabled"
        stats.add_system_log("INFO", f"{'🚫' if acc.disabled else '✅'} {masked} {action}")
        self._sync_tokens_to_config()
        return self.get_status()

    # ── 动态添加账号并登录 ────────────────────────────────────────

    async def add_accounts_and_login(self, new_emails: list):
        """
        运行时动态添加新账号：生成指纹、登录获取 token、加入轮询池。
        返回 (added_list, skipped_list)
        """
        added = []
        skipped = []
        for email in new_emails:
            e = email.strip()
            if not e:
                continue
            if e in self._accounts:
                skipped.append(e)
                continue
            idx = len(self._accounts)
            fp = _generate_fingerprint(e, idx)
            account = AccountState(email=e, index=idx, fingerprint=fp)
            with self._lock:
                self._accounts[e] = account
            added.append(e)

        # 把新账号也加入 config.ONYX_ACCOUNT_LIST（去重）
        config.add_accounts(added)

        # 并发登录所有新账号
        if added:
            tasks = [self._login_account(e) for e in added]
            await asyncio.gather(*tasks, return_exceptions=True)
            self._sync_tokens_to_config()

            active_new = sum(
                1 for e in added
                if self._accounts[e].status == "active"
            )
            stats.add_system_log(
                "INFO",
                f"➕ Added {len(added)} accounts, {active_new} logged in successfully"
            )

        return added, skipped

    # ── 获取所有邮箱（用于导出） ──────────────────────────────────

    def get_all_emails(self):
        """返回当前所有账号的完整邮箱列表"""
        with self._lock:
            return [acc.email for acc in self._accounts.values()]

    # ── 状态查询 ─────────────────────────────────────────────────

    def get_status(self):
        with self._lock:
            accounts_info = []
            for acc in self._accounts.values():
                token_stats = stats.get_token_stats(acc.token) if acc.token else {}
                accounts_info.append({
                    "email": self._mask_email(acc.email),
                    "email_full": acc.email,
                    "status": acc.status,
                    "disabled": acc.disabled,
                    "last_login": acc.last_login_time,
                    "last_check": acc.last_check_time,
                    "error": acc.error_msg,
                    "total_requests": token_stats.get("total_requests", 0),
                    "success_count": token_stats.get("success_count", 0),
                    "error_count": token_stats.get("error_count", 0),
                    "output_tokens": token_stats.get("output_tokens", 0),
                    "last_used": token_stats.get("last_used"),
                })
            active = sum(
                1 for a in self._accounts.values()
                if a.status == "active" and not a.disabled
            )
        return {
            "total_accounts": len(self._accounts),
            "active_accounts": active,
            "check_interval_seconds": self.CHECK_INTERVAL,
            "accounts": accounts_info,
        }


# ── 全局单例 ─────────────────────────────────────────────────────
auth_manager = AuthManager()
