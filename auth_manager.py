"""
账号认证管理器
- 多账号自动登录 cloud.onyx.app 获取 fastapiusersauth
- 每个账号使用不同的浏览器指纹
- 每 2 小时自动检测 Token 可用性，失效自动重新登录
- 提供手动检测/刷新 API
"""

import asyncio
import hashlib
import logging
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx
import config
import stats

logger = logging.getLogger(__name__)

# ============================================================
# 浏览器指纹生成
# ============================================================

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

_ACCEPT_LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "ja,en-US;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "zh-TW,zh;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
]

_SEC_CH_UA_POOL = [
    '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    '"Google Chrome";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
    '"Google Chrome";v="132", "Chromium";v="132", "Not_A Brand";v="24"',
    '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    '"Microsoft Edge";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
    '"Brave";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="99"',
    '"Google Chrome";v="130", "Chromium";v="130", "Not_A Brand";v="99"',
    '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="99"',
    '"Google Chrome";v="132", "Chromium";v="132", "Not_A Brand";v="99"',
    '"Brave";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
    '"Google Chrome";v="131", "Chromium";v="131", "Not.A/Brand";v="24"',
]

_PLATFORM_POOL = [
    '"Windows"', '"Windows"', '"Windows"', '"Windows"', '"Windows"',
    '"macOS"', '"macOS"', '"macOS"', '"macOS"',
    '"Linux"', '"Linux"', '"Linux"',
]


def _generate_fingerprint(account_email: str, index: int) -> Dict[str, str]:
    seed = hashlib.sha256(f"{account_email}:{index}:fingerprint_salt_v1".encode()).hexdigest()[:8]
    seed_int = int(seed, 16)

    ua = _UA_POOL[seed_int % len(_UA_POOL)]
    lang = _ACCEPT_LANGUAGE_POOL[(seed_int >> 4) % len(_ACCEPT_LANGUAGE_POOL)]
    sec_ch_ua = _SEC_CH_UA_POOL[(seed_int >> 8) % len(_SEC_CH_UA_POOL)]
    platform = _PLATFORM_POOL[(seed_int >> 12) % len(_PLATFORM_POOL)]

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
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": platform,
        "dnt": "1" if seed_int % 3 == 0 else "0",
        "connection": "keep-alive",
    }


# ============================================================
# 账号状态
# ============================================================

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
    disabled: bool = False  # ← 新增：是否禁用，禁用的账号不参与轮询


# ============================================================
# 认证管理器
# ============================================================

class AuthManager:
    CHECK_INTERVAL = 2 * 60 * 60  # 2 小时

    def __init__(self):
        self._accounts: Dict[str, AccountState] = {}
        self._lock = threading.Lock()
        self._check_task: Optional[asyncio.Task] = None

        for i, email in enumerate(config.ONYX_ACCOUNT_LIST):
            fp = _generate_fingerprint(email, i)
            self._accounts[email] = AccountState(email=email, index=i, fingerprint=fp)
            logger.info("📧 Account #%d: %s (fingerprint generated)", i + 1, self._mask_email(email))

    @staticmethod
    def _mask_email(email: str) -> str:
        if "@" in email:
            local, domain = email.split("@", 1)
            if len(local) > 3:
                return f"{local[:3]}***@{domain}"
            return f"{local[0]}***@{domain}"
        return f"{email[:4]}***"

    # --- 登录单个账号 ---
    async def _login_account(self, email: str):
        account = self._accounts.get(email)
        if not account:
            return

        masked = self._mask_email(email)
        logger.info("🔑 Logging in account: %s", masked)
        stats.add_system_log("INFO", f"开始登录账号: {masked}")

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30, connect=15.0),
                follow_redirects=True,
                trust_env=False,
            ) as client:
                headers = {**account.fingerprint, "content-type": "application/x-www-form-urlencoded"}
                data = {"username": email, "password": config.ONYX_PASSWORD}

                response = await client.post(
                    f"{config.ONYX_BASE_URL}/api/auth/login",
                    headers=headers,
                    data=data,
                )

                if response.status_code in (204, 200):
                    token = None
                    for cookie in response.cookies.jar:
                        if cookie.name == "fastapiusersauth":
                            token = cookie.value
                            break

                    if not token:
                        set_cookie = response.headers.get("set-cookie", "")
                        if "fastapiusersauth=" in set_cookie:
                            token = set_cookie.split("fastapiusersauth=")[1].split(";")[0]

                    if token:
                        with self._lock:
                            account.token = token
                            account.last_login_time = time.time()
                            account.last_check_time = time.time()
                            account.status = "active"
                            account.error_msg = None
                        logger.info("✅ Login success: %s", masked)
                        stats.add_system_log("SUCCESS", f"✅ 登录成功: {masked}")
                    else:
                        with self._lock:
                            account.status = "error"
                            account.error_msg = "Login succeeded but no token found in cookies"
                        logger.error("❌ No token in cookies for %s", masked)
                        stats.add_system_log("ERROR", f"❌ 登录异常(无cookie): {masked}")

                elif response.status_code in (400, 401):
                    with self._lock:
                        account.status = "error"
                        account.error_msg = f"Invalid credentials (HTTP {response.status_code})"
                    logger.error("❌ Invalid credentials for %s (HTTP %s)", masked, response.status_code)
                    stats.add_system_log("ERROR", f"❌ 凭据无效: {masked}")

                else:
                    with self._lock:
                        account.status = "error"
                        account.error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.error("❌ Login failed for %s (HTTP %s)", masked, response.status_code)
                    stats.add_system_log("ERROR", f"❌ 登录失败(HTTP {response.status_code}): {masked}")

        except Exception as e:
            with self._lock:
                account.status = "error"
                account.error_msg = str(e)[:200]
            logger.error("❌ Login error for %s: %s", masked, e)
            stats.add_system_log("ERROR", f"❌ 登录异常: {masked} - {str(e)[:100]}")

    # --- 检测单个 Token ---
    async def _check_token_valid(self, email: str) -> bool:
        account = self._accounts.get(email)
        if not account or not account.token:
            return False

        masked = self._mask_email(email)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(15, connect=10.0),
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
                    logger.info("✅ Token valid: %s", masked)
                    return True
                else:
                    with self._lock:
                        account.status = "expired"
                        account.error_msg = f"Token check failed (HTTP {response.status_code})"
                    logger.warning("⚠️ Token expired: %s (HTTP %s)", masked, response.status_code)
                    return False

        except Exception as e:
            with self._lock:
                account.status = "error"
                account.error_msg = str(e)[:200]
            logger.error("❌ Token check error for %s: %s", masked, e)
            return False

    # --- 批量登录 ---
    async def login_all(self):
        logger.info("🚀 Logging in all %d accounts...", len(self._accounts))
        stats.add_system_log("INFO", f"开始批量登录 {len(self._accounts)} 个账号...")

        tasks = [self._login_account(email) for email in self._accounts]
        await asyncio.gather(*tasks, return_exceptions=True)

        active = sum(1 for a in self._accounts.values() if a.status == "active")
        logger.info("✅ Login complete: %d/%d active", active, len(self._accounts))
        stats.add_system_log("INFO", f"批量登录完成: {active}/{len(self._accounts)} 个活跃")

        self._sync_tokens_to_config()

    # --- 检测并刷新 ---
    async def check_and_refresh_all(self):
        logger.info("🔍 Checking all tokens...")
        stats.add_system_log("INFO", "开始检测所有 Token...")

        for email, account in self._accounts.items():
            if account.status == "active" and account.token:
                valid = await self._check_token_valid(email)
                if valid:
                    continue
                logger.info("🔄 Re-login: %s", self._mask_email(email))
                stats.add_system_log("INFO", f"Token 失效，重新登录: {self._mask_email(email)}")
                await self._login_account(email)

        self._sync_tokens_to_config()

        active = sum(1 for a in self._accounts.values() if a.status == "active")
        logger.info("✅ Check complete: %d/%d active", active, len(self._accounts))
        stats.add_system_log("INFO", f"检测完成: {active}/{len(self._accounts)} 个活跃")

    # --- 同步 Token 到 config ---
    def _sync_tokens_to_config(self):
        with self._lock:
            valid_tokens = [
                acc.token for acc in self._accounts.values()
                if acc.status == "active" and acc.token and not acc.disabled  # ← 新增：排除禁用账号
            ]
            config.AUTH_TOKEN_LIST.clear()
            config.AUTH_TOKEN_LIST.extend(valid_tokens)

        logger.info("🔄 Synced %d valid tokens to config", len(valid_tokens))

    # --- 定时检测循环 ---
    async def _periodic_check_loop(self):
        while True:
            try:
                await asyncio.sleep(self.CHECK_INTERVAL)
                await self.check_and_refresh_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("❌ Periodic check error: %s", e)
                await asyncio.sleep(60)

    def start_periodic_check(self):
        self._check_task = asyncio.create_task(self._periodic_check_loop())
        logger.info("⏰ Periodic check started (interval: %ds)", self.CHECK_INTERVAL)

    def stop_periodic_check(self):
        if self._check_task:
            self._check_task.cancel()
            logger.info("⏰ Periodic check stopped")

    # --- 手动操作 ---
    async def manual_check_all(self) -> dict:
        await self.check_and_refresh_all()
        return self.get_status()

    async def manual_refresh_all(self) -> dict:
        logger.info("🔄 Manual refresh all accounts...")
        stats.add_system_log("INFO", "手动重新登录所有账号...")

        with self._lock:
            for acc in self._accounts.values():
                acc.status = "expired"
                acc.token = None

        await self.login_all()
        return self.get_status()

    async def manual_refresh_single(self, email: str) -> dict:
        if email not in self._accounts:
            raise ValueError(f"Account not found: {email}")

        masked = self._mask_email(email)
        logger.info("🔄 Manual refresh: %s", masked)
        stats.add_system_log("INFO", f"手动刷新账号: {masked}")

        with self._lock:
            self._accounts[email].status = "expired"
            self._accounts[email].token = None

        await self._login_account(email)
        self._sync_tokens_to_config()
        return self.get_status()

    # --- 新增：切换账号禁用状态 ---
    async def toggle_disable(self, email: str) -> dict:
        if email not in self._accounts:
            raise ValueError(f"Account not found: {email}")

        masked = self._mask_email(email)
        with self._lock:
            acc = self._accounts[email]
            acc.disabled = not acc.disabled
            new_state = acc.disabled

        if new_state:
            logger.info("🚫 Account disabled: %s", masked)
            stats.add_system_log("INFO", f"🚫 账号已禁用: {masked}")
        else:
            logger.info("✅ Account enabled: %s", masked)
            stats.add_system_log("INFO", f"✅ 账号已启用: {masked}")

        self._sync_tokens_to_config()
        return self.get_status()

    # --- 状态查询 ---
    def get_status(self) -> dict:
        accounts_info = []
        for email, acc in self._accounts.items():
            token_stats = {}
            if acc.token:
                token_stats = stats.get_token_stats(acc.token)

            accounts_info.append({
                "email": self._mask_email(email),
                "email_full": email,
                "status": acc.status,
                "disabled": acc.disabled,  # ← 新增：返回禁用状态
                "last_login": acc.last_login_time,
                "last_check": acc.last_check_time,
                "error": acc.error_msg,
                "total_requests": token_stats.get("total_requests", 0),
                "success_count": token_stats.get("success_count", 0),
                "error_count": token_stats.get("error_count", 0),
                "output_tokens": token_stats.get("output_tokens", 0),
                "last_used": token_stats.get("last_used"),
            })

        active_accounts = sum(1 for a in self._accounts.values() if a.status == "active" and not a.disabled)

        return {
            "total_accounts": len(self._accounts),
            "active_accounts": active_accounts,
            "check_interval_seconds": self.CHECK_INTERVAL,
            "accounts": accounts_info,
        }


# 全局单例
auth_manager = AuthManager()