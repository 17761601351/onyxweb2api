"""统计数据收集模块"""
import threading
import time
import logging
from collections import defaultdict
from typing import List, Dict, Any

_lock = threading.Lock()
_logger = logging.getLogger(__name__)

# ============================================================
# tiktoken 精确 token 统计（带降级后备）
# ============================================================

_tiktoken_encoding = None
_tiktoken_available = False

try:
    import tiktoken
    _tiktoken_encoding = tiktoken.get_encoding("cl100k_base")
    _tiktoken_available = True
    _logger.info("✅ tiktoken loaded successfully, using cl100k_base encoding for precise token counting")
except Exception as e:
    _logger.warning("⚠️ tiktoken not available (%s), falling back to character-based estimation", e)


def _estimate_tokens_fallback(text: str) -> int:
    """粗略估算 token 数（英文约4字符/token，中文约1.5字符/token）—— 降级后备"""
    if not text:
        return 0
    cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    en_chars = len(text) - cn_chars
    return int(cn_chars / 1.5 + en_chars / 4) or 1


def count_tokens(text: str) -> int:
    """
    精确统计 token 数。
    优先使用 tiktoken (cl100k_base) 进行精确计数；
    若 tiktoken 不可用或编码失败，则降级为字符估算。
    """
    if not text:
        return 0
    if _tiktoken_available and _tiktoken_encoding is not None:
        try:
            return len(_tiktoken_encoding.encode_ordinary(text))
        except Exception:
            pass
    return _estimate_tokens_fallback(text)


# 保留原名以兼容可能存在的外部调用
_estimate_tokens = count_tokens

# --- 每个 token 的统计 ---
_token_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "total_requests": 0,
    "success_count": 0,
    "error_count": 0,
    "input_tokens": 0,
    "output_tokens": 0,
    "last_used": None,
    "last_error": None,
    "status": "idle",  # idle / ok / error
})

# --- 传输日志（最近 200 条）---
_logs: List[Dict[str, Any]] = []
_MAX_LOGS = 200


def mask_token(token: str) -> str:
    """脱敏显示 token"""
    if len(token) <= 12:
        return token[:4] + "***" + token[-4:]
    return token[:6] + "***" + token[-6:]


def record_request_start(token: str, model: str):
    """记录请求开始"""
    with _lock:
        _token_stats[token]["total_requests"] += 1
        _token_stats[token]["last_used"] = time.time()
        _add_log("INFO", token, f"Request started → model: {model}")


def record_success(token: str, input_text: str, output_text: str, model: str):
    """记录成功请求"""
    input_tokens = count_tokens(input_text)
    output_tokens = count_tokens(output_text)
    with _lock:
        s = _token_stats[token]
        s["success_count"] += 1
        s["input_tokens"] += input_tokens
        s["output_tokens"] += output_tokens
        s["status"] = "ok"
        _add_log(
            "SUCCESS", token,
            f"✅ model: {model} | in: {input_tokens} tk | out: {output_tokens} tk"
        )


def record_error(token: str, error: str, model: str):
    """记录失败请求"""
    with _lock:
        s = _token_stats[token]
        s["error_count"] += 1
        s["last_error"] = error[:200]
        s["status"] = "error"
        _add_log("ERROR", token, f"❌ model: {model} | {error[:150]}")


def _add_log(level: str, token: str, message: str):
    """内部：添加日志条目（需在锁内调用）"""
    _logs.append({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": time.time(),
        "level": level,
        "token": mask_token(token),
        "message": message,
    })
    if len(_logs) > _MAX_LOGS:
        _logs.pop(0)


def get_dashboard_data(auth_token_list: list) -> dict:
    """获取仪表盘数据"""
    with _lock:
        total = len(auth_token_list)
        ok_count = sum(1 for t in auth_token_list if _token_stats[t]["status"] == "ok")
        err_count = sum(1 for t in auth_token_list if _token_stats[t]["status"] == "error")
        idle_count = total - ok_count - err_count

        token_details = []
        for t in auth_token_list:
            s = _token_stats[t]
            token_details.append({
                "token": mask_token(t),
                "status": s["status"],
                "total_requests": s["total_requests"],
                "success_count": s["success_count"],
                "error_count": s["error_count"],
                "input_tokens": s["input_tokens"],
                "output_tokens": s["output_tokens"],
                "last_used": time.strftime("%H:%M:%S", time.localtime(s["last_used"])) if s["last_used"] else "-",
                "last_error": s["last_error"],
            })

        total_input = sum(s["input_tokens"] for s in _token_stats.values())
        total_output = sum(s["output_tokens"] for s in _token_stats.values())

        return {
            "summary": {
                "total_accounts": total,
                "ok_count": ok_count,
                "error_count": err_count,
                "idle_count": idle_count,
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
            },
            "tokens": token_details,
            "logs": list(reversed(_logs)),  # 最新的在前
        }


# ============================================================
# 新增：供 auth_manager 和实时日志使用的辅助函数
# ============================================================

def get_token_stats(token: str) -> Dict[str, Any]:
    """获取单个 token 的调用统计（线程安全）"""
    with _lock:
        s = _token_stats[token]
        return {
            "total_requests": s["total_requests"],
            "success_count": s["success_count"],
            "error_count": s["error_count"],
            "input_tokens": s["input_tokens"],
            "output_tokens": s["output_tokens"],
            "last_used": s["last_used"],
            "last_error": s["last_error"],
            "status": s["status"],
        }


def get_logs_since(since_timestamp: float) -> List[Dict[str, Any]]:
    """获取指定时间戳之后的所有日志条目（供 SSE 实时推送）"""
    with _lock:
        return [
            log for log in _logs
            if log["timestamp"] > since_timestamp
        ]


def add_system_log(level: str, message: str):
    """添加系统级日志（非 token 相关，如登录、检测等）"""
    with _lock:
        _logs.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp": time.time(),
            "level": level,
            "token": "SYSTEM",
            "message": message,
        })
        if len(_logs) > _MAX_LOGS:
            _logs.pop(0)