"""Onyx API client for OpenAI-compatible proxy"""

import json
import logging
from typing import AsyncGenerator, Tuple, Optional

import httpx
import config
import stats

logger = logging.getLogger(__name__)

# ============================================================
# 工具函数
# ============================================================

def _content_to_text(content) -> str:
    if isinstance(content, list):
        return " ".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return str(content or "")


def _build_prompt(messages: list) -> str:
    """
    将 OpenAI 格式的消息列表转换为结构化提示文本。
    
    对 system / user / assistant 角色使用明确的标记分隔，
    使下游模型能正确理解多轮对话结构和系统指令。
    """
    if not messages:
        return "Hello"

    lines = []
    for msg in messages:
        role = msg.get("role", "user")
        text = _content_to_text(msg.get("content", "")).strip()
        if not text:
            continue

        if role == "system":
            lines.append(f"[System Instructions]\n{text}\n[End System Instructions]")
        elif role == "assistant":
            lines.append(f"[Assistant]\n{text}")
        else:
            # user 及其他角色
            lines.append(f"[User]\n{text}")

    if not lines:
        return "Hello"

    return "\n\n".join(lines)


def _resolve_model(model_name: str) -> Tuple[str, str]:
    if model_name in config.MODEL_MAP:
        return config.MODEL_MAP[model_name]
    if "__" in model_name:
        parts = model_name.split("__")
        if len(parts) >= 3:
            return parts[0], parts[-1]
    return ("Anthropic", "claude-opus-4-6")


def _headers(with_json: bool = False) -> dict:
    h = {
        "accept": "application/json",
        "origin": "https://cloud.onyx.app",
        "referer": config.ONYX_REFERER,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
    }
    if with_json:
        h["content-type"] = "application/json"
    return h


# ============================================================
# Onyx API 操作
# ============================================================

async def create_chat_session(client: httpx.AsyncClient, token: str) -> str:
    payload = {
        "persona_id": config.ONYX_PERSONA_ID,
        "description": None,
        "project_id": None,
    }
    resp = await client.post(
        f"{config.ONYX_BASE_URL}/api/chat/create-chat-session",
        headers=_headers(with_json=True),
        json=payload,
        cookies={"fastapiusersauth": token},
        timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=15.0),
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Create session failed [{resp.status_code}]: {resp.text[:300]}")
    data = resp.json()
    chat_session_id = data.get("chat_session_id") or data.get("id")
    if not chat_session_id:
        raise RuntimeError(f"No chat_session_id in response: {data}")
    return str(chat_session_id)


async def delete_chat_session(client: httpx.AsyncClient, token: str, chat_session_id: str):
    try:
        resp = await client.delete(
            f"{config.ONYX_BASE_URL}/api/chat/delete-chat-session/{chat_session_id}",
            headers=_headers(),
            cookies={"fastapiusersauth": token},
            timeout=httpx.Timeout(30, connect=10.0),
        )
        if resp.status_code in (200, 204):
            logger.debug("✅ Deleted chat session %s", chat_session_id)
        else:
            logger.warning("⚠️ Delete session %s: [%d] %s",
                           chat_session_id, resp.status_code, resp.text[:200])
    except Exception as e:
        logger.warning("⚠️ Delete session %s error: %s", chat_session_id, e)


# ============================================================
# 单 Token 的流式聊天（内部使用）
# ============================================================

async def _stream_chat_single(
    client: httpx.AsyncClient,
    token: str,
    messages: list,
    model_name: str,
    temperature: Optional[float] = None,
) -> AsyncGenerator[Tuple[str, str], None]:
    chat_session_id: Optional[str] = None
    try:
        chat_session_id = await create_chat_session(client, token)
        provider, version = _resolve_model(model_name)

        # 构造 llm_override：temperature 由外部传入，缺省 0.5
        llm_override = {
            "temperature": temperature if temperature is not None else 0.5,
            "model_provider": provider,
            "model_version": version,
        }

        payload = {
            "message": _build_prompt(messages),
            "chat_session_id": chat_session_id,
            "parent_message_id": None,
            "file_descriptors": [],
            "internal_search_filters": {
                "source_type": None,
                "document_set": None,
                "time_cutoff": None,
                "tags": [],
            },
            "deep_research": False,
            "forced_tool_id": None,
            "llm_override": llm_override,
            "origin": config.ONYX_ORIGIN,
        }

        async with client.stream(
            "POST",
            f"{config.ONYX_BASE_URL}/api/chat/send-chat-message",
            headers=_headers(with_json=True),
            json=payload,
            cookies={"fastapiusersauth": token},
            timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=15.0),
        ) as response:
            if response.status_code != 200:
                body = await response.aread()
                raise RuntimeError(
                    f"Chat failed [{response.status_code}]: {body[:300]}"
                )
            async for line in response.aiter_lines():
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                obj = item.get("obj", {})
                item_type = obj.get("type")
                if item_type == "reasoning_delta":
                    delta = obj.get("reasoning", "")
                    if delta:
                        yield ("thinking", delta)
                elif item_type == "message_delta":
                    delta = obj.get("content", "")
                    if delta:
                        yield ("text", delta)
                elif item_type == "stop":
                    break
    finally:
        if chat_session_id is not None:
            await delete_chat_session(client, token, chat_session_id)


# ============================================================
# 带自动重试 + 统计的流式聊天（对外接口）— ✅ 真正流式输出
# ============================================================

async def stream_chat(
    client: httpx.AsyncClient,
    messages: list,
    model_name: str,
    temperature: Optional[float] = None,
) -> AsyncGenerator[Tuple[str, str], None]:
    """
    真正流式输出版本：边收到数据边 yield。
    - 若尚未 yield 过任何内容时出错，可切换下一个 token 重试
    - 若已开始输出（has_yielded=True），直接抛出错误
    - 流结束后记录统计
    """
    first_token = config.get_next_token()
    tokens_to_try = config.get_all_tokens_from(first_token)
    last_error: Optional[Exception] = None
    input_text = _build_prompt(messages)

    for i, token in enumerate(tokens_to_try):
        token_label = f"{stats.mask_token(token)} ({i + 1}/{len(tokens_to_try)})"
        stats.record_request_start(token, model_name)
        has_yielded = False
        text_parts = []
        thinking_parts = []

        try:
            logger.info("🔄 Trying token %s", token_label)
            async for item_type, content in _stream_chat_single(
                client, token, messages, model_name, temperature=temperature
            ):
                yield (item_type, content)
                has_yielded = True
                if item_type == "text":
                    text_parts.append(content)
                elif item_type == "thinking":
                    thinking_parts.append(content)

            # 正常结束
            output_text = "".join(text_parts)
            stats.record_success(token, input_text, output_text, model_name)
            return

        except Exception as e:
            last_error = e
            stats.record_error(token, str(e), model_name)
            logger.warning("❌ Token %s failed: %s", token_label, str(e))
            if has_yielded:
                logger.error("⚠️ Stream interrupted after partial output, cannot retry")
                raise RuntimeError(
                    f"Stream interrupted after partial output. "
                    f"Token {token_label} failed: {e}"
                ) from e
            logger.info("🔁 No data sent yet, retrying with next token...")
            continue

    raise RuntimeError(f"All {len(tokens_to_try)} tokens failed. Last error: {last_error}")


# ============================================================
# 非流式聊天（完整响应）
# ============================================================

async def full_chat(
    client: httpx.AsyncClient,
    messages: list,
    model_name: str,
    temperature: Optional[float] = None,
) -> Tuple[str, str]:
    text_parts = []
    thinking_parts = []
    async for item_type, content in stream_chat(
        client, messages, model_name, temperature=temperature
    ):
        if item_type == "thinking":
            thinking_parts.append(content)
        else:
            text_parts.append(content)
    return ("".join(text_parts), "".join(thinking_parts))