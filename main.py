"""Onyx → OpenAI-compatible API proxy"""

import json
import time
import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse, PlainTextResponse

import config
import stats
from onyx import stream_chat, full_chat
from auth_manager import auth_manager

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting Onyx Proxy...")
    logger.info("📧 Configured accounts: %d", len(config.ONYX_ACCOUNT_LIST))
    await auth_manager.login_all()
    auth_manager.start_periodic_check()
    yield
    auth_manager.stop_periodic_check()
    logger.info("👋 Shutting down...")


app = FastAPI(title="Onyx Proxy", lifespan=lifespan)


# ── 鉴权 ─────────────────────────────────────────────────────────

def _check_api_key(request: Request):
    if not config.API_KEY:
        return
    auth = request.headers.get("authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    if token != config.API_KEY:
        raise HTTPException(401, "Invalid API key")


def _check_dashboard_key(request: Request):
    if not config.API_KEY:
        return
    key = request.headers.get("x-auth-key") or request.query_params.get("key")
    if key != config.API_KEY:
        raise HTTPException(401, "Invalid dashboard key")


# ── Dashboard ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    html = Path("templates/dashboard.html").read_text(encoding="utf-8")
    html = html.replace(
        "__MODELS_PLACEHOLDER__",
        json.dumps(config.MODEL_MAP, ensure_ascii=False),
    )
    return HTMLResponse(html)


# ── Auth 管理 API ────────────────────────────────────────────────

@app.get("/auth/status")
async def auth_status(request: Request):
    _check_dashboard_key(request)
    return auth_manager.get_status()


@app.post("/auth/check")
async def auth_check(request: Request):
    _check_dashboard_key(request)
    return await auth_manager.manual_check_all()


@app.post("/auth/refresh")
async def auth_refresh(request: Request):
    _check_dashboard_key(request)
    return await auth_manager.manual_refresh_all()


@app.post("/auth/refresh-single")
async def auth_refresh_single(request: Request):
    _check_dashboard_key(request)
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(400, "Missing email")
    try:
        return await auth_manager.manual_refresh_single(email)
    except ValueError:
        raise HTTPException(404, "Account not found")


@app.post("/auth/toggle-disable")
async def auth_toggle_disable(request: Request):
    _check_dashboard_key(request)
    body = await request.json()
    email = body.get("email")
    if not email:
        raise HTTPException(400, "Missing email")
    try:
        return await auth_manager.toggle_disable(email)
    except ValueError:
        raise HTTPException(404, "Account not found")


@app.post("/auth/verify")
async def auth_verify(request: Request):
    body = await request.json()
    key = body.get("key", "")
    if not config.API_KEY or key == config.API_KEY:
        return {"ok": True}
    raise HTTPException(401, "Invalid key")


# ── 新增：批量添加账号 ───────────────────────────────────────────

@app.post("/auth/add-accounts")
async def auth_add_accounts(request: Request):
    """
    批量添加账号（逗号分隔），使用统一的 ONYX_PASSWORD 自动登录。
    请求体: {"accounts": "email1,email2,email3"}
    """
    _check_dashboard_key(request)
    body = await request.json()
    raw = body.get("accounts", "")
    if not raw or not raw.strip():
        raise HTTPException(400, "Missing accounts")

    emails = [a.strip() for a in raw.split(",") if a.strip()]
    if not emails:
        raise HTTPException(400, "No valid accounts provided")

    if not config.ONYX_PASSWORD:
        raise HTTPException(400, "ONYX_PASSWORD is not set. Cannot login new accounts.")

    added, skipped = await auth_manager.add_accounts_and_login(emails)

    return {
        "ok": True,
        "added": len(added),
        "skipped": len(skipped),
        "added_accounts": added,
        "skipped_accounts": skipped,
        "status": auth_manager.get_status(),
    }


# ── 新增：导出所有账号为 txt ──────────────────────────────────────

@app.get("/auth/export-accounts")
async def auth_export_accounts(request: Request):
    """导出所有账号为 txt 文件下载"""
    _check_dashboard_key(request)
    emails = auth_manager.get_all_emails()
    content = "\n".join(emails)
    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=onyx_accounts.txt"
        },
    )


# ── SSE 日志 ─────────────────────────────────────────────────────

@app.get("/auth/logs/stream")
async def auth_logs_stream(request: Request):
    _check_dashboard_key(request)

    async def event_generator():
        last_ts = time.time() - 3600
        while True:
            if await request.is_disconnected():
                break
            logs = stats.get_logs_since(last_ts)
            for log in logs:
                yield f"data: {json.dumps(log, ensure_ascii=False)}\n\n"
                if log["timestamp"] > last_ts:
                    last_ts = log["timestamp"]
            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── OpenAI 兼容 API ──────────────────────────────────────────────

@app.get("/v1/models")
async def list_models(request: Request):
    _check_api_key(request)
    models = [
        {"id": name, "object": "model", "created": 0, "owned_by": "onyx-proxy"}
        for name in config.MODEL_MAP
    ]
    return {"object": "list", "data": models}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    _check_api_key(request)
    body = await request.json()
    messages = body.get("messages", [])
    model = body.get("model", "claude-sonnet-4.5")
    stream = body.get("stream", False)
    temperature = body.get("temperature", None)

    if stream:
        return StreamingResponse(
            _stream_response(messages, model, temperature),
            media_type="text/event-stream",
        )
    else:
        return await _non_stream_response(messages, model, temperature)


async def _stream_response(messages, model, temperature):
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=15.0)
        ) as client:
            async for item_type, content in stream_chat(
                client, messages, model, temperature
            ):
                if item_type == "thinking":
                    chunk = {
                        "id": "chatcmpl-onyx",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [
                            {"index": 0, "delta": {"reasoning_content": content}, "finish_reason": None}
                        ],
                    }
                else:
                    chunk = {
                        "id": "chatcmpl-onyx",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model,
                        "choices": [
                            {"index": 0, "delta": {"content": content}, "finish_reason": None}
                        ],
                    }
                yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"

        # finish
        finish_chunk = {
            "id": "chatcmpl-onyx",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        yield f"data: {json.dumps(finish_chunk, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
    except Exception as e:
        logger.error("Stream error: %s", e)
        err_chunk = {
            "id": "chatcmpl-onyx",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {"index": 0, "delta": {"content": f"\n\n[Error: {e}]"}, "finish_reason": "stop"}
            ],
        }
        yield f"data: {json.dumps(err_chunk, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"


async def _non_stream_response(messages, model, temperature):
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=15.0)
    ) as client:
        text, thinking = await full_chat(client, messages, model, temperature)

    prompt_text = " ".join(_safe_content_to_text(m.get("content", "")) for m in messages)
    prompt_tokens = stats.count_tokens(prompt_text)
    completion_tokens = stats.count_tokens(text)

    result = {
        "id": "chatcmpl-onyx",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }
    if thinking:
        result["choices"][0]["message"]["reasoning_content"] = thinking
    return result


def _safe_content_to_text(content):
    if isinstance(content, list):
        return " ".join(
            p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
        )
    return str(content) if content else ""


# ── Health ───────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "active_tokens": len(config.AUTH_TOKEN_LIST),
        "total_accounts": len(config.ONYX_ACCOUNT_LIST),
    }


# ── Entry ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.PORT)
