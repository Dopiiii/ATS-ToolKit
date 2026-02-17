"""ATS-Toolkit FastAPI REST API.

Exposes toolkit modules over HTTP with health checking,
module discovery, execution, configuration, and live log streaming.
"""

import asyncio
import json
from dataclasses import asdict
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from src.core.base_module import ExecutionResult
from src.core.config_manager import get_config_manager
from src.core.error_handler import AtsException, ModuleNotFoundError
from src.core.logger import get_logger
from src.modules.registry import get_registry

app = FastAPI(title="ATS-Toolkit", version="2.0.0")
logger = get_logger("api")

# Discover modules on startup
_registry = get_registry()


@app.on_event("startup")
async def startup() -> None:
    """Discover modules when the API starts."""
    count = _registry.discover()
    logger.info("api_startup", modules_discovered=count)


# ---- Models ----

class ModuleRunRequest(BaseModel):
    """Request body for running a module."""
    config: dict[str, Any] = {}
    timeout: Optional[int] = None


# ---- Routes ----

@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "ATS-Toolkit", "version": "2.0.0"}


@app.get("/modules")
async def list_modules() -> list[dict[str, Any]]:
    """List all registered modules."""
    specs = _registry.list_modules()
    return [
        {
            "name": s.name,
            "category": s.category.value,
            "description": s.description,
            "version": s.version,
            "tags": s.tags,
            "requires_api_key": s.requires_api_key,
            "dangerous": s.dangerous,
        }
        for s in specs
    ]


@app.get("/modules/{name}")
async def get_module_spec(name: str) -> dict[str, Any]:
    """Get the full specification for a module."""
    try:
        spec = _registry.get_spec(name)
    except ModuleNotFoundError:
        raise HTTPException(status_code=404, detail=f"Module '{name}' not found")

    return {
        "name": spec.name,
        "category": spec.category.value,
        "description": spec.description,
        "version": spec.version,
        "author": spec.author,
        "tags": spec.tags,
        "requires_api_key": spec.requires_api_key,
        "api_key_service": spec.api_key_service,
        "dangerous": spec.dangerous,
        "parameters": [
            {
                "name": p.name,
                "type": p.type.value,
                "description": p.description,
                "required": p.required,
                "default": p.default,
                "choices": p.choices,
            }
            for p in spec.parameters
        ],
        "outputs": [
            {"name": o.name, "type": o.type, "description": o.description}
            for o in spec.outputs
        ],
    }


@app.post("/modules/{name}/run")
async def run_module(name: str, request: ModuleRunRequest) -> dict[str, Any]:
    """Execute a module with the given configuration."""
    try:
        result: ExecutionResult = await _registry.execute(
            name, request.config, timeout=request.timeout
        )
    except ModuleNotFoundError:
        raise HTTPException(status_code=404, detail=f"Module '{name}' not found")
    except AtsException as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "success": result.success,
        "data": result.data,
        "errors": result.errors,
        "warnings": result.warnings,
        "duration_ms": result.duration_ms,
        "module_name": result.module_name,
        "timestamp": result.timestamp,
    }


@app.get("/config")
async def get_config() -> dict[str, Any]:
    """Get the current configuration (without sensitive API keys)."""
    cfg = get_config_manager().config
    return {
        "log_level": cfg.log_level,
        "log_format": cfg.log_format,
        "data_dir": cfg.data_dir,
        "max_concurrent": cfg.max_concurrent,
        "timeout": cfg.timeout,
        "api_keys_configured": list(cfg.api_keys.keys()),
    }


@app.websocket("/ws/logs/{module}")
async def ws_logs(websocket: WebSocket, module: str) -> None:
    """WebSocket endpoint for live log streaming of a module."""
    await websocket.accept()
    logger.info("ws_connected", module=module)

    try:
        while True:
            # Wait for messages from the client (e.g., ping / control)
            data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
            # Echo back an acknowledgement
            await websocket.send_json({"type": "ack", "module": module, "data": data})
    except (WebSocketDisconnect, asyncio.TimeoutError):
        logger.info("ws_disconnected", module=module)
