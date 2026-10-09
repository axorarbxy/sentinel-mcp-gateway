from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Security
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from auth_routes import require_scopes
from database import AuditLog, SQLiPolicyConfig, get_db
from sqli_policy import analyze_sql_injection, get_runtime_configuration, list_sqli_indicators


router = APIRouter(prefix="/api/policies/sqli", tags=["SQL injection policy"])


class IndicatorUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    severity: Literal["low", "medium", "high"] | None = None


class SQLiTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: Any
    sql_mode: Literal["none", "query_tool", "readonly"] = "none"
    tool_name: str | None = None


def _config_row(db: Session) -> SQLiPolicyConfig:
    row = db.query(SQLiPolicyConfig).filter(SQLiPolicyConfig.id == 1).first()
    if row is None:
        row = SQLiPolicyConfig(id=1, indicators_json="{}", tool_modes_json="{}")
        db.add(row)
        db.flush()
    return row


def _write_audit(db: Session, actor: dict[str, Any], action: str, details: dict[str, Any]) -> None:
    try:
        actor_id = int(actor.get("sub"))
    except (TypeError, ValueError):
        actor_id = None
    db.add(AuditLog(user_id=actor_id, action=action, details=json.dumps(details, sort_keys=True)))


@router.get("/indicators")
async def get_sqli_indicators(
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
):
    runtime = get_runtime_configuration()
    indicators = []
    for item in list_sqli_indicators():
        override = runtime["indicators"].get(item["id"], {})
        indicators.append({
            **item,
            "severity": override.get("severity", item["severity"]),
            "enabled": override.get("enabled", True),
        })
    return {"indicators": indicators, "tool_modes": runtime["tool_modes"]}


@router.put("/indicators/{indicator_id}")
async def update_sqli_indicator(
    indicator_id: str,
    update: IndicatorUpdate,
    actor: dict = Security(require_scopes, scopes=["gateway:admin"]),
    db: Session = Depends(get_db),
):
    defaults = {item["id"]: item for item in list_sqli_indicators()}
    if indicator_id not in defaults:
        raise HTTPException(status_code=404, detail="SQLi indicator not found")
    changes = update.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one of enabled or severity is required")
    row = _config_row(db)
    config = json.loads(row.indicators_json or "{}")
    current = config.get(indicator_id, {})
    updated = {
        "enabled": current.get("enabled", True),
        "severity": current.get("severity", defaults[indicator_id]["severity"]),
        **changes,
    }
    config[indicator_id] = updated
    row.indicators_json = json.dumps(config, sort_keys=True)
    _write_audit(db, actor, "sqli_indicator_update", {"indicator_id": indicator_id, "changes": changes})
    db.commit()
    return {"id": indicator_id, **updated}


@router.put("/tools/{tool_name}/mode")
async def update_sql_tool_mode(
    tool_name: str,
    sql_mode: Literal["none", "query_tool", "readonly"],
    actor: dict = Security(require_scopes, scopes=["gateway:admin"]),
    db: Session = Depends(get_db),
):
    if not tool_name or len(tool_name) > 255:
        raise HTTPException(status_code=422, detail="tool_name must be between 1 and 255 characters")
    row = _config_row(db)
    tool_modes = json.loads(row.tool_modes_json or "{}")
    previous = tool_modes.get(tool_name)
    tool_modes[tool_name] = sql_mode
    row.tool_modes_json = json.dumps(tool_modes, sort_keys=True)
    _write_audit(db, actor, "sqli_tool_mode_update", {
        "tool_name": tool_name,
        "previous": previous,
        "sql_mode": sql_mode,
    })
    db.commit()
    return {"tool_name": tool_name, "sql_mode": sql_mode}


@router.post("/test")
async def test_sqli_payload(
    request: SQLiTestRequest,
    _actor: dict = Security(require_scopes, scopes=["gateway:read"]),
):
    runtime = get_runtime_configuration()
    indicator_config = runtime.get("indicators", {})
    enabled_overrides = {
        key: value["enabled"]
        for key, value in indicator_config.items()
        if isinstance(value, dict) and isinstance(value.get("enabled"), bool)
    }
    severity_overrides = {
        key: value["severity"]
        for key, value in indicator_config.items()
        if isinstance(value, dict) and value.get("severity") in {"low", "medium", "high"}
    }
    return analyze_sql_injection(
        request.payload,
        sql_mode=request.sql_mode,
        tool_name=request.tool_name,
        enabled_overrides=enabled_overrides,
        severity_overrides=severity_overrides,
    )