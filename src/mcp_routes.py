"""
MCP Management API Routes
Handles agents, servers, and policies CRUD
"""

from fastapi import APIRouter, Depends, HTTPException, Security, Request, Query
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import json
import os
import time
from time_utils import utcnow

from database import get_db, MCPAgent, MCPServer, MCPPolicy, AuditLog
from auth import create_agent_api_key, hash_api_key, decode_token
from auth_routes import require_scopes


router = APIRouter(
    prefix="/mcp",
    tags=["mcp-management"],
    dependencies=[Security(require_scopes, scopes=["gateway:admin"])],
)


class CircuitBreaker:
    """Fail fast while an upstream MCP server is unavailable."""

    def __init__(self, failure_threshold: int = 3, reset_seconds: int = 30):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.states = {}

    def allow_request(self, key: int) -> bool:
        state = self.states.get(key)
        if not state or state["failures"] < self.failure_threshold:
            return True
        return time.monotonic() - state["last_failure"] >= self.reset_seconds

    def record_success(self, key: int):
        self.states.pop(key, None)

    def record_failure(self, key: int):
        state = self.states.setdefault(key, {"failures": 0, "last_failure": 0.0})
        state["failures"] += 1
        state["last_failure"] = time.monotonic()


server_circuit_breaker = CircuitBreaker(
    failure_threshold=max(1, int(os.getenv("SENTINEL_CIRCUIT_BREAKER_FAILURES", "3"))),
    reset_seconds=max(1, int(os.getenv("SENTINEL_CIRCUIT_BREAKER_RESET_SECONDS", "30"))),
)


def _normalize_name(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Agent name is required")
    if len(value) > 100:
        raise ValueError("Agent name must be at most 100 characters")
    return value


def _parse_tools(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _emit_agent_audit(db: Session, *, actor_id: Optional[int], agent_id: Optional[int], action: str, result: str, details: Optional[dict] = None):
    db.add(AuditLog(
        user_id=actor_id,
        action=f"agent_{action}",
        details=json.dumps({
            "target_agent_id": agent_id,
            "result": result,
            "details": details or {},
        }, default=str),
        timestamp=utcnow(),
    ))
    db.commit()


def _agent_is_active(agent: MCPAgent) -> bool:
    return bool(agent.is_active and agent.status in (None, "active", "suspended"))


def _to_agent_response(agent: MCPAgent, credential: Optional[str] = None) -> "AgentResponse":
    allowed_tools = []
    if agent.allowed_tools:
        try:
            payload = json.loads(agent.allowed_tools)
            allowed_tools = payload if isinstance(payload, list) else []
        except Exception:
            allowed_tools = _parse_tools(agent.allowed_tools)
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        owner=agent.owner,
        team=agent.team,
        environment=agent.environment or "dev",
        status=agent.status or ("active" if agent.is_active else "suspended"),
        risk_level=agent.risk_level or "low",
        allowed_tools=allowed_tools,
        credential_prefix=agent.credential_prefix,
        credential=credential,
        is_active=bool(agent.is_active and agent.status != "revoked"),
        total_requests=agent.total_requests or 0,
        blocked_requests=agent.blocked_requests or 0,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
        last_seen=agent.last_seen,
        last_seen_at=agent.last_seen,
    )


# ============ PYDANTIC MODELS ============
class AgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    owner: Optional[str] = Field(default=None, max_length=100)
    team: Optional[str] = Field(default=None, max_length=100)
    environment: str = Field(default="dev", min_length=1, max_length=32)
    allowed_tools: Optional[List[str]] = Field(default_factory=list)
    risk_level: str = Field(default="low", min_length=1, max_length=20)
    metadata: Optional[dict] = Field(default_factory=dict)


class AgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    owner: Optional[str] = Field(default=None, max_length=100)
    team: Optional[str] = Field(default=None, max_length=100)
    environment: Optional[str] = Field(default=None, min_length=1, max_length=32)
    allowed_tools: Optional[List[str]] = None
    risk_level: Optional[str] = Field(default=None, min_length=1, max_length=20)
    metadata: Optional[dict] = None


class AgentResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    owner: Optional[str] = None
    team: Optional[str] = None
    environment: str = "dev"
    status: str = "active"
    risk_level: str = "low"
    allowed_tools: List[str] = Field(default_factory=list)
    credential_prefix: Optional[str] = None
    credential: Optional[str] = None
    is_active: bool = True
    total_requests: int = 0
    blocked_requests: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class ServerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    url: str = Field(..., min_length=1, max_length=500)
    server_type: str = "custom"
    auth_token: Optional[str] = None


class ServerResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    url: str
    server_type: str
    is_active: bool
    health_status: str
    last_health_check: Optional[datetime]
    created_at: datetime


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    rule_type: str
    config: Optional[dict] = {}
    severity: str = "medium"


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    rule_type: str
    config: dict
    severity: str
    is_enabled: bool
    created_at: datetime


# ============ OVERVIEW ============
@router.get("/overview")
async def get_mcp_overview(db: Session = Depends(get_db)):
    """Get MCP overview stats"""
    total_agents = db.query(MCPAgent).count()
    active_agents = db.query(MCPAgent).filter(MCPAgent.status == "active").count() + db.query(MCPAgent).filter(MCPAgent.status.is_(None)).count()
    total_servers = db.query(MCPServer).count()
    online_servers = db.query(MCPServer).filter(MCPServer.health_status == "online").count()
    total_policies = db.query(MCPPolicy).count()
    enabled_policies = db.query(MCPPolicy).filter(MCPPolicy.is_enabled == True).count()
    total_requests = db.query(MCPAgent).with_entities(__import__('sqlalchemy').func.sum(MCPAgent.total_requests)).scalar() or 0
    total_blocked = db.query(MCPAgent).with_entities(__import__('sqlalchemy').func.sum(MCPAgent.blocked_requests)).scalar() or 0
    return {
        "agents": {"total": total_agents, "active": active_agents, "inactive": total_agents - active_agents},
        "servers": {"total": total_servers, "online": online_servers, "offline": total_servers - online_servers},
        "policies": {"total": total_policies, "enabled": enabled_policies, "disabled": total_policies - enabled_policies},
        "traffic": {"total_requests": total_requests, "blocked_requests": total_blocked, "allowed_requests": total_requests - total_blocked},
    }


# ============ AGENTS ============
@router.get("/agents", response_model=List[AgentResponse])
async def list_agents(
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    environment: Optional[str] = None,
    team: Optional[str] = None,
    search: Optional[str] = None,
):
    """List all registered MCP agents with bounded pagination and filters."""
    query = db.query(MCPAgent).filter(MCPAgent.deleted_at.is_(None)).order_by(MCPAgent.created_at.desc())
    if status:
        query = query.filter(MCPAgent.status == status)
    if environment:
        query = query.filter(MCPAgent.environment == environment)
    if team:
        query = query.filter(MCPAgent.team == team)
    if search:
        filter_text = f"%{search.strip()}%"
        query = query.filter(MCPAgent.name.ilike(filter_text) | (MCPAgent.description.ilike(filter_text)))
    agents = query.limit(200).all()
    return [_to_agent_response(agent) for agent in agents]


@router.post("/agents", response_model=AgentResponse)
async def create_agent(agent_data: AgentCreate, request: Request, db: Session = Depends(get_db)):
    """Register a new MCP agent and return the credential once."""
    name = _normalize_name(agent_data.name)
    normalized = name.casefold()
    if db.query(MCPAgent).filter(MCPAgent.name_normalized == normalized).first():
        raise HTTPException(status_code=409, detail="An agent with this name already exists")

    credential, credential_id, credential_prefix = create_agent_api_key()

    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")

    agent = MCPAgent(
        name=name,
        name_normalized=normalized,
        description=agent_data.description,
        credential_hash=hash_api_key(credential),
        credential_prefix=credential_prefix,
        credential_id=credential_id,
        policies=json.dumps([]),
        allowed_tools=json.dumps(_parse_tools(agent_data.allowed_tools)),
        owner=agent_data.owner,
        team=agent_data.team,
        environment=(agent_data.environment or "dev").strip() or "dev",
        status="active",
        risk_level=(agent_data.risk_level or "low").strip() or "low",
        is_active=True,
        created_by=actor_id,
        agent_metadata=json.dumps(agent_data.metadata or {}),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    _emit_agent_audit(db, actor_id=actor_id, agent_id=agent.id, action="register", result="success", details={"name": agent.name, "environment": agent.environment})
    return _to_agent_response(agent, credential)


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _to_agent_response(agent)


@router.patch("/agents/{agent_id}", response_model=AgentResponse)
async def update_agent(agent_id: int, updates: AgentUpdate, request: Request, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if updates.name:
        normalized = updates.name.strip().casefold()
        if db.query(MCPAgent).filter(MCPAgent.id != agent.id, MCPAgent.name_normalized == normalized).first():
            raise HTTPException(status_code=409, detail="An agent with this name already exists")
        agent.name = updates.name.strip(); agent.name_normalized = normalized
    for field in ["description", "owner", "team", "environment", "risk_level"]:
        if getattr(updates, field, None) is not None:
            setattr(agent, field, getattr(updates, field))
    if updates.allowed_tools is not None:
        agent.allowed_tools = json.dumps(_parse_tools(updates.allowed_tools))
    if updates.metadata is not None:
        agent.agent_metadata = json.dumps(updates.metadata or {})
    agent.updated_at = utcnow()
    db.commit(); db.refresh(agent)
    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")
    _emit_agent_audit(db, actor_id=actor_id, agent_id=agent.id, action="update", result="success", details={"updated_fields": [k for k, v in updates.model_dump(exclude_none=True).items()]})
    return _to_agent_response(agent)


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: int, request: Request, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.deleted_at = utcnow(); agent.is_active = False; agent.status = "revoked"
    db.commit()
    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")
    _emit_agent_audit(db, actor_id=actor_id, agent_id=agent.id, action="delete", result="success", details={"reason": "soft_delete"})
    return {"success": True, "message": "Agent deleted"}


@router.post("/agents/{agent_id}/suspend")
async def suspend_agent(agent_id: int, request: Request, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.status = "suspended"; agent.is_active = False; agent.updated_at = utcnow()
    db.commit(); db.refresh(agent)
    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")
    _emit_agent_audit(db, actor_id=actor_id, agent_id=agent.id, action="suspend", result="success", details={"status": "suspended"})
    return {"success": True, "message": "Agent suspended"}


@router.post("/agents/{agent_id}/resume")
async def resume_agent(agent_id: int, request: Request, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status == "revoked":
        raise HTTPException(status_code=409, detail="Revoked agents cannot be resumed")
    agent.status = "active"; agent.is_active = True; agent.updated_at = utcnow()
    db.commit(); db.refresh(agent)
    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")
    _emit_agent_audit(db, actor_id=actor_id, agent_id=agent.id, action="resume", result="success", details={"status": "active"})
    return {"success": True, "message": "Agent resumed"}


@router.post("/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: int, request: Request, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    revoked_at = utcnow()
    agent.status = "revoked"; agent.is_active = False; agent.updated_at = revoked_at; agent.deleted_at = revoked_at
    db.commit(); db.refresh(agent)
    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")
    _emit_agent_audit(db, actor_id=actor_id, agent_id=agent.id, action="revoke", result="success", details={"status": "revoked"})
    return {"success": True, "message": "Agent revoked"}


@router.post("/agents/{agent_id}/rotate-credential")
async def rotate_agent_credential(
    agent_id: int,
    request: Request,
    grace_period_seconds: int = Query(default=0, ge=0, le=300),
    db: Session = Depends(get_db),
):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id, MCPAgent.deleted_at.is_(None)).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status == "revoked":
        raise HTTPException(status_code=409, detail="Revoked agents cannot have credentials rotated")

    old_hash = agent.credential_hash
    old_id = agent.credential_id
    new_key, new_id, new_prefix = create_agent_api_key()
    if grace_period_seconds and old_id:
        agent.previous_credential_hash = old_hash
        agent.previous_credential_id = old_id
        agent.previous_credential_expires_at = utcnow() + timedelta(seconds=grace_period_seconds)
    else:
        agent.previous_credential_hash = None
        agent.previous_credential_id = None
        agent.previous_credential_expires_at = None
    agent.credential_hash = hash_api_key(new_key)
    agent.credential_id = new_id
    agent.credential_prefix = new_prefix
    agent.updated_at = utcnow()
    if agent.status != "active":
        agent.status = "active"
        agent.is_active = True
    db.commit(); db.refresh(agent)
    actor_id = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth.replace("Bearer ", "", 1).strip())
        if payload:
            actor_id = payload.get("sub")
    _emit_agent_audit(
        db,
        actor_id=actor_id,
        agent_id=agent.id,
        action="rotate_credential",
        result="success",
        details={"grace_period_seconds": grace_period_seconds},
    )
    return {"success": True, "message": "Credential rotated", "credential": new_key, "credential_prefix": agent.credential_prefix}


# ============ SERVERS ============
@router.get("/servers", response_model=List[ServerResponse])
async def list_servers(db: Session = Depends(get_db)):
    servers = db.query(MCPServer).order_by(MCPServer.created_at.desc()).all()
    return [
        ServerResponse(
            id=s.id,
            name=s.name,
            description=s.description,
            url=s.url,
            server_type=s.server_type,
            is_active=s.is_active,
            health_status=s.health_status or "unknown",
            last_health_check=s.last_health_check,
            created_at=s.created_at,
        )
        for s in servers
    ]


@router.post("/servers", response_model=ServerResponse)
async def create_server(server_data: ServerCreate, db: Session = Depends(get_db)):
    server = MCPServer(
        name=server_data.name,
        description=server_data.description,
        url=server_data.url,
        server_type=server_data.server_type,
        auth_token=server_data.auth_token,
        is_active=True,
        health_status="unknown",
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return ServerResponse(
        id=server.id,
        name=server.name,
        description=server.description,
        url=server.url,
        server_type=server.server_type,
        is_active=server.is_active,
        health_status=server.health_status,
        last_health_check=None,
        created_at=server.created_at,
    )


@router.delete("/servers/{server_id}")
async def delete_server(server_id: int, db: Session = Depends(get_db)):
    server = db.query(MCPServer).filter(MCPServer.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    db.delete(server)
    db.commit()
    return {"success": True, "message": "Server deleted"}


@router.post("/servers/{server_id}/health")
async def check_server_health(server_id: int, db: Session = Depends(get_db)):
    """Check if server is reachable"""
    server = db.query(MCPServer).filter(MCPServer.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    if not server_circuit_breaker.allow_request(server.id):
        server.health_status = "circuit_open"
        db.commit()
        raise HTTPException(status_code=503, detail="Upstream health checks are temporarily paused after repeated failures")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{server.url}/health")
            server.health_status = "online" if response.status_code == 200 else "offline"
            if response.status_code == 200:
                server_circuit_breaker.record_success(server.id)
            else:
                server_circuit_breaker.record_failure(server.id)
    except Exception:
        server.health_status = "offline"
        server_circuit_breaker.record_failure(server.id)

    server.last_health_check = utcnow()
    db.commit()
    return {"status": server.health_status, "last_check": server.last_health_check}


# ============ POLICIES ============
@router.get("/policies", response_model=List[PolicyResponse])
async def list_policies(db: Session = Depends(get_db)):
    policies = db.query(MCPPolicy).order_by(MCPPolicy.created_at.desc()).all()
    return [
        PolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            rule_type=p.rule_type,
            config=json.loads(p.config) if p.config else {},
            severity=p.severity,
            is_enabled=p.is_enabled,
            created_at=p.created_at,
        )
        for p in policies
    ]


@router.post("/policies", response_model=PolicyResponse)
async def create_policy(policy_data: PolicyCreate, db: Session = Depends(get_db)):
    policy = MCPPolicy(
        name=policy_data.name,
        description=policy_data.description,
        rule_type=policy_data.rule_type,
        config=json.dumps(policy_data.config or {}),
        severity=policy_data.severity,
        is_enabled=True,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        rule_type=policy.rule_type,
        config=policy_data.config or {},
        severity=policy.severity,
        is_enabled=policy.is_enabled,
        created_at=policy.created_at,
    )


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    policy = db.query(MCPPolicy).filter(MCPPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(policy)
    db.commit()
    return {"success": True, "message": "Policy deleted"}


@router.put("/policies/{policy_id}/toggle")
async def toggle_policy(policy_id: int, db: Session = Depends(get_db)):
    policy = db.query(MCPPolicy).filter(MCPPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.is_enabled = not policy.is_enabled
    db.commit()
    return {"success": True, "enabled": policy.is_enabled}
