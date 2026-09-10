"""
MCP Management API Routes
Handles agents, servers, and policies CRUD
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import datetime
import secrets
import json

from database import get_db, MCPAgent, MCPServer, MCPPolicy


router = APIRouter(prefix="/mcp", tags=["mcp-management"])


# ============ PYDANTIC MODELS ============
class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    policies: Optional[List[int]] = []


class AgentResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    api_key: str
    policies: List[int]
    is_active: bool
    total_requests: int
    blocked_requests: int
    created_at: datetime
    last_seen: Optional[datetime]


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
    active_agents = db.query(MCPAgent).filter(MCPAgent.is_active == True).count()
    total_servers = db.query(MCPServer).count()
    online_servers = db.query(MCPServer).filter(MCPServer.health_status == "online").count()
    total_policies = db.query(MCPPolicy).count()
    enabled_policies = db.query(MCPPolicy).filter(MCPPolicy.is_enabled == True).count()
    
    # Aggregate request counts
    total_requests = db.query(MCPAgent).with_entities(
        __import__('sqlalchemy').func.sum(MCPAgent.total_requests)
    ).scalar() or 0
    
    total_blocked = db.query(MCPAgent).with_entities(
        __import__('sqlalchemy').func.sum(MCPAgent.blocked_requests)
    ).scalar() or 0
    
    return {
        "agents": {
            "total": total_agents,
            "active": active_agents,
            "inactive": total_agents - active_agents,
        },
        "servers": {
            "total": total_servers,
            "online": online_servers,
            "offline": total_servers - online_servers,
        },
        "policies": {
            "total": total_policies,
            "enabled": enabled_policies,
            "disabled": total_policies - enabled_policies,
        },
        "traffic": {
            "total_requests": total_requests,
            "blocked_requests": total_blocked,
            "allowed_requests": total_requests - total_blocked,
        }
    }


# ============ AGENTS ============
@router.get("/agents", response_model=List[AgentResponse])
async def list_agents(db: Session = Depends(get_db)):
    """List all registered MCP agents"""
    agents = db.query(MCPAgent).order_by(MCPAgent.created_at.desc()).all()
    return [
        AgentResponse(
            id=a.id,
            name=a.name,
            description=a.description,
            api_key=a.api_key,
            policies=json.loads(a.policies) if a.policies else [],
            is_active=a.is_active,
            total_requests=a.total_requests or 0,
            blocked_requests=a.blocked_requests or 0,
            created_at=a.created_at,
            last_seen=a.last_seen,
        )
        for a in agents
    ]


@router.post("/agents", response_model=AgentResponse)
async def create_agent(agent_data: AgentCreate, db: Session = Depends(get_db)):
    """Register a new MCP agent"""
    api_key = f"sk_sentinel_{secrets.token_urlsafe(32)}"
    
    agent = MCPAgent(
        name=agent_data.name,
        description=agent_data.description,
        api_key=api_key,
        policies=json.dumps(agent_data.policies or []),
        is_active=True,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        api_key=agent.api_key,
        policies=agent_data.policies or [],
        is_active=agent.is_active,
        total_requests=0,
        blocked_requests=0,
        created_at=agent.created_at,
        last_seen=None,
    )


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        api_key=agent.api_key,
        policies=json.loads(agent.policies) if agent.policies else [],
        is_active=agent.is_active,
        total_requests=agent.total_requests or 0,
        blocked_requests=agent.blocked_requests or 0,
        created_at=agent.created_at,
        last_seen=agent.last_seen,
    )


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    db.delete(agent)
    db.commit()
    return {"success": True, "message": "Agent deleted"}


@router.post("/agents/{agent_id}/suspend")
async def suspend_agent(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.is_active = False
    db.commit()
    return {"success": True, "message": "Agent suspended"}


@router.post("/agents/{agent_id}/resume")
async def resume_agent(agent_id: int, db: Session = Depends(get_db)):
    agent = db.query(MCPAgent).filter(MCPAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent.is_active = True
    db.commit()
    return {"success": True, "message": "Agent resumed"}


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
    
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{server.url}/health")
            server.health_status = "online" if response.status_code == 200 else "offline"
    except Exception:
        server.health_status = "offline"
    
    server.last_health_check = datetime.utcnow()
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