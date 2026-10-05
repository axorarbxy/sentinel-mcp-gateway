"""
Database Models and Configuration
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, Text, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import hashlib
import os
import re

# Database setup - Using SQLite for development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinel_mcp.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _sqlite_has_column(table_name: str, column_name: str) -> bool:
    try:
        inspector = engine.dialect.has_table(engine.connect(), table_name)
        if not inspector:
            return False
    except Exception:
        return False

    try:
        from sqlalchemy import text
        columns = engine.connect().execute(text(f"PRAGMA table_info({table_name})")).fetchall()
        return any(col[1] == column_name for col in columns)
    except Exception:
        return False


def ensure_mcp_agent_schema() -> None:
    """Upgrade the legacy schema to the secure MCP agent model without losing data."""
    try:
        from sqlalchemy import text
        with engine.begin() as conn:
            if not conn.dialect.has_table(conn, "mcp_agents"):
                return
            existing_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(mcp_agents)"))]
            column_defs = {
                "name_normalized": "VARCHAR(100)",
                "description": "VARCHAR(500)",
                "credential_hash": "VARCHAR(255)",
                "credential_prefix": "VARCHAR(64)",
                "credential_id": "VARCHAR(16)",
                "previous_credential_hash": "VARCHAR(255)",
                "previous_credential_id": "VARCHAR(16)",
                "previous_credential_expires_at": "DATETIME",
                "owner": "VARCHAR(100)",
                "team": "VARCHAR(100)",
                "environment": "VARCHAR(32)",
                "status": "VARCHAR(20)",
                "risk_level": "VARCHAR(20)",
                "allowed_tools": "TEXT",
                "metadata": "TEXT",
                "created_by": "INTEGER",
                "updated_at": "DATETIME",
                "deleted_at": "DATETIME",
            }
            for column_name, column_type in column_defs.items():
                if column_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE mcp_agents ADD COLUMN {column_name} {column_type}"))
            select_columns = "id, credential_hash, credential_prefix"
            has_legacy_api_key = "api_key" in existing_cols
            if has_legacy_api_key:
                select_columns += ", api_key"
            rows = conn.execute(text(f"SELECT {select_columns} FROM mcp_agents")).fetchall()
            digest_pattern = re.compile(r"^[a-f0-9]{64}$")
            key_pattern = re.compile(r"^cye_(live|test)_([a-f0-9]{16})_[A-Za-z0-9_-]{43}$")
            for row in rows:
                row_values = row._mapping
                stored_hash = row_values["credential_hash"]
                legacy_key = row_values.get("api_key")
                candidate = legacy_key or stored_hash
                if candidate:
                    new_hash = (
                        stored_hash
                        if digest_pattern.fullmatch(stored_hash or "")
                        else hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                    )
                    key_match = key_pattern.fullmatch(candidate)
                    credential_id = key_match.group(2) if key_match else None
                    prefix = (
                        f"cye_{key_match.group(1)}_{key_match.group(2)}"
                        if key_match
                        else row_values["credential_prefix"] or "sk_sentinel_"
                    )
                    conn.execute(
                        text(
                            "UPDATE mcp_agents SET credential_hash=:hash, "
                            "credential_id=COALESCE(credential_id, :credential_id), "
                            "credential_prefix=CASE WHEN :credential_id IS NOT NULL "
                            "THEN :prefix ELSE COALESCE(credential_prefix, :prefix) END "
                            "WHERE id=:id"
                        ),
                        {
                            "hash": new_hash,
                            "credential_id": credential_id,
                            "prefix": prefix,
                            "id": row_values["id"],
                        },
                    )
                if has_legacy_api_key and legacy_key:
                    conn.execute(
                        text("UPDATE mcp_agents SET api_key=:retired_value WHERE id=:id"),
                        {"retired_value": f"retired:{row_values['id']}", "id": row_values["id"]},
                    )
            if "name" in existing_cols:
                conn.execute(text(
                    "UPDATE mcp_agents SET name_normalized = lower(trim(name)) "
                    "WHERE name_normalized IS NULL OR name_normalized = ''"
                ))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_agents_name_normalized ON mcp_agents(name_normalized)"))
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_agents_credential_id "
                "ON mcp_agents(credential_id)"
            ))
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_mcp_agents_previous_credential_id "
                "ON mcp_agents(previous_credential_id)"
            ))
    except Exception as exc:
        raise RuntimeError("Failed to migrate MCP agent credentials safely") from exc


# ============ EXISTING TABLES ============
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100), nullable=False)
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="audit_logs")


class MCPRequestEvent(Base):
    """Redacted, queryable record for one intercepted JSON-RPC message."""
    __tablename__ = "mcp_request_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(40), unique=True, nullable=False, index=True)
    schema_version = Column(String(16), nullable=False, default="1.0")
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    request_id = Column(String(255), nullable=True, index=True)
    agent_id = Column(Integer, nullable=False, index=True)
    agent_name = Column(String(100), nullable=False)
    environment = Column(String(32), nullable=True)
    direction = Column(String(32), nullable=False, default="agent_to_server")
    method = Column(String(255), nullable=False, index=True)
    upstream_server = Column(String(100), nullable=True)
    tool_name = Column(String(255), nullable=True, index=True)
    resource_uri = Column(String(2048), nullable=True)
    prompt_name = Column(String(255), nullable=True)
    decision = Column(String(16), nullable=False, index=True)
    decision_reason = Column(String(1000), nullable=True)
    matched_rule_ids = Column(Text, nullable=False, default="[]")
    latency_ms = Column(Float, nullable=True)
    response_status = Column(String(16), nullable=True)
    response_size_bytes = Column(Integer, nullable=True)
    source_ip = Column(String(45), nullable=True)
    payload_hash = Column(String(64), nullable=True)
    payload_json = Column(Text, nullable=False, default="{}")


class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    key = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(100))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    last_used = Column(DateTime)
    
    user = relationship("User", back_populates="api_keys")


class ThreatReport(Base):
    """User-submitted threat reports"""
    __tablename__ = "threat_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2000), nullable=False, index=True)
    verdict = Column(String(50))
    risk_score = Column(Float)
    confidence = Column(Float)
    risk_factors = Column(Text)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reporter_note = Column(Text, nullable=True)
    status = Column(String(50), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User")


class DetectionFeedback(Base):
    """User feedback on detections"""
    __tablename__ = "detection_feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2000), nullable=False, index=True)
    predicted_verdict = Column(String(50))
    predicted_risk_score = Column(Float)
    feedback_type = Column(String(20))
    actual_verdict = Column(String(50))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User")


class ScanHistory(Base):
    """Track all scans for analytics"""
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2000), nullable=False, index=True)
    verdict = Column(String(50))
    risk_score = Column(Float)
    confidence = Column(Float)
    source = Column(String(50))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ============ NEW: MCP MANAGEMENT TABLES ============
class MCPAgent(Base):
    """Registered AI agents that use MCP."""
    __tablename__ = "mcp_agents"
    __table_args__ = (UniqueConstraint("name_normalized", name="uq_mcp_agents_name_normalized"),)
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    name_normalized = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(String(500), nullable=True)
    credential_hash = Column(String(255), nullable=False, unique=True, index=True)
    credential_prefix = Column(String(64), nullable=False)
    credential_id = Column(String(16), nullable=True, unique=True, index=True)
    previous_credential_hash = Column(String(255), nullable=True)
    previous_credential_id = Column(String(16), nullable=True, unique=True, index=True)
    previous_credential_expires_at = Column(DateTime, nullable=True)
    policies = Column(Text, default="[]")
    allowed_tools = Column(Text, default="[]")
    owner = Column(String(100), nullable=True)
    team = Column(String(100), nullable=True)
    environment = Column(String(32), default="dev")
    status = Column(String(20), default="active")
    risk_level = Column(String(20), default="low")
    is_active = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    total_requests = Column(Integer, default=0)
    blocked_requests = Column(Integer, default=0)
    agent_metadata = Column("metadata", Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    
    user = relationship("User", foreign_keys=[user_id])


class MCPServer(Base):
    """Connected MCP servers that the gateway proxies to"""
    __tablename__ = "mcp_servers"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    url = Column(String(500), nullable=False)
    server_type = Column(String(50), default="custom")
    auth_token = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_health_check = Column(DateTime, nullable=True)
    health_status = Column(String(20), default="unknown")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User")


class MCPPolicy(Base):
    """Security policies that agents must comply with"""
    __tablename__ = "mcp_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    rule_type = Column(String(50), nullable=False)
    config = Column(Text, default="{}")
    severity = Column(String(20), default="medium")
    is_enabled = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User")


# Create tables
Base.metadata.create_all(bind=engine)
ensure_mcp_agent_schema()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()