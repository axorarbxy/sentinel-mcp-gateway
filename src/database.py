"""
Database Models and Configuration
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

# Database setup - Using SQLite for development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinel_mcp.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


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
    """Registered AI agents that use MCP"""
    __tablename__ = "mcp_agents"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    api_key = Column(String(255), unique=True, index=True, nullable=False)
    policies = Column(Text, default="[]")
    is_active = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    total_requests = Column(Integer, default=0)
    blocked_requests = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)
    
    user = relationship("User")


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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()