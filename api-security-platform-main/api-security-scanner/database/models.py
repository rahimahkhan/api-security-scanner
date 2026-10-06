import os
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=False)
    scan_start_time = Column(DateTime, default=datetime.utcnow)
    scan_end_time = Column(DateTime, nullable=True)
    total_endpoints_found = Column(Integer, default=0)
    total_vulnerabilities_found = Column(Integer, default=0)
    overall_risk_score = Column(Float, default=0.0)
    overall_severity = Column(String(20), default="Low")
    # Lifecycle: "running" -> "complete" | "failed". Web scans run in a
    # background thread so long targets don't hit HTTP timeouts.
    status = Column(String(20), default="running")
    # Heartbeat touched by the scan worker; a "running" session whose
    # heartbeat goes stale is treated as failed (worker died, e.g. restart).
    updated_at = Column(DateTime, default=datetime.utcnow)
    # Owner of the scan; NULL for pre-auth legacy rows (hidden from everyone).
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    # Scan progress for live ETA display: done/total work units plus a
    # human-readable stage label ("Discovering endpoints", "Testing endpoints", ...).
    progress_done = Column(Integer, default=0)
    progress_total = Column(Integer, default=0)
    progress_stage = Column(String(80), default="")
    # Last time real progress was recorded (any update_scan_progress call).
    # Unlike updated_at (the worker heartbeat, which only proves the process
    # is alive), a stale progress_updated_at on a "running" scan means the
    # worker is stuck and the scan is reaped as failed instead of hanging
    # on "Scan in progress..." forever.
    progress_updated_at = Column(DateTime, nullable=True)

    endpoints = relationship("Endpoint", back_populates="session", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="session", cascade="all, delete-orphan")
    user = relationship("User", back_populates="sessions")


class User(Base):
    """Dashboard account. Identity lives in Firebase Auth; each Firebase user
    gets one local row (keyed by firebase_uid) so scan sessions stay
    per-user isolated."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    firebase_uid = Column(String(128), unique=True, nullable=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    name = Column(String(120), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    sessions = relationship("ScanSession", back_populates="user", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    url = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False, default="GET")
    discovered_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("ScanSession", back_populates="endpoints")
    findings = relationship("Finding", back_populates="endpoint", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True)
    
    attack_type = Column(String(100), nullable=False, default="None")
    finding_status = Column(String(30), nullable=False, default="Informational")
    severity = Column(String(20), nullable=False, default="Low")
    risk_score = Column(Float, default=0.0)
    signature_triggered = Column(String(255), default="")
    ml_score = Column(Float, default=0.0)
    lstm_score = Column(Float, default=0.0)
    autoencoder_score = Column(Float, default=0.0)
    recommendation = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    request_payload = Column(Text, nullable=True, default="")
    response_status = Column(Integer, default=200)
    response_size = Column(Integer, default=0)
    response_time = Column(Float, default=0.0)

    session = relationship("ScanSession", back_populates="findings")
    endpoint = relationship("Endpoint", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(10), nullable=False) # pdf, json, html
    file_path = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("ScanSession", back_populates="reports")
