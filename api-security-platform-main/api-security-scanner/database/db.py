import os
import sys
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import DATABASE_URL
from config.logging_config import logger
from database.models import Base, ScanSession, Endpoint, Finding, Report

db_path = DATABASE_URL.replace("sqlite:///", "")
if os.path.dirname(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Creates all database tables on initial startup and applies migrations."""
    Base.metadata.create_all(bind=engine)
    # Ensure finding_status column exists for existing SQLite database
    with engine.connect() as conn:
        try:
            from sqlalchemy import text
            result = conn.execute(text("PRAGMA table_info(findings)"))
            columns = [row[1] for row in result.fetchall()]
            if columns and "finding_status" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN finding_status VARCHAR(30) DEFAULT 'Informational' NOT NULL"))
                conn.commit()
                logger.info("Migrated findings table: added finding_status column.")
            # Ensure scan_sessions.status exists for existing SQLite database.
            # Backfill as 'complete': every pre-existing row finished its scan.
            result = conn.execute(text("PRAGMA table_info(scan_sessions)"))
            columns = [row[1] for row in result.fetchall()]
            if columns and "status" not in columns:
                conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN status VARCHAR(20) DEFAULT 'complete' NOT NULL"))
                conn.commit()
                logger.info("Migrated scan_sessions table: added status column.")
        except Exception as exc:
            logger.warning(f"Database migration check: {exc}")
    logger.info("Database tables initialized successfully.")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Database Data Access Functions ---

def save_scan_session(
    target_url: str,
    total_endpoints: int = 0,
    total_vulnerabilities: int = 0,
    overall_risk_score: float = 0.0,
    overall_severity: str = "Low",
    status: str = "running"
) -> ScanSession:
    db = SessionLocal()
    try:
        session_obj = ScanSession(
            target_url=target_url,
            scan_start_time=datetime.utcnow(),
            total_endpoints_found=total_endpoints,
            total_vulnerabilities_found=total_vulnerabilities,
            overall_risk_score=overall_risk_score,
            overall_severity=overall_severity,
            status=status
        )
        db.add(session_obj)
        db.commit()
        db.refresh(session_obj)
        return session_obj
    finally:
        db.close()

def save_endpoint(session_id: int, url: str, method: str = "GET") -> Endpoint:
    db = SessionLocal()
    try:
        endpoint_obj = Endpoint(
            session_id=session_id,
            url=url,
            method=method.upper()
        )
        db.add(endpoint_obj)
        db.commit()
        db.refresh(endpoint_obj)
        return endpoint_obj
    finally:
        db.close()

def save_finding(
    session_id: int,
    endpoint_id: Optional[int],
    attack_type: str,
    severity: str,
    risk_score: float,
    finding_status: str = "Informational",
    signature_triggered: str = "",
    ml_score: float = 0.0,
    lstm_score: float = 0.0,
    autoencoder_score: float = 0.0,
    recommendation: str = "",
    request_payload: str = "",
    response_status: int = 200,
    response_size: int = 0,
    response_time: float = 0.0
) -> Finding:
    db = SessionLocal()
    try:
        finding_obj = Finding(
            session_id=session_id,
            endpoint_id=endpoint_id,
            attack_type=attack_type,
            finding_status=finding_status,
            severity=severity,
            risk_score=risk_score,
            signature_triggered=signature_triggered,
            ml_score=ml_score,
            lstm_score=lstm_score,
            autoencoder_score=autoencoder_score,
            recommendation=recommendation,
            request_payload=request_payload,
            response_status=response_status,
            response_size=response_size,
            response_time=response_time
        )
        db.add(finding_obj)
        db.commit()
        db.refresh(finding_obj)
        return finding_obj
    finally:
        db.close()

def complete_scan_session(
    session_id: int,
    overall_risk_score: float,
    overall_severity: str,
    total_vulnerabilities: int
) -> Optional[ScanSession]:
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if session_obj:
            session_obj.overall_risk_score = overall_risk_score
            session_obj.overall_severity = overall_severity
            session_obj.total_vulnerabilities_found = total_vulnerabilities
            session_obj.scan_end_time = datetime.utcnow()
            session_obj.status = "complete"
            db.commit()
            db.refresh(session_obj)
            return session_obj
        return None
    finally:
        db.close()

def fail_scan_session(session_id: int, error: str = "") -> Optional[ScanSession]:
    """Mark a background scan as failed so the UI stops polling it."""
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if session_obj:
            session_obj.status = "failed"
            session_obj.scan_end_time = datetime.utcnow()
            if error:
                logger.error(f"Scan session {session_id} failed: {error}")
            db.commit()
            db.refresh(session_obj)
            return session_obj
        return None
    finally:
        db.close()

def get_all_sessions() -> List[ScanSession]:
    db = SessionLocal()
    try:
        return db.query(ScanSession).order_by(ScanSession.scan_start_time.desc()).all()
    finally:
        db.close()

def get_session_findings(session_id: int) -> List[Finding]:
    db = SessionLocal()
    try:
        return db.query(Finding).options(
            joinedload(Finding.endpoint)
        ).filter(
            Finding.session_id == session_id,
            Finding.risk_score > 0
        ).all()
    finally:
        db.close()

def get_finding_by_id(finding_id: int) -> Optional[Finding]:
    db = SessionLocal()
    try:
        return db.query(Finding).options(joinedload(Finding.endpoint)).options(joinedload(Finding.session)).filter(Finding.id == finding_id).first()
    finally:
        db.close()

def delete_session(session_id: int) -> bool:
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if session_obj:
            db.delete(session_obj)
            db.commit()
            return True
        return False
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("\n[+] Database initialized. Creating dummy test session...")
    
    sess = save_scan_session("http://example.com/api", total_endpoints=1, total_vulnerabilities=1, overall_risk_score=75.0, overall_severity="High")
    ep = save_endpoint(sess.id, "http://example.com/api/users", "GET")
    fnd = save_finding(
        session_id=sess.id,
        endpoint_id=ep.id,
        attack_type="SQL_Injection",
        severity="High",
        risk_score=75.0,
        signature_triggered="1=1",
        ml_score=20.0,
        lstm_score=15.0,
        autoencoder_score=10.0,
        recommendation="Sanitize query parameters using prepared statements."
    )

    print(f"[+] Dummy session saved: ID #{sess.id}")
    print(f"[+] Dummy finding saved: ID #{fnd.id} [{fnd.attack_type}] Severity: {fnd.severity}")

    fetched_findings = get_session_findings(sess.id)
    print(f"[+] Retrieved {len(fetched_findings)} findings from database for Session #{sess.id}")
    
    # Cleanup test session
    delete_session(sess.id)
    print(f"[+] Test session #{sess.id} cleaned up.")
