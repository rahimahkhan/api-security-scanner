import os
import sys
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import DATABASE_URL
from config.logging_config import logger
from database.models import Base, ScanSession, Endpoint, Finding, Report, User

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
            # Heartbeat for the stale-scan reaper (worker died -> "running" forever).
            result = conn.execute(text("PRAGMA table_info(scan_sessions)"))
            columns = [row[1] for row in result.fetchall()]
            if columns and "updated_at" not in columns:
                conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN updated_at DATETIME"))
                conn.execute(text("UPDATE scan_sessions SET updated_at = scan_start_time WHERE updated_at IS NULL"))
                conn.commit()
                logger.info("Migrated scan_sessions table: added updated_at column.")
            # Owner of each scan for per-user isolation.
            result = conn.execute(text("PRAGMA table_info(scan_sessions)"))
            columns = [row[1] for row in result.fetchall()]
            if columns and "user_id" not in columns:
                conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE"))
                conn.commit()
                logger.info("Migrated scan_sessions table: added user_id column.")
            # Live progress tracking for the "time left" banner (done/total + stage).
            result = conn.execute(text("PRAGMA table_info(scan_sessions)"))
            columns = [row[1] for row in result.fetchall()]
            if columns and "progress_done" not in columns:
                conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN progress_done INTEGER DEFAULT 0"))
                conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN progress_total INTEGER DEFAULT 0"))
                conn.execute(text("ALTER TABLE scan_sessions ADD COLUMN progress_stage VARCHAR(80) DEFAULT ''"))
                conn.commit()
                logger.info("Migrated scan_sessions table: added progress tracking columns.")
            # Email + Google OAuth columns for dashboard accounts.
            result = conn.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result.fetchall()]
            if columns:
                if "email" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(255)"))
                    conn.commit()
                    logger.info("Migrated users table: added email column.")
                if "google_id" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN google_id VARCHAR(255)"))
                    conn.commit()
                    logger.info("Migrated users table: added google_id column.")
                if "name" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN name VARCHAR(120)"))
                    conn.commit()
                    logger.info("Migrated users table: added name column.")
                if "avatar_url" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500)"))
                    conn.commit()
                    logger.info("Migrated users table: added avatar_url column.")
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
    status: str = "running",
    user_id: Optional[int] = None
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
            status=status,
            updated_at=datetime.utcnow(),
            user_id=user_id
        )
        db.add(session_obj)
        db.commit()
        db.refresh(session_obj)
        return session_obj
    finally:
        db.close()


def touch_scan_session(session_id: int) -> None:
    """Heartbeat: mark a running scan as alive (stale-scan reaper input)."""
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if session_obj:
            session_obj.updated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def update_scan_progress(session_id: int, done: int = None, total: int = None,
                         stage: str = None) -> None:
    """Record scan progress for the live 'time left' banner. Only the
    arguments that are not None are updated, so the worker can bump just
    the counter per endpoint without rewriting the rest."""
    db = SessionLocal()
    try:
        session_obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
        if not session_obj:
            return
        if done is not None:
            session_obj.progress_done = max(0, int(done))
        if total is not None:
            session_obj.progress_total = max(0, int(total))
        if stage is not None:
            session_obj.progress_stage = str(stage)[:80]
        session_obj.updated_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def format_scan_eta(scan) -> str:
    """Human-friendly remaining-time estimate for a running scan, e.g.
    'about 2 minutes left'. Returns '' when there is nothing sensible to say."""
    try:
        done = int(scan.progress_done or 0)
        total = int(scan.progress_total or 0)
        if total <= 0 or done <= 0:
            return ""
        start = scan.scan_start_time
        if not start:
            return ""
        elapsed = (datetime.utcnow() - start).total_seconds()
        if elapsed <= 0:
            return ""
        remaining = elapsed / done * (total - done)
        if remaining < 15:
            return "less than 15 seconds left"
        if remaining < 90:
            return f"about {int(round(remaining / 5) * 5)} seconds left"
        minutes = remaining / 60
        if minutes < 90:
            return f"about {int(round(minutes))} minute{'s' if int(round(minutes)) != 1 else ''} left"
        return f"about {int(round(minutes / 5) * 5)} minutes left"
    except Exception:
        return ""


def create_user(username: str, password_hash: str, email: Optional[str] = None,
                google_id: Optional[str] = None, name: Optional[str] = None,
                avatar_url: Optional[str] = None) -> User:
    db = SessionLocal()
    try:
        user = User(username=username, password_hash=password_hash, email=email,
                    google_id=google_id, name=name, avatar_url=avatar_url)
        db.add(user)
        db.commit()
        db.refresh(user)
        # Detach so the caller can use user.id/username after close.
        db.expunge(user)
        return user
    finally:
        db.close()


def get_user_by_username(username: str) -> Optional[User]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            db.expunge(user)
        return user
    finally:
        db.close()


def get_user_by_email(email: str) -> Optional[User]:
    """Case-insensitive email lookup (emails are matched ignoring case)."""
    from sqlalchemy import func
    db = SessionLocal()
    try:
        user = db.query(User).filter(func.lower(User.email) == email.strip().lower()).first()
        if user:
            db.expunge(user)
        return user
    finally:
        db.close()


def get_user_by_google_id(google_id: str) -> Optional[User]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.google_id == google_id).first()
        if user:
            db.expunge(user)
        return user
    finally:
        db.close()


def link_google_account(user_id: int, google_id: str, name: Optional[str] = None,
                        avatar_url: Optional[str] = None) -> Optional[User]:
    """Attach a Google identity to an existing account (password login keeps working)."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
        user.google_id = google_id
        if name and not user.name:
            user.name = name
        if avatar_url:
            user.avatar_url = avatar_url
        db.commit()
        db.refresh(user)
        db.expunge(user)
        return user
    finally:
        db.close()


def get_user_by_id(user_id: int) -> Optional[User]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            db.expunge(user)
        return user
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

def get_all_sessions(user_id: Optional[int] = None) -> List[ScanSession]:
    """List scan sessions, newest first. When user_id is given, only that
    user's sessions are returned (per-user isolation)."""
    db = SessionLocal()
    try:
        query = db.query(ScanSession)
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        return query.order_by(ScanSession.scan_start_time.desc()).all()
    finally:
        db.close()


def get_session_for_user(session_id: int, user_id: Optional[int]) -> Optional[ScanSession]:
    """Fetch one session only if it belongs to the given user (else None,
    so callers can 404 without leaking other users' scans)."""
    db = SessionLocal()
    try:
        query = db.query(ScanSession).filter(ScanSession.id == session_id)
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        return query.first()
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
