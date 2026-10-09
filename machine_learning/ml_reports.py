"""
Threat Reports & Feedback API
Handles user-submitted threat reports and detection feedback
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import datetime
import json

from database import get_db, ThreatReport, DetectionFeedback, ScanHistory


router = APIRouter(prefix="/ml", tags=["ml-reports"])


# ============ Pydantic Models ============
class ThreatReportRequest(BaseModel):
    url: str
    verdict: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    risk_factors: Optional[List[str]] = []
    reporter_note: Optional[str] = None


class FeedbackRequest(BaseModel):
    url: str
    predicted_verdict: str
    predicted_risk_score: float
    feedback_type: str  # correct or incorrect
    actual_verdict: Optional[str] = None
    note: Optional[str] = None


class ScanHistoryRequest(BaseModel):
    url: str
    verdict: str
    risk_score: float
    confidence: float
    source: str = "phishing_module"


# ============ Routes ============
@router.post("/report-threat")
async def report_threat(
    report: ThreatReportRequest,
    db: Session = Depends(get_db)
):
    """Submit a threat report for a malicious URL"""
    try:
        threat = ThreatReport(
            url=report.url,
            verdict=report.verdict,
            risk_score=report.risk_score,
            confidence=report.confidence,
            risk_factors=json.dumps(report.risk_factors or []),
            reporter_note=report.reporter_note,
            status="pending"
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)
        
        return {
            "success": True,
            "message": "Threat report submitted successfully",
            "report_id": threat.id,
            "status": threat.status
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback")
async def submit_feedback(
    feedback: FeedbackRequest,
    db: Session = Depends(get_db)
):
    """Submit feedback on a detection (correct or incorrect)"""
    try:
        fb = DetectionFeedback(
            url=feedback.url,
            predicted_verdict=feedback.predicted_verdict,
            predicted_risk_score=feedback.predicted_risk_score,
            feedback_type=feedback.feedback_type,
            actual_verdict=feedback.actual_verdict,
            note=feedback.note
        )
        db.add(fb)
        db.commit()
        db.refresh(fb)
        
        return {
            "success": True,
            "message": "Feedback recorded. Thank you!",
            "feedback_id": fb.id
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan-history")
async def log_scan(
    scan: ScanHistoryRequest,
    db: Session = Depends(get_db)
):
    """Log a scan to history (called automatically on each scan)"""
    try:
        entry = ScanHistory(
            url=scan.url,
            verdict=scan.verdict,
            risk_score=scan.risk_score,
            confidence=scan.confidence,
            source=scan.source
        )
        db.add(entry)
        db.commit()
        return {"success": True}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports")
async def get_all_reports(limit: int = 50, db: Session = Depends(get_db)):
    """Admin: Get all threat reports"""
    reports = db.query(ThreatReport).order_by(
        ThreatReport.created_at.desc()
    ).limit(limit).all()
    
    return {
        "total": len(reports),
        "reports": [{
            "id": r.id,
            "url": r.url,
            "verdict": r.verdict,
            "risk_score": r.risk_score,
            "confidence": r.confidence,
            "risk_factors": json.loads(r.risk_factors) if r.risk_factors else [],
            "reporter_note": r.reporter_note,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None
        } for r in reports]
    }


@router.get("/feedback/list")
async def get_all_feedback(limit: int = 50, db: Session = Depends(get_db)):
    """Admin: Get all feedback"""
    feedbacks = db.query(DetectionFeedback).order_by(
        DetectionFeedback.created_at.desc()
    ).limit(limit).all()
    
    return {
        "total": len(feedbacks),
        "feedback": [{
            "id": f.id,
            "url": f.url,
            "predicted_verdict": f.predicted_verdict,
            "predicted_risk_score": f.predicted_risk_score,
            "feedback_type": f.feedback_type,
            "actual_verdict": f.actual_verdict,
            "note": f.note,
            "created_at": f.created_at.isoformat() if f.created_at else None
        } for f in feedbacks]
    }


@router.get("/reports/stats")
async def get_report_stats(db: Session = Depends(get_db)):
    """Admin: Get statistics on reports and feedback"""
    total_reports = db.query(ThreatReport).count()
    pending_reports = db.query(ThreatReport).filter(ThreatReport.status == "pending").count()
    verified_reports = db.query(ThreatReport).filter(ThreatReport.status == "verified").count()
    
    total_feedback = db.query(DetectionFeedback).count()
    correct_feedback = db.query(DetectionFeedback).filter(
        DetectionFeedback.feedback_type == "correct"
    ).count()
    incorrect_feedback = db.query(DetectionFeedback).filter(
        DetectionFeedback.feedback_type == "incorrect"
    ).count()
    
    return {
        "reports": {
            "total": total_reports,
            "pending": pending_reports,
            "verified": verified_reports
        },
        "feedback": {
            "total": total_feedback,
            "correct": correct_feedback,
            "incorrect": incorrect_feedback,
            "accuracy": round(correct_feedback / total_feedback * 100, 2) if total_feedback > 0 else 0
        }
    }