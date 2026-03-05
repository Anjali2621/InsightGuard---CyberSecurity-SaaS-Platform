from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session

from app.storage.database import get_db
from app.models.model import LogEvent
from app.detection.rules import run_detection
from app.ingestion.parser import parse_logs

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post("/upload")
async def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Ingest a raw log file, parse it into structured events, store them,
    then run rule‑based + ML anomaly detection.
    """
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    # Use the real multi‑format parser
    parsed_events = parse_logs(text)

    for event in parsed_events:
        db_event = LogEvent(
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            severity=event.severity,
            user=event.user,
            ip=event.ip,
            action=event.action,
            resource=event.resource,
            raw=event.raw,
        )
        db.add(db_event)

    db.commit()

    incidents = run_detection(db)

    return {
        "message": "Logs stored successfully",
        "events_saved": len(parsed_events),
        "incidents_created": incidents,
    }


@router.get("/")
def get_logs(db: Session = Depends(get_db)):
    """
    Return the most recent 100 log events for the dashboard.
    """
    logs = db.query(LogEvent).order_by(LogEvent.id.desc()).limit(100).all()

    return [
        {
            "id": log.id,
            "timestamp": log.timestamp,
            "source": log.source,
            "event_type": log.event_type,
            "severity": log.severity,
            "user": log.user,
            "ip": log.ip,
            "action": log.action,
            "resource": log.resource,
        }
        for log in logs
    ]
