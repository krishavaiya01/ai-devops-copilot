from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from app.core.db import get_db
from app.core.security import require_engineer, require_viewer
from app.models.models import Alert, User
from app.schemas.schemas import AlertCreate, AlertUpdate, AlertResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/", response_model=List[AlertResponse])
def get_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return db.query(Alert).order_by(Alert.created_at.desc()).all()

@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(
    alert_in: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    db_alert = Alert(
        source=alert_in.source,
        title=alert_in.title,
        message=alert_in.message,
        severity=alert_in.severity,
        status=alert_in.status,
        metric_value=alert_in.metric_value
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

@router.put("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    alert_in: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if alert_in.status:
        db_alert.status = alert_in.status
        
    db.commit()
    db.refresh(db_alert)
    return db_alert

@router.post("/webhook", status_code=status.HTTP_202_ACCEPTED)
async def prometheus_alert_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Webhook endpoint to receive alerts from Prometheus Alertmanager.
    Alertmanager payload structure:
    {
      "alerts": [
        {
          "labels": {"alertname": "...", "severity": "..."},
          "annotations": {"description": "...", "summary": "..."},
          "status": "firing" | "resolved"
        }
      ]
    }
    """
    try:
        payload = await request.json()
        alerts = payload.get("alerts", [])
        for alert_data in alerts:
            labels = alert_data.get("labels", {})
            annotations = alert_data.get("annotations", {})
            status_val = alert_data.get("status", "firing")
            
            title = labels.get("alertname", "Prometheus Alert")
            message = annotations.get("description", annotations.get("summary", "Metric exceeded threshold"))
            severity = labels.get("severity", "warning")
            if severity == "page":
                severity = "critical"
            
            mapped_status = "active" if status_val == "firing" else "resolved"
            
            # Save alert to DB
            db_alert = Alert(
                source="prometheus",
                title=title,
                message=message,
                severity=severity,
                status=mapped_status,
                metric_value=labels.get("instance", "cluster-node")
            )
            db.add(db_alert)
        db.commit()
        return {"status": "success", "processed": len(alerts)}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook parsing failed: {str(e)}"
        )
