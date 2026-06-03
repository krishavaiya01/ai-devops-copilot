import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.db import get_db
from app.core.security import require_engineer, require_viewer
from app.models.models import Incident, User
from app.schemas.schemas import IncidentCreate, IncidentUpdate, IncidentResponse

router = APIRouter(prefix="/incidents", tags=["incidents"])

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    # Setup initial timeline event
    initial_event = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "event": f"Incident created by {current_user.username}",
        "user": current_user.username
    }
    
    db_incident = Incident(
        project_id=incident_in.project_id,
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        status=incident_in.status,
        timeline=[initial_event]
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident

@router.get("/", response_model=List[IncidentResponse])
def get_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return db.query(Incident).order_by(Incident.created_at.desc()).all()

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    incident_in: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Store changes to record in the timeline
    timeline_updates = []
    
    if incident_in.status and incident_in.status != incident.status:
        timeline_updates.append(f"Status changed from {incident.status} to {incident_in.status}")
        incident.status = incident_in.status
        
    if incident_in.severity and incident_in.severity != incident.severity:
        timeline_updates.append(f"Severity changed from {incident.severity} to {incident_in.severity}")
        incident.severity = incident_in.severity
        
    if incident_in.title and incident_in.title != incident.title:
        incident.title = incident_in.title
        
    if incident_in.description and incident_in.description != incident.description:
        incident.description = incident_in.description
        
    # Append explicit timeline event if provided
    if incident_in.timeline_event:
        timeline_updates.append(incident_in.timeline_event)
        
    # Commit timeline events if any occurred
    if timeline_updates:
        # Load current timeline, append events, and flag as modified
        current_timeline = list(incident.timeline or [])
        for update_text in timeline_updates:
            current_timeline.append({
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "event": update_text,
                "user": current_user.username
            })
        incident.timeline = current_timeline
        
    db.commit()
    db.refresh(incident)
    return incident

@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(incident)
    db.commit()
    return None
