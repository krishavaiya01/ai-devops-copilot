from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.db import get_db
from app.core.security import require_engineer, get_current_user
from app.models.models import Log, User
from app.schemas.schemas import LogCreate, LogResponse
from app.services.gemini import analyze_log_with_ai

router = APIRouter(prefix="/logs", tags=["log-analyzer"])


@router.post("/analyze", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def analyze_log(
    log_in: LogCreate, db: Session = Depends(get_db), current_user: User = Depends(require_engineer)
):
    try:
        # Call Gemini service to analyze log content
        analysis_result = await analyze_log_with_ai(log_in.content)

        # Save to database
        db_log = Log(
            content=log_in.content,
            incident_id=log_in.incident_id,
            analysis=analysis_result,
            analyzed_by=current_user.id,
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze log: {str(e)}",
        )


@router.get("/", response_model=List[LogResponse])
def get_logs(
    incident_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Log)
    if incident_id:
        query = query.filter(Log.incident_id == incident_id)
    return query.order_by(Log.created_at.desc()).all()
