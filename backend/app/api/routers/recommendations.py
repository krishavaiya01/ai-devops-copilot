from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.db import get_db
from app.core.security import require_engineer, require_viewer
from app.models.models import Recommendation, CloudResource, User
from app.schemas.schemas import RecommendationResponse, RecommendationUpdate, CloudResourceResponse

router = APIRouter(prefix="/recommendations", tags=["cloud-cost"])

@router.get("/cost", response_model=List[RecommendationResponse])
def get_cost_recommendations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return db.query(Recommendation).order_by(Recommendation.potential_savings.desc()).all()

@router.put("/cost/{rec_id}", response_model=RecommendationResponse)
def update_cost_recommendation(
    rec_id: int,
    rec_in: RecommendationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer)
):
    rec = db.query(Recommendation).filter(Recommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    
    rec.status = rec_in.status
    db.commit()
    db.refresh(rec)
    return rec

@router.get("/resources", response_model=List[CloudResourceResponse])
def get_cloud_resources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return db.query(CloudResource).order_by(CloudResource.cost_per_hour.desc()).all()
