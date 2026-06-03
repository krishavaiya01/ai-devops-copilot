from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime


# --- Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "engineer"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Project Schemas ---
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None


class ProjectCreate(ProjectBase):
    pass


class ProjectResponse(ProjectBase):
    id: int
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Incident Schemas ---
class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    status: str = "open"  # open, investigating, resolved


class IncidentCreate(IncidentBase):
    project_id: Optional[int] = None


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    timeline_event: Optional[str] = None  # To append an event


class IncidentResponse(IncidentBase):
    id: int
    project_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    timeline: List[Dict[str, Any]] = []

    class Config:
        from_attributes = True


# --- Log Schemas ---
class BusinessImpactSchema(BaseModel):
    affected_users: int
    failed_transactions: int
    estimated_revenue_impact_usd: float
    summary: str


class TimelineEventSchema(BaseModel):
    timestamp: str
    event: str
    confidence_score: float


class SubsystemAnalysisSchema(BaseModel):
    status: str  # Healthy, Warning, Critical
    findings: str
    evidence: str
    severity: str  # P0-P5
    confidence: float


class RootCauseMatrixItem(BaseModel):
    root_cause: str
    subsystem: str
    confidence: float
    type: str  # Primary, Secondary
    evidence: str


class SubsystemsAnalysis(BaseModel):
    security: SubsystemAnalysisSchema
    kubernetes: SubsystemAnalysisSchema
    postgresql: SubsystemAnalysisSchema
    redis: SubsystemAnalysisSchema
    kafka: SubsystemAnalysisSchema
    aws_infrastructure: SubsystemAnalysisSchema
    dns: SubsystemAnalysisSchema
    tls_certificates: SubsystemAnalysisSchema
    network: SubsystemAnalysisSchema
    cicd: SubsystemAnalysisSchema
    data_integrity: SubsystemAnalysisSchema
    business_impact: SubsystemAnalysisSchema


class LogAnalysisResponse(BaseModel):
    executive_summary: str
    primary_root_causes: List[str]
    confidence_score: float
    supporting_evidence: str
    contributing_factors: List[str]
    symptoms: List[str]
    infrastructure_issues: str
    kubernetes_issues: str
    database_issues: str
    redis_issues: str
    cloud_issues: str
    security_issues: str
    kafka_issues: str
    container_issues: str
    cicd_issues: str
    business_impact: BusinessImpactSchema
    severity_classification: str
    immediate_actions: str
    long_term_prevention: str
    critical_findings_missed: List[str]
    timeline_reconstruction: List[TimelineEventSchema]
    documentation_links: List[str]
    root_cause_matrix: Optional[List[RootCauseMatrixItem]] = None
    subsystem_analysis: Optional[SubsystemsAnalysis] = None


class LogCreate(BaseModel):
    content: str
    incident_id: Optional[int] = None


class LogResponse(BaseModel):
    id: int
    incident_id: Optional[int]
    content: str
    analysis: Optional[Dict[str, Any]]
    analyzed_by: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


# --- Alert Schemas ---
class AlertBase(BaseModel):
    source: str
    title: str
    message: str
    severity: str = "warning"
    status: str = "active"
    metric_value: Optional[str] = None


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    status: Optional[str] = None  # active, acknowledged, resolved


class AlertResponse(AlertBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Cloud Resource Schemas ---
class CloudResourceResponse(BaseModel):
    id: int
    provider: str
    resource_type: str
    resource_id: str
    cost_per_hour: float
    state: str
    last_scanned_at: datetime

    class Config:
        from_attributes = True


# --- Recommendation Schemas ---
class RecommendationResponse(BaseModel):
    id: int
    category: str
    description: str
    potential_savings: float
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class RecommendationUpdate(BaseModel):
    status: str  # applied, dismissed


# --- Chat Schemas ---
class ChatMessageBase(BaseModel):
    role: str
    content: str


class ChatSessionCreate(BaseModel):
    session_id: str


class ChatMessageInput(BaseModel):
    session_id: str
    content: str


class ChatMessageResponse(ChatMessageBase):
    id: int
    session_id: str
    timestamp: datetime

    class Config:
        from_attributes = True
