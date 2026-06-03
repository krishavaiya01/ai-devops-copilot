import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from app.core.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="engineer")  # admin, engineer, viewer
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    projects = relationship("Project", back_populates="owner")
    logs_analyzed = relationship("Log", back_populates="analyzer")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="projects")
    incidents = relationship("Incident", back_populates="project")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="medium")  # low, medium, high, critical
    status = Column(String, default="open")  # open, investigating, resolved
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    timeline = Column(
        JSON, default=list
    )  # List of objects: {"timestamp": "...", "event": "...", "user": "..."}

    project = relationship("Project", back_populates="incidents")
    logs = relationship("Log", back_populates="incident")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    content = Column(Text, nullable=False)
    # analysis stores: {"root_cause": "", "severity": "", "recommended_fix": "", "documentation_links": []}
    analysis = Column(JSON, nullable=True)
    analyzed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    incident = relationship("Incident", back_populates="logs")
    analyzer = relationship("User", back_populates="logs_analyzed")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)  # prometheus, kubernetes, manual
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String, default="warning")  # warning, critical
    status = Column(String, default="active")  # active, acknowledged, resolved
    metric_value = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class CloudResource(Base):
    __tablename__ = "cloud_resources"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, default="aws")
    resource_type = Column(String, nullable=False)  # ec2, ebs, s3, rds
    resource_id = Column(String, nullable=False, unique=True)
    cost_per_hour = Column(Float, default=0.0)
    state = Column(String, default="active")  # active, idle, unused
    last_scanned_at = Column(DateTime, default=datetime.datetime.utcnow)


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, default="cost")  # cost, security, performance
    description = Column(Text, nullable=False)
    potential_savings = Column(Float, default=0.0)
    status = Column(String, default="pending")  # pending, applied, dismissed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=False)
    role = Column(String, nullable=False)  # user, assistant
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
