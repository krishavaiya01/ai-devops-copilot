import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import Base, engine, SessionLocal
from app.core.security import get_password_hash
from app.models.models import User, Project, Incident, Alert, CloudResource, Recommendation
from app.api.routers import auth, logs, incidents, alerts, chat, recommendations, metrics

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Production-grade AI DevOps Copilot API Platform",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Set to specific domains in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus Metric Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Don't track requests to the metrics scraper endpoint itself
    path = request.url.path
    if path == "/metrics":
        return await call_next(request)
        
    response = None
    try:
        response = await call_next(request)
        status_code = str(response.status_code)
        return response
    except Exception as e:
        status_code = "500"
        raise e
    finally:
        process_time = time.time() - start_time
        # Record prometheus metrics
        metrics.REQUEST_COUNT.labels(
            method=request.method,
            endpoint=path,
            http_status=status_code
        ).inc()
        
        metrics.REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=path
        ).observe(process_time)

# Include Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(logs.router, prefix=settings.API_V1_STR)
app.include_router(incidents.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(chat.router, prefix=settings.API_V1_STR)
app.include_router(recommendations.router, prefix=settings.API_V1_STR)
app.include_router(metrics.router)  # Expose /metrics at root level for Prometheus scraping

# Seeding Logic
def seed_database():
    db: Session = SessionLocal()
    try:
        # 1. Seed default Users if none exist
        if db.query(User).count() == 0:
            print("Seeding database with default user profiles...")
            admin_user = User(
                username="admin",
                email="admin@devopscopilot.io",
                password_hash=get_password_hash("admin123"),
                role="admin"
            )
            engineer_user = User(
                username="engineer",
                email="sre@devopscopilot.io",
                password_hash=get_password_hash("engineer123"),
                role="engineer"
            )
            db.add_all([admin_user, engineer_user])
            db.commit()
            db.refresh(admin_user)
            db.refresh(engineer_user)
            
            # 2. Seed a default Project
            demo_project = Project(
                name="Production Kubernetes Cluster",
                description="Primary AWS EKS Cluster hosting customer facing applications, microservices, and storage backends.",
                owner_id=admin_user.id
            )
            db.add(demo_project)
            db.commit()
            db.refresh(demo_project)
            
            # 3. Seed initial Incidents
            incident_1 = Incident(
                project_id=demo_project.id,
                title="API Gateway Container CrashLoopBackOff",
                description="The API Ingress Gateway is returning high 5xx error rates. Describe pods displays repeated container restarts with exit code 137.",
                severity="critical",
                status="investigating",
                timeline=[
                    {
                        "timestamp": "2026-06-03T10:15:00Z",
                        "event": "Automated alarm triggered for Ingress gateway health checking.",
                        "user": "System"
                    },
                    {
                        "timestamp": "2026-06-03T10:20:00Z",
                        "event": "Incident acknowledged by engineer.",
                        "user": "engineer"
                    },
                    {
                        "timestamp": "2026-06-03T10:30:00Z",
                        "event": "Ran AI log analysis. Diagnostic result points to memory limit exhaustion (OOMKilled).",
                        "user": "engineer"
                    }
                ]
            )
            
            incident_2 = Incident(
                project_id=demo_project.id,
                title="Database Replication Lag Latency Spike",
                description="Primary-Secondary database sync lag has exceeded 5 seconds. Read operations are serving stale transactional states.",
                severity="high",
                status="open",
                timeline=[
                    {
                        "timestamp": "2026-06-03T10:50:00Z",
                        "event": "Replication latency alarm fired on Prometheus metrics channel.",
                        "user": "System"
                    }
                ]
            )
            db.add_all([incident_1, incident_2])
            
            # 4. Seed initial Alerts
            alert_1 = Alert(
                source="prometheus",
                title="Pod OOMKilled Warning",
                message="Pod api-gateway-7f89bcd-xx22 was terminated by OOM Killer on node ip-10-0-12-86.us-east-1.compute.internal.",
                severity="critical",
                status="active",
                metric_value="exit_code=137"
            )
            alert_2 = Alert(
                source="prometheus",
                title="HTTP 5xx Error Rate High",
                message="Ingress controller reporting 5.2% error rate over the last 5 minutes on path /v1/auth.",
                severity="warning",
                status="active",
                metric_value="rate=5.2%"
            )
            alert_3 = Alert(
                source="kubernetes",
                title="PersistentVolumeClaim Binding Issue",
                message="PVC db-data-pvc has been in Pending state for more than 15 minutes due to volume scheduler lock.",
                severity="warning",
                status="active",
                metric_value="pvc_state=pending"
            )
            db.add_all([alert_1, alert_2, alert_3])
            
            # 5. Seed Cloud Cost Resources
            res_1 = CloudResource(
                provider="aws",
                resource_type="ec2",
                resource_id="i-0abcd1234efgh5678",
                cost_per_hour=0.76,  # m5.2xlarge
                state="idle",
                last_scanned_at=settings.DATABASE_URL.startswith("sqlite") and None or None  # Set dynamically
            )
            res_2 = CloudResource(
                provider="aws",
                resource_type="ebs",
                resource_id="vol-0123456789abcdef0",
                cost_per_hour=0.04,  # Unused 250 GB GP2 EBS volume
                state="unused"
            )
            res_3 = CloudResource(
                provider="aws",
                resource_type="ec2",
                resource_id="i-0987654321fedcba0",
                cost_per_hour=0.38,  # t3.xlarge
                state="active"
            )
            db.add_all([res_1, res_2, res_3])
            
            # 6. Seed Cost Recommendations
            rec_1 = Recommendation(
                category="cost",
                description="Terminate idle EC2 instance i-0abcd1234efgh5678 (m5.2xlarge). It has had < 1% CPU utilization for the past 14 days.",
                potential_savings=547.20,  # ~0.76 * 24 * 30
                status="pending"
            )
            rec_2 = Recommendation(
                category="cost",
                description="Delete unattached EBS volume vol-0123456789abcdef0 (250GB gp2). Unattached for over 30 days.",
                potential_savings=25.00,
                status="pending"
            )
            rec_3 = Recommendation(
                category="cost",
                description="Upgrade active EBS volumes from gp2 to gp3. Saves up to 20% on storage costs while maintaining equivalent throughput and IOPS scaling.",
                potential_savings=145.50,
                status="pending"
            )
            db.add_all([rec_1, rec_2, rec_3])
            
            db.commit()
            print("Database pre-seeding completed successfully!")
    except Exception as e:
        print(f"Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

# Execute seed
seed_database()

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "AI DevOps Copilot API",
        "endpoints": {
            "metrics": "/metrics",
            "api_health": "/api/metrics/dashboard",
            "docs": "/docs"
        }
    }
