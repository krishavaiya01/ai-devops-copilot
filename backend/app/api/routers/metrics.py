import time
import random
from fastapi import APIRouter, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Histogram, Gauge

router = APIRouter(tags=["metrics"])

# Define Prometheus metrics
REQUEST_COUNT = Counter(
    "devops_copilot_api_requests_total",
    "Total number of API requests received",
    ["method", "endpoint", "http_status"]
)

REQUEST_LATENCY = Histogram(
    "devops_copilot_api_request_duration_seconds",
    "API request latency in seconds",
    ["method", "endpoint"]
)

SYSTEM_CPU_USAGE = Gauge(
    "devops_copilot_system_cpu_usage_ratio",
    "Current CPU utilization ratio"
)

SYSTEM_MEMORY_USAGE = Gauge(
    "devops_copilot_system_memory_usage_bytes",
    "Current memory utilization in bytes"
)

# Populate some static system metrics for Prometheus
SYSTEM_CPU_USAGE.set(0.45)
SYSTEM_MEMORY_USAGE.set(4 * 1024 * 1024 * 1024)  # 4 GB

@router.get("/metrics")
def metrics():
    # Dynamically tweak system values slightly for scraped metrics
    SYSTEM_CPU_USAGE.set(0.3 + random.random() * 0.4)
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@router.get("/api/metrics/dashboard")
def get_dashboard_metrics():
    """
    Returns time-series metrics formatted for Recharts in the React frontend.
    This simulates standard metrics collected from Prometheus.
    """
    current_time = int(time.time())
    data = []
    
    # Generate 10 data points corresponding to past minutes
    for i in range(10):
        timestamp = current_time - (9 - i) * 60
        time_label = time.strftime("%H:%M", time.localtime(timestamp))
        
        # CPU fluctuates between 30% and 75%
        cpu = round(40 + random.uniform(-10, 15) + (5 if i > 7 else 0), 2)
        # Memory fluctuates around 65%
        memory = round(62 + random.uniform(-2, 3), 2)
        # Network in MB/s
        network_in = round(120 + random.uniform(-30, 40), 1)
        network_out = round(85 + random.uniform(-20, 30), 1)
        # API Latency in ms (e.g. 80ms - 250ms)
        latency = round(120 + random.uniform(-40, 80) + (100 if i == 6 else 0), 1)
        # Error rate (0% to 5%)
        error_rate = round(0.5 + random.uniform(-0.5, 1.5) if i != 5 else 4.2, 2)
        if error_rate < 0:
            error_rate = 0.0
            
        data.append({
            "time": time_label,
            "cpu": cpu,
            "memory": memory,
            "networkIn": network_in,
            "networkOut": network_out,
            "latency": latency,
            "errorRate": error_rate
        })
        
    return {
        "status": "success",
        "current": {
            "cpu": data[-1]["cpu"],
            "memory": data[-1]["memory"],
            "networkIn": data[-1]["networkIn"],
            "networkOut": data[-1]["networkOut"],
            "latency": data[-1]["latency"],
            "errorRate": data[-1]["errorRate"]
        },
        "series": data
    }
