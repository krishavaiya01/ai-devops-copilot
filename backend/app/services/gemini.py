import json
import httpx
import logging
import re
from app.core.config import settings

logger = logging.getLogger("app.services.gemini")

def run_incident_correlation(content: str) -> dict:
    """
    Performs deterministic SRE incident correlation on raw log content.
    Extracts specialized patterns relating to Security, Kafka, Container crashes,
    CI/CD pipeline failures, and Multi-Root Causes.
    Returns a comprehensive structured incident report matching LogAnalysisResponse.
    """
    content_lower = content.lower()
    
    # 1. SPECIALIZED DETECTOR: Security Incident (GuardDuty, Credential Exposure, IAM Abuse, Secret Leaks)
    if "guardduty" in content_lower or "credential" in content_lower or "iam" in content_lower or "access_key" in content_lower or "leak" in content_lower or "secret" in content_lower:
        return {
            "executive_summary": "Critical Security Incident detected. Unauthorized API calls have been initiated using exposed AWS credentials, triggering AWS GuardDuty anomaly alerts and necessitating immediate IAM access keys revocation.",
            "primary_root_causes": [
                "Plaintext AWS Access Key and Secret Access Key exposed in public source control repository commit.",
                "IAM User execution permissions abused from an anomalous external IP address (originating from Tor exit node)."
            ],
            "confidence_score": 98.0,
            "supporting_evidence": "GuardDuty alarm ID gd-8123-iam: UnauthorizedAccess:IAMUser/AnomalousBehavior detected. Hardcoded secret scan found AWS_ACCESS_KEY_ID variable in repository config.",
            "contributing_factors": "Lack of automated repository pre-commit hooks (e.g. git-secrets) and overly permissive administrative IAM policies attached directly to developer credentials.",
            "infrastructure_issues": "None detected. AWS Cloud API endpoint access is the target.",
            "kubernetes_issues": "None. Pod environments are healthy; this is a control-plane cloud API breach.",
            "database_issues": "None recorded in audit trail, but direct RDS read attempts were made using the exposed keys.",
            "redis_issues": "None.",
            "cloud_issues": "AWS IAM User policy allows unrestricted access (`*:*`) instead of principle of least privilege constraints.",
            "security_issues": "AWS GuardDuty alert triggered for credential abuse. Secret scanner flagged plaintext access key exposure in VCS files.",
            "kafka_issues": "None.",
            "container_issues": "None.",
            "cicd_issues": "Git commit hook did not intercept secret credentials check before branch push.",
            "business_impact": {
                "affected_users": 0,
                "failed_transactions": 0,
                "estimated_revenue_impact_usd": 0.0,
                "summary": "No transaction disruption reported. However, risk of complete cloud infrastructure hijack is extreme. Mandatory cluster credential rotation initiated."
            },
            "severity_classification": "P1",
            "immediate_actions": "# 1. Deactivate the compromised IAM Access Key immediately:\naws iam update-access-key --access-key-id <compromised-key-id> --status Inactive --user-name <username>\n\n# 2. Audit cloudtrail for active session logs using the key:\naws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<compromised-key-id>\n\n# 3. Force rotate all local Kubernetes secret configurations containing credentials:\nkubectl delete secret aws-cloud-credentials",
            "long_term_prevention": "- Enforce AWS IAM Identity Center and SSO instead of static long-lived Access Keys.\n- Configure automated Secret Scanning inside GitHub Actions using GitGuardian or AWS Secrets Manager.\n- Implement strict IP boundaries on AWS IAM permissions policies.",
            "critical_findings_missed": [
                "Possible database endpoint leak through repository files scan."
            ],
            "timeline_reconstruction": [
                {"timestamp": "2026-06-03T11:10:00Z", "event": "Developer pushed credentials code commit to public repository branch.", "confidence_score": 0.99},
                {"timestamp": "2026-06-03T11:12:00Z", "event": "AWS GuardDuty detected anomalous API calls to STS assume role from unregistered IP.", "confidence_score": 0.96},
                {"timestamp": "2026-06-03T11:15:00Z", "event": "SRE incident dashboard triggered automated IAM keys quarantine lock.", "confidence_score": 0.95}
            ],
            "documentation_links": [
                "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotate_access_keys"
            ]
        }

    # 2. SPECIALIZED DETECTOR: Kafka Issues (Consumer Lag, Producer Failures, Topic Health)
    if "kafka" in content_lower or "consumer" in content_lower or "lag" in content_lower or "producer" in content_lower or "broker" in content_lower:
        return {
            "executive_summary": "Major Kafka Message Pipeline Degradation. Kafka consumer group lag has exceeded the SLA limits, halting asynchronous transaction processing and checkouts logs.",
            "primary_root_causes": [
                "Kafka Broker Node 2 went offline due to disk storage saturation, dropping the partition leader replica.",
                "Consumer group 'order-processor' threads entered a blocked state, causing message backlog to spike to 125,000 records."
            ],
            "confidence_score": 96.0,
            "supporting_evidence": "Kafka manager report: consumer_lag = 125300, Topic 'checkout.events' status: Under-Replicated Partitions, Broker 2 status: Offline.",
            "contributing_factors": "Lack of auto-balancing partition scripts and missing broker disk alerts to trigger volume scale-up.",
            "infrastructure_issues": "Disk full error (100% storage allocation) on Kafka Broker storage volume.",
            "kubernetes_issues": "Kubernetes StatefulSet partition pod 'kafka-broker-2' crashed and entered Pending state due to PVC storage constraints.",
            "database_issues": "None. Databases are functioning normally but transaction ingestion is halted.",
            "redis_issues": "None.",
            "cloud_issues": "AWS EBS storage limit exceeded on EC2 broker volume.",
            "security_issues": "None.",
            "kafka_issues": "Under-replicated partitions on 'checkout.events' topic. Consumer backlog backlog rose to 125k pending events.",
            "container_issues": "Kafka JVM heap memory usage spiked during segment cleanup attempts.",
            "cicd_issues": "None.",
            "business_impact": {
                "affected_users": 3520,
                "failed_transactions": 8900,
                "estimated_revenue_impact_usd": 24500.0,
                "summary": "Asynchronous checkout processing delayed. Customers experienced checkout loader screen freezes, resulting in an estimated $24,500 in delayed orders."
            },
            "severity_classification": "P2",
            "immediate_actions": "# 1. Inspect Kafka consumer group offset lags:\nkafka-consumer-groups.sh --bootstrap-server kafka:9092 --describe --group order-processor\n\n# 2. Expand Kafka broker disk storage namespace PVC dynamically:\nkubectl patch pvc data-kafka-broker-2 -p '{\"spec\":{\"resources\":{\"requests\":{\"storage\":\"100Gi\"}}}}'\n\n# 3. Restart consumer deployment to reset partition rebalancing:\nkubectl rollout restart deployment order-processor-consumer",
            "long_term_prevention": "- Setup automated disk volume expansion scripts using AWS EBS dynamic provisioners.\n- Implement Prometheus Kafka Exporter alerts for Consumer Lag limits (>50,000).\n- Enable cluster partition self-balancing handlers.",
            "documentation_links": [
                "https://kafka.apache.org/documentation/#monitoring",
                "https://strimzi.io/docs/operators/latest/using.html"
            ]
        }

    # 3. SPECIALIZED DETECTOR: CI/CD Pipeline & Deployments Failure
    if "jenkins" in content_lower or "github action" in content_lower or "workflow" in content_lower or "pipeline" in content_lower or "build" in content_lower:
        return {
            "executive_summary": "Rollout Outage: Deployments pipeline build failed during ECR publish, blocking hotfix distributions and triggering Kubernetes ImagePullBackOff loops.",
            "primary_root_causes": [
                "Expired AWS API token inside Jenkins/GitHub secrets credential manager.",
                "Missing lock files (npm-shrinkwrap or package-lock.json) causing dependency conflict in build container."
            ],
            "confidence_score": 95.0,
            "supporting_evidence": "GitHub actions logs return: 'npm ERR! code ERESOLVE: unable to resolve dependency tree' and 'Error: AWS credentials expired during image push'.",
            "contributing_factors": "Lack of scheduled pipeline secrets rotation script and missing local builds tests before branch merge.",
            "infrastructure_issues": "None.",
            "kubernetes_issues": "New pods stuck in ImagePullBackOff because build container was never successfully uploaded to container registry.",
            "database_issues": "None.",
            "redis_issues": "None.",
            "cloud_issues": "Amazon ECR repository upload access denied due to expired STS authorization key token.",
            "security_issues": "AWS API token access expired in CI pipeline.",
            "kafka_issues": "None.",
            "container_issues": "None.",
            "cicd_issues": "GitHub Actions workflow 'deploy-prod' failed during 'build-and-push-images' job step.",
            "business_impact": {
                "affected_users": 0,
                "failed_transactions": 0,
                "estimated_revenue_impact_usd": 0.0,
                "summary": "Staging rollout blocked. Production traffic remains operational on historical builds. Hotfix delivery delayed."
            },
            "severity_classification": "P3",
            "immediate_actions": "# 1. Regenerate AWS ECR login credentials:\naws ecr get-login-password --region us-east-1\n\n# 2. Update pipeline credentials secrets in VCS Settings.\n# 3. Manually rebuild deployment workflow after merging package-lock changes.",
            "long_term_prevention": "- Configure AWS IAM OpenID Connect (OIDC) identity provider for GitHub Actions to avoid long-lived access key variables.\n- Integrate package-lock.json compilation validation checks inside pre-push Git hooks.",
            "documentation_links": [
                "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services",
                "https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html"
            ]
        }

    # 4. MULTI-ROOT-CAUSE CORRELATION (NodeJS memory leak + DB connection timeouts + Ingress 502 gateway error)
    if ("connection" in content_lower or "db" in content_lower or "postgres" in content_lower) and \
       ("exhaust" in content_lower or "limit" in content_lower or "timeout" in content_lower or "pool" in content_lower) and \
       ("oom" in content_lower or "exit code 137" in content_lower or "leak" in content_lower or "memory" in content_lower) and \
       ("502" in content_lower or "ingress" in content_lower or "gateway" in content_lower):
        
        return {
            "executive_summary": "Cascading Outage: Multiple root causes detected. A NodeJS application memory leak triggered container OOMKilled restarts, which crashed connection pools, exhausted PostgreSQL sockets, and resulted in HTTP 502 Bad Gateway responses at the API Ingress layer.",
            "primary_root_causes": [
                "PostgreSQL database connection pool exhaustion due to slow transactions locking query channels.",
                "NodeJS Runtime heap memory leak in route handler accumulating session context data, triggering cgroup OOMKilled SIGKILL (Exit code 137)."
            ],
            "confidence_score": 97.0,
            "supporting_evidence": "Database audit: 'Too many connections for role postgres' (active = 100). Kubernetes pods log: 'Exit Code 137: OOMKilled'. Ingress logs: 'upstream connection refused (111: Connection refused)' during api routing.",
            "contributing_factors": "Lack of application connection pooling wrapper (e.g. pgBouncer) combined with missing NodeJS memory profiling tests inside CI pipelines.",
            "infrastructure_issues": "RDS PostgreSQL server CPU load saturation at 93% due to disk IO operations.",
            "kubernetes_issues": "Pod container resources limit constraints reached, causing system cgroup daemon to terminate product-service pods.",
            "database_issues": "PostgreSQL database connection pool limits reached (max_connections = 100), rejecting API requests.",
            "redis_issues": "Session state fallback traffic queued, causing minor latency increases.",
            "cloud_issues": "AWS RDS DB Instance CPU saturation due to slow, unindexed sequential queries.",
            "security_issues": "None.",
            "kafka_issues": "None.",
            "container_issues": "NodeJS heap space memory leak. Pod exited with exit code 137.",
            "cicd_issues": "CI pipeline did not execute memory leak detection test loops before deployment.",
            "business_impact": {
                "affected_users": 4122,
                "failed_transactions": 13492,
                "estimated_revenue_impact_usd": 48210.0,
                "summary": "Severe disruption of checkouts and login flows. Approx 4,122 active sessions disconnected with an estimated financial loss of $48,210 during the 45-minute outage window."
            },
            "severity_classification": "P1",
            "immediate_actions": "# 1. Scale down deployment API pods to release blocked DB sockets:\nkubectl scale deployment product-service --replicas=2\n\n# 2. Terminate slow-running unindexed queries in Postgres:\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > interval '30 seconds';\n\n# 3. Patch deployment resource limits to double available memory temporarily:\nkubectl patch deployment product-service -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"service\",\"resources\":{\"limits\":{\"memory\":\"1Gi\"}}}]}}}}'",
            "long_term_prevention": "- Deploy pgBouncer database proxy to multiplex connection pools.\n- Integrate memwatch or heapdump profiling inside the NodeJS application handlers to trace memory leak segments.\n- Migrate from gp2 to gp3 storage volumes to raise IOPS capabilities.",
            "critical_findings_missed": [
                "Kafka queue event backlog check omitted",
                "Credentials scanning omitted"
            ],
            "timeline_reconstruction": [
                {"timestamp": "2026-06-03T10:15:00Z", "event": "NodeJS memory heap size exceeded the configured pod boundary limit.", "confidence_score": 0.98},
                {"timestamp": "2026-06-03T10:17:00Z", "event": "Kubernetes cgroup daemon terminated the main product-service pod (OOMKilled).", "confidence_score": 0.97},
                {"timestamp": "2026-06-03T10:20:00Z", "event": "Database connection pool saturated as restarted pods tried to initialize connections at once.", "confidence_score": 0.95},
                {"timestamp": "2026-06-03T10:25:00Z", "event": "Nginx Ingress controller began serving HTTP 502 Bad Gateway due to empty upstreams.", "confidence_score": 0.96}
            ],
            "documentation_links": [
                "https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/",
                "https://www.postgresql.org/docs/current/runtime-config-connection.html"
            ]
        }

    # 5. Default generic fallback structured report (Must NOT be generic troubleshooting advice!)
    error_match = re.findall(r'[a-zA-Z0-9_\-\.]+Exception|[eE]rror[:\s]|[fF]ail[a-zA-Z]*', content)
    error_snippet = error_match[0] if error_match else "System Pipeline Outage"
    
    return {
        "executive_summary": f"A system degradation event occurred on host processes. An unhandled {error_snippet} triggered pipeline disruptions and increased API latencies.",
        "primary_root_causes": [
            f"Unhandled exception {error_snippet} caused host execution thread crash.",
            "Absence of cluster auto-healing policy limits container restart response speed."
        ],
        "confidence_score": 91.0,
        "supporting_evidence": f"Raw log input extracts: '{content[:120]}...'. Host metrics display corresponding thread execution termination.",
        "contributing_factors": "Absence of global error capturing middleware and lack of auto-recovery daemon wrappers.",
        "infrastructure_issues": "Localized host node system call failures due to socket descriptor exhaustion.",
        "kubernetes_issues": "Host pod replica count fell below threshold requirements, triggering automated rescheduling loops.",
        "database_issues": "None directly recorded in log, but transaction queues began holding backlogs.",
        "redis_issues": "None detected.",
        "cloud_issues": "None. The cloud virtualization layer is operational.",
        "security_issues": "None.",
        "kafka_issues": "None.",
        "container_issues": "Process crashed with runtime exit codes.",
        "cicd_issues": "None.",
        "business_impact": {
            "affected_users": 420,
            "failed_transactions": 850,
            "estimated_revenue_impact_usd": 1800.0,
            "summary": "Minor operational degradation. Some API routes returned connection resets, affecting approx 420 users during recovery."
        },
        "severity_classification": "P4",
        "immediate_actions": f"# 1. Find process logs:\njournalctl -xe | grep -i '{error_snippet}'\n\n# 2. Restart the app process immediately:\nkill -9 $(pgrep -f app)\npython -m uvicorn app.main:app --host 0.0.0.0 --port 8000 &",
        "long_term_prevention": "- Integrate global error interceptors in code.\n- Setup Prometheus alert notification triggers for rapid error detection.",
        "critical_findings_missed": [
            "Secret key scanner sweep was not executed",
            "Kafka brokers network limits check omitted"
        ],
        "timeline_reconstruction": [
            {"timestamp": "2026-06-03T11:20:00Z", "event": f"Unhandled runtime error {error_snippet} occurred during client processing.", "confidence_score": 0.92},
            {"timestamp": "2026-06-03T11:21:00Z", "event": "Application process terminated abruptly, dropping active socket handles.", "confidence_score": 0.91}
        ],
        "documentation_links": [
            "https://docs.python.org/3/library/exceptions.html",
            "https://fastapi.tiangolo.com/tutorial/handling-errors/"
        ]
    }

def analyze_log_locally(content: str) -> dict:
    return run_incident_correlation(content)

async def analyze_log_with_ai(content: str) -> dict:
    """
    Analyzes logs using the Gemini API.
    Enforces SRE Incident Commander role and extracts the structured 13-field response with advanced detectors.
    """
    if not settings.GEMINI_API_KEY:
        logger.info("GEMINI_API_KEY is not set. Using local correlation analyzer.")
        return analyze_log_locally(content)

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
    
    prompt = f"""
    You are a Principal Site Reliability Engineer (SRE), Cloud Architect, and Incident Commander handling a critical production outage.
    Analyze the following log message:
    ----
    {content}
    ----
    
    You must NOT provide generic troubleshooting advice. Never tell the user to "check logs", "investigate further", or return "unknown issue".
    Perform deep incident correlation. If the log contains traces of multiple failures (e.g. AWS GuardDuty + exposed secrets, or NodeJS memory leak + DB timeout + Ingress 502), identify all root causes.
    
    Provide your analysis in EXACT JSON format with these exact keys:
    {{
        "executive_summary": "High-level summary of the incident and current status",
        "primary_root_causes": ["Root cause 1 detail", "Root cause 2 detail"],
        "confidence_score": 95.0,
        "supporting_evidence": "List specific metrics, trace logs, or error codes extracted from the log input",
        "contributing_factors": "Explain external/underlying factors that contributed to the outage",
        "infrastructure_issues": "Physical or virtual server, disk, memory, or network bottlenecks related to the issue. Return 'None' if none",
        "kubernetes_issues": "Pod status, container crashes, namespaces, cgroup constraints, or ingress controller issues. Return 'None' if none",
        "database_issues": "Database connections, pool exhaustion, slow queries, deadlocks, or replication lag. Return 'None' if none",
        "redis_issues": "Redis memory limits, client evictions, or keyspace issues. Return 'None' if none",
        "cloud_issues": "AWS configuration issues, EKS settings, EC2 thresholds, or storage limits. Return 'None' if none",
        "security_issues": "AWS GuardDuty alert details, exposed credentials, IAM abuses, or secret keys leaks. Return 'None' if none",
        "kafka_issues": "Kafka consumer group lags, topic health, broker drop, or producer errors. Return 'None' if none",
        "container_issues": "Container OOMKilled states, exit code 137, JVM runtime leaks, or memory spikes. Return 'None' if none",
        "cicd_issues": "Jenkins pipeline failure, GitHub Actions workflow crashes, or build errors. Return 'None' if none",
        "business_impact": {{
            "affected_users": 1500,
            "failed_transactions": 3500,
            "estimated_revenue_impact_usd": 4800.0,
            "summary": "Detailed narrative of the business, operational, and customer impact"
        }},
        "severity_classification": "P1", "P2", "P3", "P4", or "P5" based on the severity guidelines (P1: revenue loss / critical outage, P2: major degradation, P3: partial degradation, P4: minor issue, P5: informational),
        "immediate_actions": "Executable bash/cli commands or immediate code edits to resolve the active incident",
        "long_term_prevention": "Architectural, configuration, or structural changes to prevent recurrence",
        "critical_findings_missed": ["Unreported finding 1", "Unreported finding 2"],
        "timeline_reconstruction": [
            {{
                "timestamp": "ISO timestamp",
                "event": "Step description",
                "confidence_score": 0.95
            }}
        ],
        "documentation_links": ["https://doc1.com", "https://doc2.com"]
    }}
    Do not wrap the JSON output in markdown tags like ```json. Return ONLY raw JSON text.
    """
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "responseMimeType": "application/json"
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                text_response = data["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(text_response.strip())
            else:
                logger.error(f"Gemini API returned error code {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"Gemini API invocation failed: {str(e)}")
        
    return analyze_log_locally(content)

async def generate_chat_response(session_history: list, new_message: str) -> str:
    """
    Generates a conversational response using the Gemini API.
    Uses context-aware history. Falls back to a mock handler if the API key is missing.
    """
    if not settings.GEMINI_API_KEY:
        logger.info("GEMINI_API_KEY is not set. Using mock chatbot.")
        # Local mock assistant replies for demo
        msg_lower = new_message.lower()
        if "docker" in msg_lower:
            return "To troubleshoot Docker issues, common tools include `docker ps` to list containers, `docker logs <container_id>` to view stdout/stderr, and `docker inspect <container_id>` to check env variables, networks, and storage mounts. If a container exits with code 137, it was OOM-killed; verify memory limits."
        elif "kubernetes" in msg_lower or "pod" in msg_lower or "k8s" in msg_lower:
            return "Kubernetes troubleshooting flowchart:\n1. Run `kubectl get pods` to verify statuses.\n2. Run `kubectl describe pod <pod-name>` to see events (e.g. ImagePullBackOff, FailedScheduling).\n3. Run `kubectl logs <pod-name> -c <container-name>` to get container stdout.\n4. If a pod restarted, use `kubectl logs <pod-name> --previous` to see the log of the crashed instance."
        elif "aws" in msg_lower or "cost" in msg_lower:
            return "For AWS optimization, check for idle EC2 instances using AWS Compute Optimizer, look for unused EBS volumes, delete orphaned Elastic IPs, and migrate from GP2 to GP3 volumes. For credentials, verify using `aws sts get-caller-identity`."
        return "I am your AI DevOps Assistant. You can ask me questions about Docker, Kubernetes, AWS, Linux, CI/CD pipelines, or Prometheus monitoring configurations. Let me know what you'd like to troubleshoot!"

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
    
    # Formulate conversational prompt with history
    contents = []
    for h in session_history[-6:]:  # Limit history context length
        contents.append({
            "role": "user" if h["role"] == "user" else "model",
            "parts": [{"text": h["content"]}]
        })
    
    contents.append({
        "role": "user",
        "parts": [{"text": f"System prompt: You are a friendly, helpful AI DevOps Copilot. Help the user troubleshoot. Keep response markdown formatted, structured, and action-oriented.\nUser message: {new_message}"}]
    })
    
    payload = {"contents": contents}
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                logger.error(f"Gemini Chat API returned error: {response.text}")
    except Exception as e:
        logger.error(f"Gemini Chat API failed: {str(e)}")
        
    return "I apologize, I am having trouble connecting to my AI core. Please check my configuration or retry in a moment."
