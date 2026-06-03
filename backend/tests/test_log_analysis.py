from app.services.gemini import run_incident_correlation

def test_multi_root_cause_log_analysis():
    log_content = """
    14:03 Credential Exposure in public commit.
    14:05 DNS Failure: Route53 query failed NXDOMAIN.
    14:10 OOMKilled: NodeJS heap limit reached, Exit Code 137.
    14:12 Kafka Backlog: consumer lag = 125300 on checkout.events.
    14:14 EBS Saturation: volume-08f23 disk full (100% capacity).
    Affected Users: 5,200
    Failed Transactions: 11,000
    Revenue Impact: $1,842,330
    """
    
    result = run_incident_correlation(log_content)
    
    # Assert executive summary is present
    assert result["executive_summary"]
    
    # Assert business impact parses correctly and DOES NOT TRUNCATE COMMAS
    assert result["business_impact"]["affected_users"] == 5200
    assert result["business_impact"]["failed_transactions"] == 11000
    assert result["business_impact"]["estimated_revenue_impact_usd"] == 1842330.0
    
    # Assert subsystems are updated to Critical
    assert result["subsystem_analysis"]["security"]["status"] == "Critical"
    assert result["subsystem_analysis"]["dns"]["status"] == "Critical"
    assert result["subsystem_analysis"]["kubernetes"]["status"] == "Critical"
    assert result["subsystem_analysis"]["kafka"]["status"] == "Critical"
    assert result["subsystem_analysis"]["aws_infrastructure"]["status"] == "Critical"
    assert "Storage Full" in result["subsystem_analysis"]["aws_infrastructure"]["findings"]
    
    # Assert timeline reconstruction is present and SRE event-normalized
    timeline = result["timeline_reconstruction"]
    assert len(timeline) >= 5
    assert timeline[0]["event"] == "AWS GuardDuty Alert"
    assert timeline[1]["event"] == "DNS Resolution Errors"
    assert timeline[2]["event"] == "OOMKilled"

def test_evidence_validation_success():
    # If build succeeds, never trigger deployment failures
    log_content = """
    12:00 Build SUCCESS
    All modules operational.
    """
    result = run_incident_correlation(log_content)
    assert result["subsystem_analysis"]["cicd"]["status"] == "Healthy"

def test_infrastructure_parser_differentiation():
    # Test Storage Full
    log_1 = "AWS EBS saturation: volume disk full (100% capacity)"
    res_1 = run_incident_correlation(log_1)
    assert "Storage Full" in res_1["subsystem_analysis"]["aws_infrastructure"]["findings"]
    
    # Test IOPS Saturation
    log_2 = "EBS IOPS limit reached maximum threshold, disk latency high"
    res_2 = run_incident_correlation(log_2)
    assert "IOPS Saturation" in res_2["subsystem_analysis"]["aws_infrastructure"]["findings"]
    
    # Test Throughput Saturation
    log_3 = "AWS storage throughput saturation mb/s limit reached"
    res_3 = run_incident_correlation(log_3)
    assert "Throughput Saturation" in res_3["subsystem_analysis"]["aws_infrastructure"]["findings"]
