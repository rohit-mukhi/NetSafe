"""
Integration layer between NetSafe detection and threat mitigation agent.
Converts detection results to threats and triggers mitigation.
"""
import uuid
from datetime import datetime
from typing import Optional, Tuple, List, Dict

from agent.threat_model import (
    Threat, ThreatType, ThreatLevel, ThreatIndicator, MitigationPlan
)
from agent.agent import ThreatMitigationAgent, AgentConfig, get_agent


def get_or_create_agent() -> ThreatMitigationAgent:
    """Get or create the global agent instance with safe configuration."""
    try:
        return get_agent()
    except Exception as e:
        print(f"Error initializing agent: {e}")
        return None


def detection_result_to_threat(
    predictions: List[int],
    total_samples: int,
    anomalies_detected: int,
    anomaly_scores: Optional[List[float]] = None,
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    port: Optional[int] = None,
    raw_data: Optional[Dict] = None
) -> Threat:
    """
    Convert detection results to Threat model.
    
    Args:
        predictions: Array of predictions (-1 for anomaly, 1 for normal)
        total_samples: Total number of samples
        anomalies_detected: Count of detected anomalies
        anomaly_scores: Anomaly scores for each sample
        source_ip: Source IP address if available
        dest_ip: Destination IP address if available
        port: Port number if available
        raw_data: Additional raw data about the threat
        
    Returns:
        Threat object
    """
    anomaly_rate = anomalies_detected / max(total_samples, 1)
    
    # Determine threat type and level based on anomaly characteristics
    threat_type, threat_level = _classify_threat(
        predictions, anomaly_rate, anomaly_scores, port
    )
    
    # Build indicators
    indicators = [
        ThreatIndicator(
            indicator_type="anomaly_rate",
            value=anomaly_rate,
            threshold=0.05,  # 5% threshold
            severity_contribution=min(anomaly_rate * 2, 1.0)
        )
    ]
    
    if anomaly_scores is not None and len(anomaly_scores) > 0:
        mean_score = sum(anomaly_scores) / len(anomaly_scores)
        indicators.append(ThreatIndicator(
            indicator_type="mean_anomaly_score",
            value=mean_score,
            threshold=0.5,
            severity_contribution=min(mean_score, 1.0)
        ))
    
    confidence = min(anomaly_rate + 0.1, 1.0)  # Confidence based on anomaly rate
    
    threat = Threat(
        threat_id=f"threat_{uuid.uuid4().hex[:8]}",
        threat_type=threat_type,
        level=threat_level,
        source_ip=source_ip,
        dest_ip=dest_ip,
        port=port,
        timestamp=datetime.now(),
        indicators=indicators,
        description=_get_threat_description(threat_type, anomaly_rate),
        confidence=confidence,
        raw_data=raw_data or {}
    )
    
    return threat


def _classify_threat(
    predictions: List[int],
    anomaly_rate: float,
    anomaly_scores: Optional[List[float]] = None,
    port: Optional[int] = None
) -> Tuple[ThreatType, ThreatLevel]:
    """
    Classify threat type and level based on detection characteristics.
    
    Returns:
        (threat_type, threat_level)
    """
    # Default to generic anomaly
    threat_type = ThreatType.ANOMALOUS_TRAFFIC
    
    # Heuristics for threat type classification
    if port in [22, 23, 3389]:  # SSH, Telnet, RDP
        threat_type = ThreatType.BRUTE_FORCE
    elif port in [80, 443, 8080]:  # HTTP ports
        if anomaly_rate > 0.3:
            threat_type = ThreatType.DDOS
    elif port in [53]:  # DNS
        threat_type = ThreatType.ANOMALOUS_TRAFFIC
    
    # Determine severity level
    if anomaly_rate > 0.5:
        threat_level = ThreatLevel.CRITICAL
    elif anomaly_rate > 0.2:
        threat_level = ThreatLevel.HIGH
    elif anomaly_rate > 0.1:
        threat_level = ThreatLevel.MEDIUM
    else:
        threat_level = ThreatLevel.LOW
    
    return threat_type, threat_level


def _get_threat_description(threat_type: ThreatType, anomaly_rate: float) -> str:
    """Generate a description for the threat."""
    descriptions = {
        ThreatType.DDOS: f"DDoS attack detected with {anomaly_rate*100:.1f}% anomalous traffic",
        ThreatType.BRUTE_FORCE: f"Brute force attack detected with {anomaly_rate*100:.1f}% failed attempts",
        ThreatType.PORT_SCAN: f"Port scan activity detected with {anomaly_rate*100:.1f}% suspicious patterns",
        ThreatType.C2_COMMUNICATION: f"C2 communication detected with {anomaly_rate*100:.1f}% confidence",
        ThreatType.DATA_EXFILTRATION: f"Data exfiltration detected with {anomaly_rate*100:.1f}% anomalous flows",
        ThreatType.UNAUTHORIZED_ACCESS: f"Unauthorized access detected with {anomaly_rate*100:.1f}% anomalies",
        ThreatType.ANOMALOUS_TRAFFIC: f"Anomalous traffic detected with {anomaly_rate*100:.1f}% rate",
    }
    return descriptions.get(threat_type, f"Unknown threat detected with {anomaly_rate*100:.1f}% anomalies")


def trigger_agent_mitigation(
    threat: Threat,
    agent: Optional[ThreatMitigationAgent] = None,
    auto_execute: bool = False,
    dry_run: bool = True
) -> Tuple[Optional[MitigationPlan], List]:
    """
    Trigger agent mitigation for a detected threat.
    
    Args:
        threat: Threat to mitigate
        agent: Agent instance (creates one if None)
        auto_execute: Auto-execute mitigations without approval
        dry_run: Simulate without executing
        
    Returns:
        (mitigation_plan, results)
    """
    if agent is None:
        agent = get_or_create_agent()
    
    if agent is None:
        return None, []
    
    # Set agent configuration
    agent.set_auto_execute(auto_execute)
    agent.set_dry_run(dry_run)
    
    # Analyze and mitigate
    plan, results = agent.mitigate_threat(threat)
    
    return plan, results


def get_agent_status() -> Dict:
    """Get current agent status and system info."""
    agent = get_or_create_agent()
    
    if agent is None:
        return {
            "enabled": False,
            "error": "Agent initialization failed"
        }
    
    return {
        "enabled": agent.config.enabled,
        "auto_execute": agent.config.auto_execute,
        "dry_run": agent.config.dry_run,
        "system_info": agent.get_system_info(),
        "active_plans": agent.get_active_plans(),
        "execution_history": agent.get_execution_history(limit=10),
    }


def format_mitigation_result(plan: Optional[MitigationPlan], results: List) -> str:
    """Format mitigation result for display."""
    if not plan:
        return "❌ No mitigation plan generated"
    
    if not results:
        return f"⏳ Plan generated but not executed"
    
    success_count = sum(1 for r in results if r.success)
    total_count = len(results)
    
    if success_count == total_count:
        return f"✅ Successfully executed {total_count} mitigation actions"
    elif success_count > 0:
        return f"⚠️ Partially executed: {success_count}/{total_count} actions successful"
    else:
        return f"❌ Failed to execute any mitigations ({total_count} attempted)"
