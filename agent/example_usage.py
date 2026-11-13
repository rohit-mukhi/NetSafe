"""
Example usage of the Threat Mitigation Agent.
Demonstrates how to use the rule-based agent for threat analysis and mitigation.
"""
import uuid
from datetime import datetime
from pathlib import Path

from agent.threat_model import (
    Threat, ThreatType, ThreatLevel, ThreatIndicator, MitigationStatus
)
from agent.agent import ThreatMitigationAgent, AgentConfig


def example_1_ddos_detection():
    """Example 1: DDoS Attack Detection and Mitigation."""
    print("\n" + "="*80)
    print("EXAMPLE 1: DDoS Attack Detection and Mitigation")
    print("="*80)

    # Create agent with dry-run enabled
    config = AgentConfig(
        enabled=True,
        auto_execute=False,  # Require approval for destructive actions
        dry_run=True,  # Don't actually execute, just show what would happen
        require_approval_for_destructive=True
    )
    agent = ThreatMitigationAgent(config)

    # Create a simulated DDoS threat
    ddos_threat = Threat(
        threat_id=f"threat_{uuid.uuid4().hex[:8]}",
        threat_type=ThreatType.DDOS,
        level=ThreatLevel.HIGH,
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        port=80,
        timestamp=datetime.now(),
        indicators=[
            ThreatIndicator(
                indicator_type="packet_rate",
                value=50000.0,
                threshold=1000.0,
                severity_contribution=0.8
            )
        ],
        description="Possible DDoS attack with 50k packets/sec",
        confidence=0.95
    )

    # Analyze threat
    print("\n[Step 1] Analyzing threat...")
    plan = agent.analyze_threat(ddos_threat)

    if plan:
        print(f"✓ Generated mitigation plan: {plan.plan_id}")
        print(f"  - Threat: {ddos_threat.threat_type.value} (confidence: {ddos_threat.confidence})")
        print(f"  - Severity: {ddos_threat.level.value}")
        print(f"  - Actions: {len(plan.actions)}")
        print(f"  - Requires approval: {plan.requires_approval}")

        # Show actions
        print("\n[Step 2] Mitigation actions:")
        for i, action in enumerate(plan.actions, 1):
            print(f"\n  Action {i}: {action.action_type}")
            print(f"    Target: {action.target}")
            print(f"    Reason: {action.reason}")
            print(f"    Reversible: {action.reversible}")
            print(f"    Timeout: {action.timeout_seconds}s" if action.timeout_seconds else "")
            print(f"    Command: {action.command}")

        # Execute plan
        print("\n[Step 3] Executing mitigation plan (dry-run)...")
        success, results = agent.execute_mitigation(plan)
        print(f"✓ Plan execution: {'SUCCESS' if success else 'FAILED'}")

        for result in results:
            print(f"\n  Action {result.action_id}:")
            print(f"    Success: {result.success}")
            print(f"    Execution time: {result.execution_time_ms:.2f}ms")
            if result.output:
                print(f"    Output: {result.output[:100]}...")
    else:
        print("✗ No mitigation plan generated")


def example_2_brute_force_detection():
    """Example 2: Brute Force Attack Detection."""
    print("\n" + "="*80)
    print("EXAMPLE 2: Brute Force Attack Detection")
    print("="*80)

    config = AgentConfig(
        enabled=True,
        auto_execute=False,
        dry_run=True,
    )
    agent = ThreatMitigationAgent(config)

    # Create brute force threat
    brute_force_threat = Threat(
        threat_id=f"threat_{uuid.uuid4().hex[:8]}",
        threat_type=ThreatType.BRUTE_FORCE,
        level=ThreatLevel.MEDIUM,
        source_ip="203.0.113.45",
        dest_ip="10.0.0.1",
        port=22,
        timestamp=datetime.now(),
        indicators=[
            ThreatIndicator(
                indicator_type="failed_attempts",
                value=50.0,
                threshold=5.0,
                severity_contribution=0.7
            )
        ],
        description="SSH brute force: 50 failed login attempts in 60 seconds",
        confidence=0.88
    )

    print("\n[Step 1] Analyzing brute force threat...")
    plan = agent.analyze_threat(brute_force_threat)

    if plan:
        print(f"✓ Generated plan with {len(plan.actions)} actions")
        
        print("\n[Step 2] Mitigation plan details:")
        for action in plan.actions:
            print(f"  - {action.action_type}: {action.target} ({action.reason})")
            print(f"    Auto-unblock in: {action.timeout_seconds}s" if action.timeout_seconds else "")

        print("\n[Step 3] Plan status:")
        status = agent.get_plan_status(plan.plan_id)
        if status:
            print(f"  Status: {status['status']}")
            print(f"  Requires approval: {status['requires_approval']}")


def example_3_c2_communication():
    """Example 3: C2 Communication Detection."""
    print("\n" + "="*80)
    print("EXAMPLE 3: C2 (Command & Control) Communication Detection")
    print("="*80)

    config = AgentConfig(
        enabled=True,
        auto_execute=False,
        dry_run=True,
    )
    agent = ThreatMitigationAgent(config)

    # Create C2 threat
    c2_threat = Threat(
        threat_id=f"threat_{uuid.uuid4().hex[:8]}",
        threat_type=ThreatType.C2_COMMUNICATION,
        level=ThreatLevel.CRITICAL,
        source_ip="10.0.0.50",  # Internal compromised host
        dest_ip="198.51.100.10",  # External C2 server
        port=443,
        timestamp=datetime.now(),
        indicators=[
            ThreatIndicator(
                indicator_type="suspicious_protocol",
                value=1.0,
                threshold=0.5,
                severity_contribution=0.95
            )
        ],
        description="Suspicious outbound HTTPS connection to known C2 server",
        confidence=0.92,
        raw_data={"pid": 4521}  # Process ID of suspicious process
    )

    print("\n[Step 1] Analyzing C2 threat...")
    plan = agent.analyze_threat(c2_threat)

    if plan:
        print(f"✓ Generated plan: {plan.plan_id}")
        print(f"  Requires approval: {plan.requires_approval} (CRITICAL action)")
        
        print("\n[Step 2] Actions to be taken:")
        for i, action in enumerate(plan.actions, 1):
            print(f"\n  Action {i}: {action.action_type}")
            print(f"    Target: {action.target}")
            print(f"    Command: {action.command}")
            print(f"    Reversible: {action.reversible}")
            if action.rollback_command:
                print(f"    Rollback: {action.rollback_command}")


def example_4_system_info():
    """Example 4: Display system information."""
    print("\n" + "="*80)
    print("EXAMPLE 4: System Information")
    print("="*80)

    agent = ThreatMitigationAgent()

    print("\n[System Details]")
    sys_info = agent.get_system_info()
    print(f"  OS Type: {sys_info['os_type']}")
    print(f"  Running as admin: {sys_info['is_admin']}")
    
    print("\n[OS Details]")
    for key, value in sys_info['os_details'].items():
        print(f"  {key}: {value}")

    print("\n[Available Tools]")
    tools = sys_info['available_tools']
    for tool, available in tools.items():
        status = "✓" if available else "✗"
        print(f"  {status} {tool}")


def example_5_multiple_threats():
    """Example 5: Handle multiple threats."""
    print("\n" + "="*80)
    print("EXAMPLE 5: Handling Multiple Threats")
    print("="*80)

    config = AgentConfig(
        enabled=True,
        auto_execute=False,
        dry_run=True,
    )
    agent = ThreatMitigationAgent(config)

    threats = [
        Threat(
            threat_id=f"threat_{uuid.uuid4().hex[:8]}",
            threat_type=ThreatType.PORT_SCAN,
            level=ThreatLevel.LOW,
            source_ip="192.168.1.200",
            timestamp=datetime.now(),
            description="Network port scan detected",
            confidence=0.75
        ),
        Threat(
            threat_id=f"threat_{uuid.uuid4().hex[:8]}",
            threat_type=ThreatType.DATA_EXFILTRATION,
            level=ThreatLevel.HIGH,
            source_ip="10.0.0.50",
            dest_ip="203.0.113.99",
            timestamp=datetime.now(),
            indicators=[
                ThreatIndicator(
                    indicator_type="outbound_bytes",
                    value=1_000_000.0,
                    threshold=100_000.0,
                    severity_contribution=0.85
                )
            ],
            description="Unusual large data transfer to external IP",
            confidence=0.82
        ),
    ]

    print("\n[Processing Multiple Threats]")
    for threat in threats:
        print(f"\n  Threat: {threat.threat_type.value} (confidence: {threat.confidence})")
        plan = agent.analyze_threat(threat)
        if plan:
            print(f"    ✓ Generated plan with {len(plan.actions)} actions")
        else:
            print(f"    - No mitigation plan generated")

    print(f"\n[Summary]")
    history = agent.get_threat_history()
    print(f"  Total threats analyzed: {len(history)}")
    print(f"  Active plans: {len(agent.get_active_plans())}")


def example_6_threat_history():
    """Example 6: View threat history and execution logs."""
    print("\n" + "="*80)
    print("EXAMPLE 6: Threat History and Execution Logs")
    print("="*80)

    agent = ThreatMitigationAgent(AgentConfig(enabled=True, dry_run=True))

    # Create and analyze some threats
    for i in range(3):
        threat = Threat(
            threat_id=f"threat_{uuid.uuid4().hex[:8]}",
            threat_type=ThreatType.DDOS,
            level=ThreatLevel.MEDIUM,
            source_ip=f"192.168.1.{100+i}",
            port=80,
            timestamp=datetime.now(),
            description=f"DDoS threat {i+1}",
            confidence=0.85
        )
        agent.analyze_threat(threat)

    print("\n[Threat History]")
    history = agent.get_threat_history(limit=5)
    for threat in history:
        print(f"\n  {threat['threat_id']}")
        print(f"    Type: {threat['threat_type']}")
        print(f"    Severity: {threat['level']}")
        print(f"    Source: {threat['source_ip']}")
        print(f"    Confidence: {threat['confidence']}")

    print("\n[Execution History]")
    exec_history = agent.get_execution_history(limit=10)
    for log in exec_history:
        status = "✓" if log['success'] else "✗"
        print(f"  {status} {log['timestamp']}: {log['action_type']} on {log['target']}")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("NETSAFE THREAT MITIGATION AGENT - USAGE EXAMPLES")
    print("="*80)

    example_1_ddos_detection()
    example_2_brute_force_detection()
    example_3_c2_communication()
    example_4_system_info()
    example_5_multiple_threats()
    example_6_threat_history()

    print("\n" + "="*80)
    print("Examples completed!")
    print("="*80 + "\n")
