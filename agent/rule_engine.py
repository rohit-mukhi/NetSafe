"""
Rule-based threat analysis and mitigation planning engine.
Analyzes detected threats and generates mitigation plans based on configurable rules.
"""
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
import uuid
from datetime import datetime, timedelta

from agent.threat_model import (
    Threat, ThreatType, ThreatLevel, ThreatIndicator,
    MitigationAction, MitigationPlan, MitigationStatus
)
from agent.mitigation_commands import (
    FirewallCommands, ProcessCommands, NetworkCommands, get_os_type
)


@dataclass
class Rule:
    """A single threat mitigation rule."""
    rule_id: str
    name: str
    threat_type: ThreatType
    condition: Dict[str, Any]  # Conditions to match (e.g., {"min_severity": "high"})
    actions: List[Dict[str, Any]]  # Actions to take (e.g., {"type": "firewall_block_ip"})
    enabled: bool = True
    priority: int = 0  # Higher = executed first
    requires_approval: bool = False


class RuleEngine:
    """
    Rule-based threat mitigation engine.
    Matches threats against rules and generates mitigation plans.
    """

    def __init__(self):
        self.rules: List[Rule] = []
        self._load_default_rules()

    def _load_default_rules(self):
        """Load default threat mitigation rules."""

        # ====== DDoS ATTACK RULES ======
        self.add_rule(Rule(
            rule_id="ddos_block_source_ip",
            name="DDoS: Block source IP",
            threat_type=ThreatType.DDOS,
            condition={
                "min_severity": ThreatLevel.MEDIUM,
                "high_packet_rate": True,
            },
            actions=[
                {
                    "type": "firewall_block_ip",
                    "target_field": "source_ip",
                    "reversible": True,
                    "timeout_seconds": 3600,  # Auto-unblock after 1 hour
                    "reason": "DDoS detected: blocking source IP"
                },
                {
                    "type": "firewall_rate_limit",
                    "target_field": "source_ip",
                    "packets_per_sec": 100,
                    "reason": "DDoS rate limiting"
                }
            ],
            enabled=True,
            priority=10,
            requires_approval=False
        ))

        self.add_rule(Rule(
            rule_id="ddos_block_port",
            name="DDoS: Block attacked port",
            threat_type=ThreatType.DDOS,
            condition={
                "min_severity": ThreatLevel.CRITICAL,
                "attack_port": True,
            },
            actions=[
                {
                    "type": "firewall_block_port",
                    "target_field": "port",
                    "reason": "DDoS: blocking attacked port temporarily"
                },
                {
                    "type": "kill_process_by_port",
                    "target_field": "port",
                    "reason": "DDoS: terminating service on attacked port"
                }
            ],
            enabled=True,
            priority=9,
            requires_approval=True  # Critical action
        ))

        # ====== BRUTE FORCE ATTACK RULES ======
        self.add_rule(Rule(
            rule_id="brute_force_ban_ip",
            name="Brute Force: Temporary IP ban",
            threat_type=ThreatType.BRUTE_FORCE,
            condition={
                "min_severity": ThreatLevel.MEDIUM,
                "failed_attempts": True,
            },
            actions=[
                {
                    "type": "firewall_block_ip",
                    "target_field": "source_ip",
                    "reversible": True,
                    "timeout_seconds": 1800,  # 30 minutes
                    "reason": "Brute force: temporary IP ban"
                }
            ],
            enabled=True,
            priority=8,
            requires_approval=False
        ))

        # ====== PORT SCAN RULES ======
        self.add_rule(Rule(
            rule_id="port_scan_drop_packets",
            name="Port Scan: Drop packets from scanner",
            threat_type=ThreatType.PORT_SCAN,
            condition={
                "min_severity": ThreatLevel.MEDIUM,
            },
            actions=[
                {
                    "type": "firewall_block_ip",
                    "target_field": "source_ip",
                    "reversible": True,
                    "timeout_seconds": 600,  # 10 minutes
                    "reason": "Port scan detected: dropping packets"
                }
            ],
            enabled=True,
            priority=7,
            requires_approval=False
        ))

        # ====== C2 COMMUNICATION RULES ======
        self.add_rule(Rule(
            rule_id="c2_block_domain",
            name="C2: Block C2 domain/IP",
            threat_type=ThreatType.C2_COMMUNICATION,
            condition={
                "min_severity": ThreatLevel.HIGH,
            },
            actions=[
                {
                    "type": "firewall_block_ip",
                    "target_field": "dest_ip",
                    "reversible": True,
                    "timeout_seconds": 7200,  # 2 hours
                    "reason": "C2 communication detected: blocking destination"
                },
                {
                    "type": "drop_connection",
                    "target_fields": ["source_ip", "dest_ip", "port"],
                    "reason": "C2: dropping active connections"
                }
            ],
            enabled=True,
            priority=10,
            requires_approval=False
        ))

        self.add_rule(Rule(
            rule_id="c2_kill_process",
            name="C2: Kill suspicious process",
            threat_type=ThreatType.C2_COMMUNICATION,
            condition={
                "min_severity": ThreatLevel.CRITICAL,
                "has_pid": True,
            },
            actions=[
                {
                    "type": "kill_process",
                    "target_field": "pid",
                    "reason": "C2: terminating suspicious process"
                }
            ],
            enabled=True,
            priority=11,
            requires_approval=True  # Critical action
        ))

        # ====== DATA EXFILTRATION RULES ======
        self.add_rule(Rule(
            rule_id="exfil_rate_limit",
            name="Exfiltration: Rate limit outbound",
            threat_type=ThreatType.DATA_EXFILTRATION,
            condition={
                "min_severity": ThreatLevel.MEDIUM,
                "high_outbound_bytes": True,
            },
            actions=[
                {
                    "type": "firewall_rate_limit",
                    "target_field": "dest_ip",
                    "packets_per_sec": 50,
                    "reason": "Data exfiltration: rate limiting outbound traffic"
                }
            ],
            enabled=True,
            priority=6,
            requires_approval=False
        ))

        self.add_rule(Rule(
            rule_id="exfil_block_dest",
            name="Exfiltration: Block destination IP",
            threat_type=ThreatType.DATA_EXFILTRATION,
            condition={
                "min_severity": ThreatLevel.HIGH,
            },
            actions=[
                {
                    "type": "firewall_block_ip",
                    "target_field": "dest_ip",
                    "reversible": True,
                    "timeout_seconds": 3600,
                    "reason": "Suspicious data exfiltration: blocking destination"
                }
            ],
            enabled=True,
            priority=7,
            requires_approval=False
        ))

        # ====== UNAUTHORIZED ACCESS RULES ======
        self.add_rule(Rule(
            rule_id="unauthorized_block_port",
            name="Unauthorized Access: Block port",
            threat_type=ThreatType.UNAUTHORIZED_ACCESS,
            condition={
                "min_severity": ThreatLevel.MEDIUM,
            },
            actions=[
                {
                    "type": "firewall_block_port",
                    "target_field": "port",
                    "reason": "Unauthorized access attempt: blocking port"
                }
            ],
            enabled=True,
            priority=8,
            requires_approval=False
        ))

    def add_rule(self, rule: Rule):
        """Add a rule to the engine."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, rule_id: str):
        """Remove a rule by ID."""
        self.rules = [r for r in self.rules if r.id != rule_id]

    def get_applicable_rules(self, threat: Threat) -> List[Rule]:
        """Get all rules that match a threat."""
        applicable = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.threat_type != threat.threat_type:
                continue
            if self._matches_condition(rule.condition, threat):
                applicable.append(rule)
        return applicable

    def _matches_condition(self, condition: Dict[str, Any], threat: Threat) -> bool:
        """Check if threat matches rule condition."""
        for key, value in condition.items():
            if key == "min_severity":
                severity_order = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
                threat_severity_idx = severity_order.index(threat.level)
                condition_severity_idx = severity_order.index(value)
                if threat_severity_idx < condition_severity_idx:
                    return False
            elif key == "high_packet_rate":
                if value and not self._has_high_packet_rate(threat):
                    return False
            elif key == "attack_port":
                if value and threat.port is None:
                    return False
            elif key == "failed_attempts":
                if value and not self._has_failed_attempts_indicator(threat):
                    return False
            elif key == "high_outbound_bytes":
                if value and not self._has_high_outbound_indicator(threat):
                    return False
            elif key == "has_pid":
                if value and "pid" not in threat.raw_data:
                    return False
        return True

    def _has_high_packet_rate(self, threat: Threat) -> bool:
        """Check if threat has high packet rate indicator."""
        return any(ind.indicator_type == "packet_rate" for ind in threat.indicators)

    def _has_failed_attempts_indicator(self, threat: Threat) -> bool:
        """Check if threat has failed attempts indicator."""
        return any(ind.indicator_type == "failed_attempts" for ind in threat.indicators)

    def _has_high_outbound_indicator(self, threat: Threat) -> bool:
        """Check if threat has high outbound bytes indicator."""
        return any(ind.indicator_type == "outbound_bytes" for ind in threat.indicators)

    def generate_mitigation_plan(self, threat: Threat) -> MitigationPlan:
        """
        Generate a mitigation plan for a threat.
        
        Args:
            threat: Detected threat to mitigate
            
        Returns:
            MitigationPlan with actions to execute
        """
        plan = MitigationPlan(
            plan_id=f"plan_{uuid.uuid4().hex[:8]}",
            threat_id=threat.threat_id,
            threat_type=threat.threat_type,
        )

        applicable_rules = self.get_applicable_rules(threat)
        if not applicable_rules:
            return plan  # Empty plan if no rules match

        # Generate actions from applicable rules
        for rule in applicable_rules:
            for action_spec in rule.actions:
                action = self._build_mitigation_action(action_spec, threat, rule)
                if action:
                    plan.actions.append(action)
                    if rule.requires_approval:
                        plan.requires_approval = True

        plan.notes = f"Generated from {len(applicable_rules)} matching rules"
        return plan

    def _build_mitigation_action(
        self,
        action_spec: Dict[str, Any],
        threat: Threat,
        rule: Rule
    ) -> Optional[MitigationAction]:
        """Build a mitigation action from a rule action specification."""
        action_type = action_spec.get("type")
        reason = action_spec.get("reason", "")

        try:
            if action_type == "firewall_block_ip":
                target_ip = self._get_target_value(action_spec, threat)
                if not target_ip:
                    return None
                cmd, rollback = FirewallCommands.block_ip(target_ip)
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=target_ip,
                    command=cmd,
                    reason=reason,
                    reversible=action_spec.get("reversible", True),
                    timeout_seconds=action_spec.get("timeout_seconds"),
                    rollback_command=rollback,
                )

            elif action_type == "firewall_block_port":
                target_port = self._get_target_value(action_spec, threat)
                if target_port is None:
                    return None
                cmd, rollback = FirewallCommands.block_port(int(target_port))
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=str(target_port),
                    command=cmd,
                    reason=reason,
                    reversible=action_spec.get("reversible", True),
                    rollback_command=rollback,
                )

            elif action_type == "firewall_rate_limit":
                target_ip = self._get_target_value(action_spec, threat)
                if not target_ip:
                    return None
                pps = action_spec.get("packets_per_sec", 100)
                cmd, rollback = FirewallCommands.rate_limit(target_ip, pps)
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=target_ip,
                    command=cmd,
                    reason=reason,
                    reversible=action_spec.get("reversible", True),
                    rollback_command=rollback,
                )

            elif action_type == "kill_process":
                pid = threat.raw_data.get("pid")
                if not pid:
                    return None
                cmd, rollback = ProcessCommands.kill_process(int(pid))
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=str(pid),
                    command=cmd,
                    reason=reason,
                    reversible=False,
                    rollback_command=rollback,
                )

            elif action_type == "kill_process_by_port":
                target_port = self._get_target_value(action_spec, threat)
                if target_port is None:
                    return None
                cmd, rollback = ProcessCommands.kill_process_by_port(int(target_port))
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=str(target_port),
                    command=cmd,
                    reason=reason,
                    reversible=False,
                    rollback_command=rollback,
                )

            elif action_type == "drop_connection":
                src_ip = threat.source_ip
                dest_ip = threat.dest_ip
                port = threat.port
                if not all([src_ip, dest_ip, port]):
                    return None
                cmd, rollback = NetworkCommands.drop_connection(src_ip, dest_ip, port)
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=f"{src_ip}→{dest_ip}:{port}",
                    command=cmd,
                    reason=reason,
                    reversible=action_spec.get("reversible", True),
                    rollback_command=rollback,
                )

            elif action_type == "reset_connections":
                target_ip = self._get_target_value(action_spec, threat)
                if not target_ip:
                    return None
                cmd, rollback = NetworkCommands.reset_connections(target_ip)
                return MitigationAction(
                    action_id=f"action_{uuid.uuid4().hex[:8]}",
                    action_type=action_type,
                    target=target_ip,
                    command=cmd,
                    reason=reason,
                    reversible=False,
                    rollback_command=rollback,
                )

        except Exception as e:
            print(f"Error building mitigation action: {e}")
            return None

        return None

    def _get_target_value(self, action_spec: Dict[str, Any], threat: Threat) -> Optional[Any]:
        """Extract target value from action spec and threat data."""
        target_field = action_spec.get("target_field")
        if not target_field:
            return None

        if target_field == "source_ip":
            return threat.source_ip
        elif target_field == "dest_ip":
            return threat.dest_ip
        elif target_field == "port":
            return threat.port
        elif target_field == "pid":
            return threat.raw_data.get("pid")
        return None


# ============================================================================
# Singleton instance for global access
# ============================================================================

_engine_instance: Optional[RuleEngine] = None


def get_rule_engine() -> RuleEngine:
    """Get or create the global rule engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RuleEngine()
    return _engine_instance
