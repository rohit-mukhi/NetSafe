"""
Main ThreatMitigationAgent class.
Orchestrates threat detection analysis and mitigation.
"""
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from agent.threat_model import Threat, ThreatType, ThreatLevel, MitigationPlan, MitigationResult
from agent.rule_engine import RuleEngine, get_rule_engine
from agent.executor import MitigationExecutor
from agent.os_detector import OSDetector


@dataclass
class AgentConfig:
    """Configuration for threat mitigation agent."""
    enabled: bool = True
    auto_execute: bool = False  # Auto-execute mitigations without approval
    dry_run: bool = False  # Simulate without executing
    enable_logging: bool = True
    log_dir: Optional[Path] = None
    require_approval_for_destructive: bool = True
    enable_timeout_rollback: bool = True
    timeout_check_interval_seconds: int = 60


class ThreatMitigationAgent:
    """
    Agentic threat mitigation system.
    Analyzes detected threats and generates/executes mitigation plans.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.rule_engine = get_rule_engine()
        self.executor = MitigationExecutor(log_dir=self.config.log_dir)
        self.os_detector = OSDetector()
        self.active_plans: Dict[str, MitigationPlan] = {}
        self.threat_history: List[Threat] = []

        # Print system info on init
        if self.config.enabled:
            self._log_init_info()

    def _log_init_info(self):
        """Log initialization information."""
        print("[Agent] Threat Mitigation Agent initialized")
        print(f"[Agent] OS: {self.os_detector.detect().value}")
        print(f"[Agent] Admin privileges: {self.os_detector.is_admin()}")
        print(f"[Agent] Available tools: {self.os_detector.get_available_tools()}")
        print(f"[Agent] Config: auto_execute={self.config.auto_execute}, dry_run={self.config.dry_run}")

    def analyze_threat(self, threat: Threat) -> Optional[MitigationPlan]:
        """
        Analyze a detected threat and generate mitigation plan.
        
        Args:
            threat: Detected threat
            
        Returns:
            MitigationPlan if threats match rules, None otherwise
        """
        if not self.config.enabled:
            return None

        # Store threat in history
        self.threat_history.append(threat)

        # Get applicable rules
        applicable_rules = self.rule_engine.get_applicable_rules(threat)
        if not applicable_rules:
            return None

        # Generate mitigation plan
        plan = self.rule_engine.generate_mitigation_plan(threat)
        if not plan.actions:
            return None

        self.active_plans[plan.plan_id] = plan
        self._log_plan_generated(threat, plan, applicable_rules)
        return plan

    def execute_mitigation(self, plan: MitigationPlan) -> Tuple[bool, List[MitigationResult]]:
        """
        Execute a mitigation plan.
        
        Args:
            plan: Plan to execute
            
        Returns:
            (success, results)
        """
        if not self.config.enabled:
            return False, []

        # Check for destructive actions if approval required
        has_destructive = any(not action.reversible for action in plan.actions)
        require_approval = has_destructive and self.config.require_approval_for_destructive

        # Execute plan
        success, results = self.executor.execute_plan(
            plan,
            dry_run=self.config.dry_run,
            auto_approve=self.config.auto_execute or not require_approval
        )

        if success:
            self._log_plan_executed(plan, results)

        return success, results

    def mitigate_threat(self, threat: Threat) -> Tuple[Optional[MitigationPlan], List[MitigationResult]]:
        """
        Analyze threat and execute mitigation in one call.
        
        Args:
            threat: Detected threat
            
        Returns:
            (plan, results)
        """
        plan = self.analyze_threat(threat)
        if not plan or not plan.actions:
            return None, []

        success, results = self.execute_mitigation(plan)
        return plan if success else None, results

    def rollback_plan(self, plan_id: str) -> Tuple[bool, Dict[str, Tuple[bool, Optional[str]]]]:
        """
        Rollback a mitigation plan.
        
        Args:
            plan_id: ID of plan to rollback
            
        Returns:
            (all_success, results)
        """
        if plan_id not in self.active_plans:
            return False, {}

        plan = self.active_plans[plan_id]
        success, results = self.executor.rollback_plan(plan)

        self._log_plan_rollback(plan, results)
        return success, results

    def get_plan_status(self, plan_id: str) -> Optional[Dict]:
        """Get status of a mitigation plan."""
        if plan_id not in self.active_plans:
            return None

        plan = self.active_plans[plan_id]
        return {
            "plan_id": plan.plan_id,
            "threat_id": plan.threat_id,
            "threat_type": plan.threat_type.value,
            "status": plan.status.value,
            "created_at": plan.created_at.isoformat(),
            "approved_at": plan.approved_at.isoformat() if plan.approved_at else None,
            "requires_approval": plan.requires_approval,
            "actions": [
                {
                    "action_id": a.action_id,
                    "action_type": a.action_type,
                    "target": a.target,
                    "reason": a.reason,
                    "status": a.status.value,
                    "reversible": a.reversible,
                    "timeout_seconds": a.timeout_seconds,
                    "executed_at": a.executed_at.isoformat() if a.executed_at else None,
                }
                for a in plan.actions
            ],
            "notes": plan.notes,
        }

    def get_active_plans(self) -> List[Dict]:
        """Get all active mitigation plans."""
        return [
            self.get_plan_status(plan_id)
            for plan_id in self.active_plans.keys()
        ]

    def get_execution_history(self, limit: int = 50) -> List[Dict]:
        """Get execution history."""
        return [
            {
                "timestamp": log.timestamp.isoformat(),
                "action_id": log.action_id,
                "action_type": log.action_type,
                "target": log.target,
                "success": log.success,
                "error": log.error,
                "execution_time_ms": log.execution_time_ms,
            }
            for log in self.executor.get_execution_history(limit)
        ]

    def get_active_mitigations(self) -> List[Dict]:
        """Get currently active mitigations (timeout-tracked)."""
        return self.executor.get_active_mitigations()

    def check_timeout_rollbacks(self) -> List[str]:
        """Check and execute timeout-based rollbacks."""
        rolled_back = self.executor.check_and_execute_timeouts()
        for action_id in rolled_back:
            self._log(f"Auto-rolled back action: {action_id}")
        return rolled_back

    def get_threat_history(self, limit: int = 100) -> List[Dict]:
        """Get recent threat analysis history."""
        return [
            {
                "threat_id": t.threat_id,
                "threat_type": t.threat_type.value,
                "level": t.level.value,
                "source_ip": t.source_ip,
                "dest_ip": t.dest_ip,
                "port": t.port,
                "timestamp": t.timestamp.isoformat(),
                "confidence": t.confidence,
                "description": t.description,
            }
            for t in self.threat_history[-limit:]
        ]

    def get_available_tools(self) -> Dict:
        """Get available system tools for this platform."""
        return self.os_detector.get_available_tools()

    def get_system_info(self) -> Dict:
        """Get system information."""
        return {
            "os_type": self.os_detector.detect().value,
            "os_details": self.os_detector.get_details(),
            "is_admin": self.os_detector.is_admin(),
            "available_tools": self.os_detector.get_available_tools(),
        }

    def enable(self):
        """Enable the agent."""
        self.config.enabled = True
        self._log("Agent enabled")

    def disable(self):
        """Disable the agent."""
        self.config.enabled = False
        self._log("Agent disabled")

    def set_auto_execute(self, enabled: bool):
        """Enable/disable auto-execution of mitigations."""
        self.config.auto_execute = enabled
        self._log(f"Auto-execute: {enabled}")

    def set_dry_run(self, enabled: bool):
        """Enable/disable dry-run mode."""
        self.config.dry_run = enabled
        self._log(f"Dry-run mode: {enabled}")

    def _log(self, message: str):
        """Log a message."""
        print(f"[Agent] {message}")

    def _log_plan_generated(self, threat: Threat, plan: MitigationPlan, rules: List):
        """Log plan generation."""
        self._log(
            f"Generated mitigation plan {plan.plan_id} for {threat.threat_type.value} "
            f"(severity: {threat.level.value}) - {len(plan.actions)} actions from {len(rules)} rules"
        )

    def _log_plan_executed(self, plan: MitigationPlan, results: List[MitigationResult]):
        """Log plan execution."""
        success_count = sum(1 for r in results if r.success)
        self._log(
            f"Executed plan {plan.plan_id}: {success_count}/{len(results)} actions successful"
        )

    def _log_plan_rollback(self, plan: MitigationPlan, results: Dict):
        """Log plan rollback."""
        success_count = sum(1 for s, _ in results.values() if s)
        self._log(
            f"Rolled back plan {plan.plan_id}: {success_count}/{len(results)} actions successful"
        )


# ============================================================================
# Singleton instance for global access
# ============================================================================

_agent_instance: Optional[ThreatMitigationAgent] = None


def get_agent(config: Optional[AgentConfig] = None) -> ThreatMitigationAgent:
    """Get or create the global agent instance."""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = ThreatMitigationAgent(config)
    return _agent_instance
