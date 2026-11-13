"""
Mitigation action executor.
Safely executes mitigation actions with logging, error handling, and rollback capability.
"""
import subprocess
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path

from agent.threat_model import MitigationPlan, MitigationAction, MitigationStatus, MitigationResult
from agent.mitigation_commands import execute_command, get_os_type, is_admin


@dataclass
class ExecutionLog:
    """Log of executed mitigation actions."""
    timestamp: datetime
    action_id: str
    action_type: str
    target: str
    command: str
    success: bool
    output: str
    error: Optional[str]
    execution_time_ms: float


class MitigationExecutor:
    """
    Executes mitigation plans and manages action state.
    """

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or Path.cwd() / "mitigation_logs"
        self.log_dir.mkdir(exist_ok=True)
        self.execution_history: List[ExecutionLog] = []
        self.action_registry: Dict[str, Dict] = {}  # Track active actions for timeout management

    def execute_plan(
        self,
        plan: MitigationPlan,
        dry_run: bool = False,
        auto_approve: bool = False
    ) -> Tuple[bool, List[MitigationResult]]:
        """
        Execute a mitigation plan.
        
        Args:
            plan: Mitigation plan to execute
            dry_run: If True, only show what would happen without executing
            auto_approve: If True, don't require approval for approval-requiring actions
            
        Returns:
            (success, results)
        """
        results = []

        # Check if plan requires approval
        if plan.requires_approval and not auto_approve and not dry_run:
            plan.status = MitigationStatus.PENDING
            return False, results  # Plan not approved

        plan.status = MitigationStatus.IN_PROGRESS
        plan.approved_at = datetime.now()

        for action in plan.get_pending_actions():
            result = self.execute_action(action, dry_run=dry_run)
            results.append(result)
            action.status = MitigationStatus.COMPLETED if result.success else MitigationStatus.FAILED

        plan.status = MitigationStatus.COMPLETED
        return True, results

    def execute_action(
        self,
        action: MitigationAction,
        dry_run: bool = False
    ) -> MitigationResult:
        """
        Execute a single mitigation action.
        
        Args:
            action: Action to execute
            dry_run: If True, only simulate execution
            
        Returns:
            MitigationResult with execution details
        """
        action.status = MitigationStatus.IN_PROGRESS
        start_time = time.time()

        # Check privileges if needed
        if not self._check_privileges(action):
            action.status = MitigationStatus.FAILED
            error_msg = "Insufficient privileges to execute action"
            self._log_action(action, False, "", error_msg)
            return MitigationResult(
                action_id=action.action_id,
                success=False,
                output="",
                error=error_msg,
                execution_time_ms=(time.time() - start_time) * 1000
            )

        # Dry run mode
        if dry_run:
            action.status = MitigationStatus.COMPLETED
            execution_time = (time.time() - start_time) * 1000
            self._log_action(action, True, f"[DRY RUN] {action.command}", None)
            return MitigationResult(
                action_id=action.action_id,
                success=True,
                output=f"[DRY RUN] Would execute: {action.command}",
                error=None,
                execution_time_ms=execution_time
            )

        # Execute command
        success, output, error = execute_command(action.command)
        execution_time = (time.time() - start_time) * 1000

        if success:
            action.status = MitigationStatus.COMPLETED
            action.executed_at = datetime.now()
            self._log_action(action, True, output, None)

            # Register action for timeout-based rollback
            if action.timeout_seconds and action.reversible:
                self._register_for_rollback(action)
        else:
            action.status = MitigationStatus.FAILED
            action.error_message = error
            self._log_action(action, False, output, error)

        return MitigationResult(
            action_id=action.action_id,
            success=success,
            output=output,
            error=error,
            execution_time_ms=execution_time
        )

    def rollback_action(self, action: MitigationAction) -> Tuple[bool, Optional[str]]:
        """
        Rollback a mitigation action.
        
        Args:
            action: Action to rollback
            
        Returns:
            (success, error_message)
        """
        if not action.reversible or not action.rollback_command:
            return False, "Action is not reversible"

        if action.status != MitigationStatus.COMPLETED:
            return False, f"Cannot rollback action in {action.status.value} state"

        success, output, error = execute_command(action.rollback_command)
        if success:
            action.status = MitigationStatus.ROLLED_BACK
            self._log_rollback(action, True, output, None)
            return True, None
        else:
            self._log_rollback(action, False, output, error)
            return False, error

    def rollback_plan(self, plan: MitigationPlan) -> Tuple[bool, Dict[str, Tuple[bool, Optional[str]]]]:
        """
        Rollback all actions in a plan.
        
        Args:
            plan: Plan to rollback
            
        Returns:
            (all_success, results_dict)
        """
        results = {}
        all_success = True

        # Rollback in reverse order
        for action in reversed(plan.actions):
            if action.status == MitigationStatus.COMPLETED:
                success, error = self.rollback_action(action)
                results[action.action_id] = (success, error)
                if not success:
                    all_success = False

        plan.status = MitigationStatus.ROLLED_BACK
        return all_success, results

    def _check_privileges(self, action: MitigationAction) -> bool:
        """Check if we have sufficient privileges to execute the action."""
        # Actions that require elevated privileges
        privileged_actions = {
            "firewall_block_ip",
            "firewall_block_port",
            "firewall_rate_limit",
            "kill_process",
            "kill_process_by_port",
            "drop_connection",
            "reset_connections",
            "isolate_interface",
        }

        os_type = get_os_type()

        # Windows: check if running as admin
        if os_type == "windows":
            if action.action_type in privileged_actions:
                return is_admin()

        # Linux/macOS: check if running as root (sudo commands will work)
        elif os_type in ["linux", "macos"]:
            if action.action_type in privileged_actions and not action.command.startswith("sudo"):
                return is_admin()

        return True

    def _register_for_rollback(self, action: MitigationAction):
        """Register an action for automatic rollback after timeout."""
        self.action_registry[action.action_id] = {
            "action": action,
            "registered_at": datetime.now(),
            "timeout_seconds": action.timeout_seconds,
        }

    def check_and_execute_timeouts(self) -> List[str]:
        """
        Check registered actions and rollback those that have timed out.
        Should be called periodically (e.g., every 60 seconds).
        
        Returns:
            List of rolled-back action IDs
        """
        rolled_back = []
        current_time = datetime.now()

        for action_id, registry_entry in list(self.action_registry.items()):
            action = registry_entry["action"]
            registered_at = registry_entry["registered_at"]
            timeout_seconds = registry_entry["timeout_seconds"]

            elapsed = (current_time - registered_at).total_seconds()
            if elapsed >= timeout_seconds:
                success, error = self.rollback_action(action)
                if success:
                    rolled_back.append(action_id)
                del self.action_registry[action_id]

        return rolled_back

    def _log_action(
        self,
        action: MitigationAction,
        success: bool,
        output: str,
        error: Optional[str]
    ):
        """Log an executed action."""
        log_entry = ExecutionLog(
            timestamp=datetime.now(),
            action_id=action.action_id,
            action_type=action.action_type,
            target=action.target,
            command=action.command,
            success=success,
            output=output,
            error=error,
            execution_time_ms=0.0
        )
        self.execution_history.append(log_entry)
        self._write_log_file(log_entry)

    def _log_rollback(
        self,
        action: MitigationAction,
        success: bool,
        output: str,
        error: Optional[str]
    ):
        """Log a rollback action."""
        log_entry = ExecutionLog(
            timestamp=datetime.now(),
            action_id=f"{action.action_id}_rollback",
            action_type=f"{action.action_type}_rollback",
            target=action.target,
            command=action.rollback_command or "",
            success=success,
            output=output,
            error=error,
            execution_time_ms=0.0
        )
        self.execution_history.append(log_entry)
        self._write_log_file(log_entry)

    def _write_log_file(self, log_entry: ExecutionLog):
        """Write log entry to file."""
        log_file = self.log_dir / f"mitigation_{log_entry.timestamp.strftime('%Y%m%d')}.json"

        log_dict = {
            "timestamp": log_entry.timestamp.isoformat(),
            "action_id": log_entry.action_id,
            "action_type": log_entry.action_type,
            "target": log_entry.target,
            "command": log_entry.command,
            "success": log_entry.success,
            "output": log_entry.output,
            "error": log_entry.error,
            "execution_time_ms": log_entry.execution_time_ms,
        }

        try:
            if log_file.exists():
                with open(log_file, "r") as f:
                    logs = json.load(f)
            else:
                logs = []

            logs.append(log_dict)

            with open(log_file, "w") as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"Error writing log file: {e}")

    def get_execution_history(self, limit: int = 100) -> List[ExecutionLog]:
        """Get recent execution history."""
        return self.execution_history[-limit:]

    def get_active_mitigations(self) -> List[Dict]:
        """Get currently active mitigations (not yet rolled back)."""
        active = []
        for action_id, registry_entry in self.action_registry.items():
            action = registry_entry["action"]
            active.append({
                "action_id": action_id,
                "action_type": action.action_type,
                "target": action.target,
                "reason": action.reason,
                "registered_at": registry_entry["registered_at"].isoformat(),
                "timeout_seconds": registry_entry["timeout_seconds"],
            })
        return active
