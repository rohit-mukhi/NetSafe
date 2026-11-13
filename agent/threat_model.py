"""
Threat data models and classification.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ThreatLevel(Enum):
    """Severity levels for threats."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of network threats detected."""
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    ANOMALOUS_TRAFFIC = "anomalous_traffic"
    UNKNOWN = "unknown"


class MitigationStatus(Enum):
    """Status of mitigation actions."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ThreatIndicator:
    """Individual indicator of a threat."""
    indicator_type: str  # e.g., "packet_rate", "failed_logins", "port_diversity"
    value: float
    threshold: float
    severity_contribution: float  # 0.0 to 1.0


@dataclass
class Threat:
    """Detected threat with context and metadata."""
    threat_id: str
    threat_type: ThreatType
    level: ThreatLevel
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.now)
    indicators: List[ThreatIndicator] = field(default_factory=list)
    description: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def get_primary_indicator(self) -> Optional[ThreatIndicator]:
        """Get the most significant indicator."""
        if not self.indicators:
            return None
        return max(self.indicators, key=lambda x: x.severity_contribution)


@dataclass
class MitigationAction:
    """A single mitigation action to take."""
    action_id: str
    action_type: str  # e.g., "firewall_block", "process_kill", "rate_limit"
    target: str  # e.g., IP address, process ID, interface
    command: str  # OS-specific command to execute
    reason: str  # Why this action is taken
    reversible: bool  # Can this action be undone?
    timeout_seconds: Optional[int] = None  # Auto-expire after this duration
    os_targets: List[str] = field(default_factory=list)  # ["windows", "linux", "macos"]
    status: MitigationStatus = MitigationStatus.PENDING
    executed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    rollback_command: Optional[str] = None  # Command to undo this action


@dataclass
class MitigationPlan:
    """Complete plan to mitigate a threat."""
    plan_id: str
    threat_id: str
    threat_type: ThreatType
    created_at: datetime = field(default_factory=datetime.now)
    actions: List[MitigationAction] = field(default_factory=list)
    requires_approval: bool = False
    approved_at: Optional[datetime] = None
    status: MitigationStatus = MitigationStatus.PENDING
    notes: str = ""
    
    def get_pending_actions(self) -> List[MitigationAction]:
        """Get all actions that haven't been executed yet."""
        return [a for a in self.actions if a.status == MitigationStatus.PENDING]
    
    def all_completed(self) -> bool:
        """Check if all actions are completed."""
        if not self.actions:
            return False
        return all(a.status in [MitigationStatus.COMPLETED, MitigationStatus.ROLLED_BACK] 
                   for a in self.actions)


@dataclass
class MitigationResult:
    """Result of executing a mitigation action."""
    action_id: str
    success: bool
    output: str
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
