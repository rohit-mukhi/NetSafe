# NetSafe: AI-Powered Network Anomaly Detection & Threat Mitigation

An intelligent network security system that detects anomalies using machine learning and autonomously mitigates threats with rule-based actions.

## Overview

NetSafe combines multiple ML models with an autonomous threat mitigation agent to protect networks from DDoS attacks, brute force attempts, C2 communications, data exfiltration, and other anomalies.

**Key Features:**
- 🤖 Multiple ML detection models (Isolation Forest, Random Forest, One-Class SVM)
- 🛡️ Rule-based autonomous threat mitigation agent
- 🔄 Cross-platform support (Windows, Linux, macOS)
- 📊 Real-time & dataset-based anomaly detection
- 🎯 OS-specific firewall & process management
- 📝 Comprehensive audit logging
- 🔙 Automatic action rollback with timeout management

## Architecture

```
┌─────────────────────────────────────────────────────┐
│          Network Traffic / Dataset Input             │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│     Preprocessing (Feature Extraction & Scaling)     │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│    ML Detection (IF, RF, One-Class SVM)              │
│    Output: Anomaly Predictions                       │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│    Threat Classification                            │
│    (ThreatType, ThreatLevel)                        │
└─────────────────────────────────────────────────────┘
                          ↓
                  [Agent Mode Toggle]
                          ↓
┌─────────────────────────────────────────────────────┐
│    Rule-Based Threat Mitigation Agent               │
│    • Analyze threat                                 │
│    • Generate mitigation plan                       │
│    • Execute OS-specific commands                   │
│    • Log & rollback                                 │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│         Mitigation Results & Audit Trail             │
└─────────────────────────────────────────────────────┘
```

## Installation

### Requirements
- Python 3.8+
- pip or uv package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/netsafe.git
cd netsafe
```

2. Create virtual environment:
```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. **Windows Only**: Install Npcap for packet capture
   - Download from https://npcap.com/download/
   - Enable "WinPcap API-compatible Mode" during installation
   - Restart your computer

## Quick Start

### Run the Application

```bash
# Ensure you're in the virtual environment
python -m streamlit run main.py
```

App launches on `http://localhost:8502`

### Usage Modes

#### 1. Dataset Mode (Recommended for Testing)
- Pre-recorded network captures from IoT-23 and KDD99 datasets
- Instant results, no network setup required
- Perfect for demonstrating threat detection & mitigation

```
Select: Scan Mode → "Dataset"
       Model → "Random Forest"
       Dataset → Any available
       Agent Mode → Enabled/Disabled
Click: "🔍 Scan Network"
```

#### 2. Live Traffic Mode
- Real-time packet capture from your network
- Requires administrator/root privileges
- Windows: Requires Npcap installation

```
Select: Scan Mode → "Live Traffic"
       Network Interface → Select your interface
       Duration → Capture time (seconds)
Click: "🔍 Scan Network"
```

## Features

### ML Detection Models

| Model | Type | Best For |
|-------|------|----------|
| **Isolation Forest** | Unsupervised anomaly detection | General anomalies |
| **Random Forest** | Supervised classification | Known threat patterns |
| **One-Class SVM** | Unsupervised boundary detection | Extreme outliers |

### Threat Types

The system detects and classifies:
- **DDoS Attacks** → High volume traffic from single source
- **Brute Force** → Multiple failed authentication attempts
- **Port Scans** → Systematic port probing
- **C2 Communication** → Command & Control communication
- **Data Exfiltration** → Unusual outbound traffic
- **Unauthorized Access** → Suspicious privilege escalation
- **Anomalous Traffic** → Other statistical anomalies

### Mitigation Actions

**Firewall Operations:**
- Block source IP addresses
- Block destination ports
- Rate limiting traffic
- Connection dropping

**Process Management:**
- Terminate suspicious processes
- Kill connections on compromised ports

**Network Management:**
- Reset TCP connections
- Interface isolation (emergency)

### Cross-Platform Support

| Operation | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| Firewall | netsh | ufw/iptables | pfctl |
| Processes | taskkill | kill | kill |
| Network | netstat | ss/netstat | netstat |
| Packet Capture | Npcap | Scapy/tcpdump | Scapy/tcpdump |

**Privilege Requirements:**
- Most firewall/process operations need admin/root access
- Packet capture needs admin/root on all platforms

## Configuration

### Agent Mode Settings

In the UI, configure:
- **Agent Mode**: Enable/disable autonomous mitigation
- **Execution Mode**: Dry-run (preview) vs. Auto-execute
- **Threat Level Threshold**: Only mitigate HIGH/CRITICAL threats

### Retraining Models

Retrain with your own data:

```bash
python train.py
```

Customize in `train.py`:
- Data source
- Train/test split
- Model hyperparameters
- Feature engineering

### Custom Rules

Add custom mitigation rules in `agent/rule_engine.py`:

```python
Rule(
    rule_id="custom_rule_1",
    name="Custom threat response",
    threat_type=ThreatType.CUSTOM,
    condition={"min_severity": ThreatLevel.HIGH},
    actions=[
        {"type": "firewall_block_ip", "target_field": "source_ip"},
    ],
    enabled=True,
    priority=10,
)
```

## Project Structure

```
netsafe/
├── main.py                          # Streamlit UI
├── train.py                         # Model training pipeline
├── requirements.txt                 # Python dependencies
│
├── core/
│   ├── preprocessor.py              # Feature extraction & scaling
│   ├── predictor.py                 # ML model predictions
│   └── packet_capture.py            # Cross-platform packet capture
│
├── models/
│   ├── isolation_forest.py          # IF model implementation
│   ├── one_class_svm.py             # One-Class SVM implementation
│   ├── random_forest.py             # RF model implementation
│   └── __init__.py
│
├── agent/
│   ├── agent.py                     # Main agent orchestrator
│   ├── threat_model.py              # Data models (Threat, Plan, Action)
│   ├── rule_engine.py               # Rule matching & plan generation
│   ├── executor.py                  # Action execution & logging
│   ├── mitigation_commands.py       # OS-specific commands
│   ├── os_detector.py               # Platform detection
│   └── example_usage.py             # Agent usage examples
│
├── agent_integration.py             # Bridge from detection to agent
│
├── tests/                           # Testing & utility scripts
│   ├── test_with_synthetic_data.py  # Test agent with synthetic threats
│   ├── test_ddos_detection.py       # Verify DDoS detection pipeline
│   ├── capture_and_analyze.py       # Capture & analyze live traffic
│   ├── ddos_generator.py            # Generate DDoS test traffic
│   └── __init__.py
│
├── datasets/
│   ├── iot-23/                      # IoT-23 network captures
│   └── kdd-99-cup/                  # KDD99 intrusion detection data
│
├── saved_models/                    # Trained model artifacts
│   ├── *.pkl                        # Serialized models
│   ├── *.npy                        # Preprocessed data & thresholds
│   └── scaler.pkl                   # Feature scaler
│
├── mitigation_logs/                 # Audit trail of executed actions
│
└── notebooks/                       # Jupyter notebooks (legacy training)
```

## Datasets

NetSafe includes benchmark datasets for testing:

### IoT-23
Network captures from IoT devices with benign and malicious traffic.
- **Source**: CTU Honeypot Captures
- **Files**: 23 captures, each ~500K flows
- **Labels**: Benign vs. botnet/malware

### KDD99 Cup
Classic intrusion detection dataset.
- **Source**: KDD Cup 1999
- **Samples**: 400K+ network connections
- **Attack Types**: 22 types (DoS, Probe, R2L, U2R)

Access in the UI or programmatically:

```python
import pandas as pd
data = pd.read_csv("datasets/iot-23/CTU-IoT-Malware-Capture-1-1.csv")
```

## Troubleshooting

### Windows: "Npcap not found" during live capture
1. Download Npcap: https://npcap.com/download/
2. Install with "WinPcap API-compatible Mode" enabled
3. Restart computer
4. Run app as Administrator

### "Permission denied" errors
- **Windows**: Run PowerShell as Administrator
- **Linux/macOS**: Use `sudo` or add user to pcap group:
  ```bash
  sudo usermod -a -G pcap $USER
  ```

### Live traffic returns "0 packets"
- Ensure network interface is active and has traffic
- Try Dataset mode for testing instead
- Check firewall isn't blocking packet capture

### Models not improving
- More training data needed
- Try different model (RF vs IF vs SVM)
- Adjust feature engineering in `core/preprocessor.py`
- Retrain with balanced class distribution

## Performance

| Operation | Time | Resources |
|-----------|------|-----------|
| Live capture (10s) | ~10 seconds | 100-200MB RAM |
| Feature extraction | <1 second | <50MB RAM |
| Model prediction | <100ms | <50MB RAM |
| Mitigation execution | 100-500ms | Variable |

## Safety & Ethics

⚠️ **Important Notes:**
- NetSafe executes real system commands that modify firewall rules and kill processes
- Test in non-production environments first
- Always review mitigation plans in dry-run mode before auto-executing
- Some actions are irreversible (process termination)
- Requires elevated privileges for effective operation

**Responsible Use:**
- Use only on systems you own or have explicit permission to modify
- Monitor for false positives that may block legitimate traffic
- Maintain audit logs for compliance
- Test custom rules thoroughly before deployment

## Development

### Running Tests

```bash
# Test agent with synthetic data
python tests/test_with_synthetic_data.py

# Test DDoS detection
python tests/test_ddos_detection.py

# Capture and analyze live traffic
python tests/capture_and_analyze.py

# Generate DDoS traffic
python tests/ddos_generator.py <target_ip> <port> <duration> <packet_rate>
# Example:
python tests/ddos_generator.py 192.168.1.100 80 30 100
```

### Adding New Models

1. Create model class in `models/your_model.py`
2. Implement `train()` and `predict()` methods
3. Register in `core/predictor.py`
4. Test with `test_with_synthetic_data.py`

### Adding New Mitigation Rules

1. Define rule in `agent/rule_engine.py`
2. Test with `agent/example_usage.py`
3. Verify cross-platform commands in `agent/mitigation_commands.py`

## API Reference

### Detection

```python
from core.predictor import Predictor

predictor = Predictor()
predictions = predictor.predict(X, model_type="random_forest")
# Returns: array of -1 (anomaly) or 1 (normal)
```

### Threat Classification

```python
from agent_integration import detection_result_to_threat

threat = detection_result_to_threat(
    predictions=predictions,
    total_samples=len(X),
    anomalies_detected=sum(predictions == -1),
    anomaly_scores=scores,
    source_ip="192.168.1.100",
    dest_ip="10.0.0.1",
    port=80,
)
```

### Agent Mitigation

```python
from agent.agent import ThreatMitigationAgent, AgentConfig

config = AgentConfig(enabled=True, auto_execute=False, dry_run=True)
agent = ThreatMitigationAgent(config)
plan = agent.analyze_threat(threat)
success, results = agent.execute_mitigation(plan)
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -m "Add feature"`
4. Push to branch: `git push origin feature/my-feature`
5. Submit pull request

## License

[Your License Here] - See LICENSE file for details

## Authors

- Your Name & Team
- NetSafe Development Team

## Citation

If you use NetSafe in research, please cite:

```bibtex
@software{netsafe2026,
  title={NetSafe: AI-Powered Network Anomaly Detection and Threat Mitigation},
  author={Your Team},
  year={2026},
  url={https://github.com/yourusername/netsafe}
}
```

## Support & Feedback

- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Ask questions on GitHub Discussions
- **Email**: your-email@example.com

---

**Status**: Active Development
**Python Version**: 3.8+
**Last Updated**: November 2026
