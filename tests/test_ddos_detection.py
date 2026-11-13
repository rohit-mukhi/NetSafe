"""
Test script to verify DDoS detection works correctly.
Run this before running the actual DDoS to verify the detection pipeline.
"""
import numpy as np
from core.predictor import _load_model
from core.preprocessor import REQUIRED_COLUMNS, N_FEATURES
import pandas as pd

print("[*] Testing DDoS Detection Pipeline")
print("=" * 60)

# Load a model
print("\n[1] Loading Random Forest model...")
try:
    model = _load_model("Random Forest")
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit(1)

# Test with synthetic DDoS-like traffic
print("\n[2] Creating synthetic DDoS traffic...")

# Create 1000 samples of high-packet-rate traffic (DDoS signature)
ddos_samples = []
for i in range(1000):
    # DDoS characteristics: high packet rate, high connection count
    sample = np.zeros(N_FEATURES)
    
    # Key features for DDoS detection:
    sample[21] = 0.8  # serror_rate (high)
    sample[22] = 0.8  # srv_serror_rate
    sample[1] = 100   # src_bytes (low - just SYN packets)
    sample[2] = 10    # dst_bytes
    sample[19] = 500  # count (high connection count)
    sample[20] = 500  # srv_count
    
    ddos_samples.append(sample)

X_ddos = np.array(ddos_samples, dtype=np.float64)
print(f"✅ Created {len(X_ddos)} synthetic DDoS samples")

# Test prediction
print("\n[3] Testing model predictions...")
try:
    predictions = model.predict(X_ddos)
    anomaly_count = np.sum(predictions == -1)
    anomaly_rate = anomaly_count / len(predictions)
    
    print(f"   Total samples: {len(predictions)}")
    print(f"   Anomalies detected: {anomaly_count}")
    print(f"   Anomaly rate: {anomaly_rate*100:.1f}%")
    print(f"   Predictions: {np.unique(predictions, return_counts=True)}")
    
    if anomaly_count > 0:
        print("✅ DDoS traffic IS detected as anomalous")
    else:
        print("❌ DDoS traffic NOT detected - model might be insensitive")
        print("\n⚠️ This explains why your DDoS attack wasn't detected!")
        
except Exception as e:
    print(f"❌ Error during prediction: {e}")
    exit(1)

# Test with normal traffic
print("\n[4] Testing with normal traffic...")
normal_samples = []
for i in range(100):
    sample = np.zeros(N_FEATURES)
    sample[21] = 0.05  # Low serror_rate
    sample[22] = 0.05
    sample[1] = 50     # Normal bytes
    sample[2] = 50
    sample[19] = 10    # Normal connection count
    sample[20] = 10
    normal_samples.append(sample)

X_normal = np.array(normal_samples, dtype=np.float64)
predictions_normal = model.predict(X_normal)
anomaly_count_normal = np.sum(predictions_normal == -1)

print(f"   Normal samples: {len(X_normal)}")
print(f"   Anomalies detected: {anomaly_count_normal}")
print(f"   Anomaly rate: {anomaly_count_normal/len(X_normal)*100:.1f}%")

if anomaly_count_normal == 0:
    print("✅ Normal traffic correctly identified as safe")
else:
    print(f"⚠️ False positives: {anomaly_count_normal} normal samples flagged")

print("\n" + "=" * 60)
print("[Summary]")
print(f"✅ Model loaded and working")
print(f"   - DDoS detection: {'✅ Working' if anomaly_count > 0 else '❌ Not working'}")
print(f"   - False positive rate: {anomaly_count_normal/len(X_normal)*100:.1f}%")

if anomaly_count == 0:
    print("\n⚠️ ISSUE FOUND: Model is not detecting synthetic DDoS")
    print("   The real DDoS traffic may not have the right characteristics")
    print("   for the model to classify as anomalous.")
