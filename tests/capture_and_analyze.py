"""
Capture live traffic and analyze the feature values.
This will help us understand what real DDoS traffic looks like.
"""
import numpy as np
from core.packet_capture import capture_live_traffic_cross_platform
from core.preprocessor import COMBINED_FEATURES
import pickle
from pathlib import Path

print("[*] Live Traffic Capture & Analysis")
print("=" * 60)
print("\n[1] Capturing 10 seconds of traffic...")
print("    (Start your DDoS attack AFTER this starts)")
print("    Press Ctrl+C on DDoS script after 10 seconds\n")

try:
    X = capture_live_traffic_cross_platform(duration=10, iface=None)
    print(f"✅ Captured traffic: shape {X.shape}")
    
    if X.shape[0] > 0:
        print("\n[2] Analyzing feature values...")
        
        # Load scaler to unscale values
        scaler = pickle.load(open(Path(__file__).parent.parent / "saved_models" / "scaler.pkl", "rb"))
        X_unscaled = scaler.inverse_transform(X)
        
        print("\nTop features with highest values:")
        print("-" * 60)
        
        # Calculate mean and max for each feature
        feature_stats = []
        for i, feat_name in enumerate(COMBINED_FEATURES):
            mean_val = X_unscaled[:, i].mean()
            max_val = X_unscaled[:, i].max()
            feature_stats.append((feat_name, mean_val, max_val, i))
        
        # Sort by mean value
        feature_stats.sort(key=lambda x: x[1], reverse=True)
        
        for feat_name, mean_val, max_val, idx in feature_stats[:15]:
            print(f"{feat_name:30s} | Mean: {mean_val:12.2f} | Max: {max_val:12.2f}")
        
        print("\n[3] Feature values for first sample:")
        print("-" * 60)
        for i in range(min(25, len(COMBINED_FEATURES))):
            print(f"{COMBINED_FEATURES[i]:30s} = {X_unscaled[0, i]:12.6f}")
        
        print("\n[4] Statistics:")
        print(f"   Total samples (flows): {X.shape[0]}")
        print(f"   Features per sample: {X.shape[1]}")
        print(f"   Min feature value: {X.min():.6f}")
        print(f"   Max feature value: {X.max():.6f}")
        print(f"   Mean feature value: {X.mean():.6f}")
        
    else:
        print("❌ No traffic captured")
        
except KeyboardInterrupt:
    print("\n[!] Capture interrupted")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
