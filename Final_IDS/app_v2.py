import time
from scapy.all import sniff, wrpcap
import os
import numpy as np
import pandas as pd
import subprocess
import tensorflow as tf
from tensorflow.keras.models import load_model
import joblib
from concurrent.futures import ThreadPoolExecutor
import threading
from flask import Flask, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
executor = ThreadPoolExecutor(max_workers=4)
lock = threading.Lock()

OUTPUT_DIR = r"C:\Users\admin\OneDrive - Hanoi University of Science and Technology\Pictures\Desktop\VANN\IDS_IoT\Final_IDS/pcap_splits"
CSV_OUTPUT_DIR = r"C:\Users\admin\OneDrive - Hanoi University of Science and Technology\Pictures\Desktop\VANN\IDS_IoT\Final_IDS/csv_cicflowmeter"
CICFLOWMETER_DIR = r"C:\Users\admin\OneDrive - Hanoi University of Science and Technology\Pictures\Desktop\VANN\IDS_IoT\CICFlowMeter-4.0\bin"
ALERT_DIR = os.path.join(OUTPUT_DIR, "alerts")
CFM_PATH = os.path.join(CICFLOWMETER_DIR, "cfm.bat")
CHUNK_SIZE = 5000
MODEL = load_model("Final_IDS/Model/autoencoder.h5")
SCALER = joblib.load("Final_IDS/Model/scaler.pkl")
packet_count = 0
packet_buffer = []
file_index = 0

# Load AI model
try:
    MODEL = load_model("Final_IDS/Model/autoencoder.h5")
    SCALER = joblib.load("Final_IDS/Model/scaler.pkl")
except Exception as e:
    print(f"⛔ Failed to load model: {e}")
    exit(1)

# Save alert history
alert_history = []


def extract_feature_by_CICFlowmeter(pcap_path, output_dir):
    """Trích xuất đặc trưng từ một file PCAP"""
    if not os.path.exists(CFM_PATH):
        print("⛔ Lỗi: Không tìm thấy CICFlowMeter! Kiểm tra lại đường dẫn.")
        return None

    os.makedirs(output_dir, exist_ok=True)

    pcap_name = os.path.basename(pcap_path)
    csv_name = os.path.splitext(pcap_name)[0] + ".pcap_Flow" + ".csv"
    output_file = os.path.join(output_dir, csv_name)

    cmd = f'"{CFM_PATH}" "{pcap_path}" "{output_dir}"'
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=CICFLOWMETER_DIR)
        print(f"✅ Đã trích xuất đặc trưng từ {pcap_path}")
    except subprocess.CalledProcessError as e:
        print(f"⛔ Lỗi khi chạy CICFlowMeter: {e}")
        return None
    # print("output_file", output_file)

    return output_file if os.path.exists(output_file) else None


def aggregate_csv_features(csv_file):
    """Aggregate specific features from CSV"""
    try:
        data = pd.read_csv(csv_file)
        if data.empty:
            print("⛔ Error: Empty CSV file")
            return None

        selected_features = {
            "Flow IAT Max": ["std"],
            "Fwd IAT Mean": ["mean", "std"],
            "Bwd IAT Std": ["mean"],
            "Idle Std": ["mean"],
        }

        # Check for missing columns
        available_cols = [
            col for col in selected_features.keys() if col in data.columns
        ]
        if len(available_cols) != len(selected_features):
            missing = set(selected_features.keys()) - set(available_cols)
            print(f"⚠ Missing columns: {missing}")
            return None

        # Aggregate features
        aggregated = {
            f"{col}_{func}": data[col].agg(func)
            for col in available_cols
            for func in selected_features[col]
        }

        return pd.DataFrame([aggregated])
    except Exception as e:
        print(f"⛔ Error aggregating features: {e}")
        return None


def detect_intrusion(X_new):
    """Detect anomalies using Autoencoder"""
    try:
        X_new_scaled = SCALER.transform(X_new)
        reconstructions = MODEL.predict(X_new_scaled)
        test_loss = tf.keras.losses.mae(reconstructions, X_new_scaled).numpy()

        threshold = 0.1
        return (test_loss > threshold).astype(int)
        print("test_loss: ", test_loss)
    except Exception as e:
        print(f"⛔ Detection error: {e}")
        return None


def send_websocket_alert(alert_data):
    """Send alert via WebSocket"""
    socketio.emit("intrusion_alert", alert_data)
    alert_history.append(alert_data)


def handle_alert(predictions, buffer, index):
    """Handle detected attacks"""
    if predictions is None or not np.any(predictions == 1):
        return

    alert_count = np.sum(predictions == 1)
    os.makedirs(ALERT_DIR, exist_ok=True)

    alert_pcap = os.path.join(ALERT_DIR, f"alert_{index}.pcap")
    wrpcap(alert_pcap, buffer)

    print(f"🚨 Attack detected: {alert_count} alerts!")

    send_websocket_alert(
        {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": alert_pcap,
            "message": f"Detected {alert_count} anomalies!",
            "severity": "high" if alert_count > 1 else "medium",
        }
    )


def process_packets(buffer, index):
    """Process packet buffer and detect intrusions"""
    # Create output directories if they don't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

    # Save packet buffer to pcap
    pcap_file = os.path.join(OUTPUT_DIR, f"capture_{index}.pcap")
    wrpcap(pcap_file, buffer)
    print(f"📦 Saved: {pcap_file}")

    # Extract features
    csv_file = extract_feature_by_CICFlowmeter(pcap_file, CSV_OUTPUT_DIR)
    if not csv_file:
        return

    # Aggregate features
    aggregated = aggregate_csv_features(csv_file)
    if aggregated is None:
        return

    # Detect anomalies
    predictions = detect_intrusion(aggregated.values)
    print("predictions", predictions)
    if predictions is not None:
        handle_alert(predictions, buffer, index)

    # Cleanup temporary files
    for f in [pcap_file, csv_file]:
        try:
            if os.path.exists(f):
                os.remove(f)
        except Exception as e:
            print(f"⚠ Error deleting {f}: {e}")


def packet_callback(packet):
    """Process each network packet"""
    global packet_count, packet_buffer, file_index

    with lock:
        packet_buffer.append(packet)
        packet_count += 1

        if packet_count >= CHUNK_SIZE:
            # Process the current buffer in a separate thread
            current_buffer = packet_buffer.copy()
            current_index = file_index
            file_index += 1

            # Reset buffer and counter
            packet_buffer.clear()
            packet_count = 0

            # Submit for processing
            executor.submit(process_packets, current_buffer, current_index)


@app.route("/api/alerts")
def get_alerts():
    """API endpoint for recent alerts"""
    return jsonify(
        {"count": len(alert_history), "alerts": alert_history[-10:]}  # Last 10 alerts
    )


if __name__ == "__main__":
    # Create necessary directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)
    os.makedirs(ALERT_DIR, exist_ok=True)

    print("🚀 Starting IDS...")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print(f"📊 CSV directory: {CSV_OUTPUT_DIR}")
    print(f"⚠ Alert directory: {ALERT_DIR}")
    print("🛡️ Starting packet capture...")

    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n🛑 Stopping packet capture...")
    except Exception as e:
        print(f"⛔ Fatal error: {e}")
