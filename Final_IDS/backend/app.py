from flask import Flask, jsonify
import os
import time
import numpy as np
import pandas as pd
import tensorflow as tf
import joblib
import threading
import subprocess
from scapy.all import sniff, wrpcap
from flask_socketio import SocketIO
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
executor = ThreadPoolExecutor(max_workers=4)
lock = threading.Lock()

# Thư mục lưu trữ
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(DATA_DIR, "pcap_splits")
CSV_OUTPUT_DIR = os.path.join(DATA_DIR, "csv_cicflowmeter")
CICFLOWMETER_DIR = os.path.join(BASE_DIR, "CICFlowMeter-4.0", "bin")
CFM_PATH = os.path.join(CICFLOWMETER_DIR, "cfm.bat")
ALERT_DIR = os.path.join(OUTPUT_DIR, "alerts")

# Load AI Model
try:
    MODEL = tf.keras.models.load_model(
        os.path.join(BASE_DIR, "models", "autoencoder.h5")
    )
    SCALER = joblib.load(os.path.join(BASE_DIR, "models", "scaler.pkl"))
except Exception as e:
    print(f"⛔ Lỗi tải mô hình AI: {e}")
    exit(1)

packet_count = 0
packet_buffer = []
file_index = 0
alert_history = []


# 🚀 **Bắt gói tin trực tiếp từ card mạng**
def packet_callback(packet):
    """Callback xử lý từng gói tin"""
    global packet_count, packet_buffer, file_index

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

    with lock:
        packet_buffer.append(packet)
        packet_count += 1

        if packet_count >= 5000:
            current_buffer = packet_buffer.copy()
            current_index = file_index
            file_index += 1
            packet_buffer.clear()
            packet_count = 0

            executor.submit(process_packets, current_buffer, current_index)


# 🚀 **Xử lý gói tin, chuyển thành Flow**
def process_packets(buffer, index):
    """Lưu PCAP, trích xuất Flow, và phân tích"""
    pcap_file = os.path.join(OUTPUT_DIR, f"capture_{index}.pcap")
    wrpcap(pcap_file, buffer)

    csv_file = extract_feature_by_CICFlowmeter(pcap_file, CSV_OUTPUT_DIR)
    if csv_file:
        analyze_csv(csv_file)


# 🚀 **Chạy CICFlowMeter để trích xuất flow**
def extract_feature_by_CICFlowmeter(pcap_path, output_dir):
    """Trích xuất Flow từ PCAP bằng CICFlowMeter"""
    if not os.path.exists(CFM_PATH):
        print("⛔ Lỗi: Không tìm thấy CICFlowMeter!")
        return None

    csv_name = os.path.splitext(os.path.basename(pcap_path))[0] + ".pcap_Flow.csv"
    output_file = os.path.join(output_dir, csv_name)

    cmd = f'"{CFM_PATH}" "{pcap_path}" "{output_dir}"'
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=CICFLOWMETER_DIR)
    except subprocess.CalledProcessError:
        return None

    return output_file if os.path.exists(output_file) else None


# 🚀 **Phân tích flow để phát hiện xâm nhập**
def analyze_csv(csv_file):
    """Phát hiện xâm nhập từ dữ liệu Flow"""
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
    available_cols = [col for col in selected_features.keys() if col in data.columns]
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

    X_new = pd.DataFrame([aggregated])
    X_scaled = SCALER.transform(X_new)

    reconstructions = MODEL.predict(X_scaled)
    loss = tf.keras.losses.mae(reconstructions, X_scaled).numpy()
    threshold = 0.1
    attack_detected = np.any(loss > threshold)

    if attack_detected:
        send_alert(f"🔥 Tấn công phát hiện! Loss: {loss.mean():.5f}")


def send_alert(message):
    """Gửi cảnh báo đến giao diện"""
    alert_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "severity": "high",
    }
    socketio.emit("intrusion_alert", alert_data)
    alert_history.append(alert_data)

@app.route("/api/start_sniffing", methods=["GET"])
def start_sniffing():
    """Bắt đầu bắt gói tin trên card mạng"""
    executor.submit(lambda: sniff(prn=packet_callback, store=False))
    return jsonify({"message": "Sniffer đã khởi động!"})

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Trả về danh sách 10 cảnh báo gần nhất"""
    return jsonify({"count": len(alert_history), "alerts": alert_history[-10:]})


if __name__ == "__main__":
    print("🚀 Hệ thống IDS đang chạy...")
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
