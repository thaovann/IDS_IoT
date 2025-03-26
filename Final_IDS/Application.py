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
from flask import Flask
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


def aggregate_csv_features(input_csv, output_dir):
    """Tổng hợp đặc trưng từ file CSV"""
    if input_csv is None or not os.path.exists(input_csv):
        print(f"⛔ Lỗi: Không tìm thấy file CSV {input_csv}")
        return None
    
    drop_columns =  [
            "Source IP",
            "Destination IP",
            "Label",
            "Protocol",
            "arp_operation",
            "protocol_type",
            "sender_mac",
            "sender_ip",
            "target_mac",
            "target_ip",
            "Label",
            "Flow ID",
            "Src IP",
            "Src Port",
            "Dst IP",
            "Dst Port",
            "Timestamp",
        ]


    data = pd.read_csv(input_csv)
    numeric_data = data.drop(columns=[col for col in drop_columns if col in data.columns], errors="ignore")
    # numeric_data = data.select_dtypes(include=[np.number])

    # if numeric_data.empty:
    #     print(f"⚠ Không có dữ liệu số trong {input_csv}")
    #     return None

    aggregated_features = numeric_data.aggregate(
        ["mean", "std", "skew", "kurtosis", "median"]
    ).values.flatten()
    aggregated_df = pd.DataFrame([aggregated_features])

    output_csv = os.path.join(
        output_dir, os.path.splitext(os.path.basename(input_csv))[0] + "_aggregated.csv"
    )
    aggregated_df.to_csv(output_csv, index=False)
    # print("aggregated_csv: ", output_csv)

    return output_csv


def select_columns_forAE(input_csv):
    """Chọn các cột quan trọng cho Autoencoder"""
    print("input_csv in select_colums_forAE: ", input_csv)
    if input_csv is None or not os.path.exists(input_csv):
        print(f"⛔ Lỗi: Không tìm thấy file CSV {input_csv}")
        return None

    selected_columns = ["365", "101", "86", "100", "130"]
    df = pd.read_csv(input_csv)
    # print("df: ", df)

    if not all(col in df.columns for col in selected_columns):
        print("⛔ Lỗi: Một số cột được chọn không có trong tập dữ liệu.")
        return None
    
    # print("df[selected_columns].values: ", df[selected_columns].values)

    return df[selected_columns].values  


def detect_intrusion(X_new):
    """Dự đoán bất thường bằng mô hình Autoencoder"""
    X_new_scaled = SCALER.transform(X_new)
    reconstructions = MODEL.predict(X_new_scaled)
    test_loss = tf.keras.losses.mae(reconstructions, X_new_scaled).numpy()
    
    print("test_loss: ", test_loss)
    threshold = 0.1
    return (test_loss < threshold).astype(int) 


def packet_callback(packet):
    """Callback xử lý từng gói tin"""
    global packet_count, packet_buffer, file_index

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

    with lock:
        packet_buffer.append(packet)
        packet_count += 1

        if packet_count >= CHUNK_SIZE:
            current_buffer = packet_buffer.copy()
            current_index = file_index
            file_index += 1
            packet_buffer.clear()
            packet_count = 0

            executor.submit(process_packets, current_buffer, current_index)


def send_websocket_alert(alert_path):
    socketio.emit(
        "intrusion_alert",
        {
            "timestamp": time.time(),
            "file_path": alert_path,
            "message": "Phát hiện tấn công!",
        },
    )


def handle_alert(predictions, buffer, index):
    if np.any(predictions == 1):
        alert_dir = os.path.join(ALERT_DIR, f"alert_{index}")
        os.makedirs(alert_dir, exist_ok=True)

        # Lưu pcap và CSV
        alert_pcap = os.path.join(alert_dir, f"alert_{index}.pcap")
        wrpcap(alert_pcap, buffer)

        print(f"🚨 Đã phát hiện {np.sum(predictions)} cảnh báo!")

        # Gửi cảnh báo qua WebSocket
        send_websocket_alert(alert_pcap)


def process_packets(buffer, index):
    file_name = f"{OUTPUT_DIR}/capture_{index}.pcap"
    wrpcap(file_name, buffer)
    print(f"📂 Đã lưu: {file_name}")

    # Phân tích tiếp
    csv_file = extract_feature_by_CICFlowmeter(file_name, CSV_OUTPUT_DIR)
    # if csv_file is None:
    #     print("⚠ Không thể trích xuất đặc trưng, bỏ qua xử lý.")
    #     return

    aggregated_csv_path = aggregate_csv_features(csv_file, CSV_OUTPUT_DIR)
    # if aggregated_csv_path is None:
    #     print("⚠ Không thể tổng hợp đặc trưng, bỏ qua xử lý.")
    #     return

    X_new = select_columns_forAE(aggregated_csv_path)
    # if X_new is None:
    #     print("⚠ Không thể chọn đặc trưng phù hợp, bỏ qua xử lý.")
    #     return

    if X_new is not None:
        predictions = detect_intrusion(X_new)
        handle_alert(predictions, buffer, index)
        
    for f in [file_name, csv_file, aggregated_csv_path]:
        if f and os.path.exists(f):
            os.remove(f)


if __name__ == "__main__":
    print("⏳ Đang bắt gói tin...")
    sniff(prn=packet_callback, store=False)
