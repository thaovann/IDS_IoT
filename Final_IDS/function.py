from scapy.all import sniff, wrpcap
import os
import numpy as np
import pandas as pd
import os
from sklearn.preprocessing import MinMaxScaler
import subprocess


def packet_callback(packet, output_dir):
    CHUNK_SIZE = 5000
    os.makedirs(output_dir, exist_ok=True)

    packet_count = 0
    packet_buffer = []

    packet_buffer.append(packet)
    packet_count += 1

    if packet_count >= CHUNK_SIZE:
        os.makedirs(output_dir, exist_ok=True)
        file_name = f"{output_dir}/capture_{packet_count // CHUNK_SIZE}.pcap"
        wrpcap(file_name, packet_buffer)
        print(f"Saved: {file_name}")

        packet_buffer.clear()
        packet_count = 0

def extract_feature_by_CICFlowmeter(pcap_dir, output_dir):
    CICFLOWMETER_DIR = r"C:\Users\admin\OneDrive - Hanoi University of Science and Technology\Pictures\Desktop\VANN\IDS_IoT\CICFlowMeter-4.0\bin"
    CFM_PATH = os.path.join(CICFLOWMETER_DIR, "cfm.bat")
    if not os.path.exists(CFM_PATH):
        print("⛔ Lỗi: Không tìm thấy CICFlowMeter! Kiểm tra lại đường dẫn.")
        return
    
    for pcap_file in os.listdir(pcap_dir):
        if not pcap_file.endswith(".pcap"):
            continue

        pcap_path = os.path.join(pcap_dir, pcap_file)
        cmd = f'"{CFM_PATH}" "{pcap_path}" "{output_dir}"'
        try:
            subprocess.run(cmd, shell=True, check=True, cwd=CICFLOWMETER_DIR)
            print("✅ CICFlowMeter đã chạy thành công!")
        except subprocess.CalledProcessError as e:
            print(f"⛔ Lỗi khi chạy CICFlowMeter: {e}")


def aggregate_csv_features(data):
    aggregated_features = []
    numeric_data = data.select_dtypes(include=[np.number])

    if numeric_data.empty:
        return pd.DataFrame()

    for feature in data.columns:
        if feature not in [
            "Label",
            "Flow ID",
            "Src IP",
            "Src Port",
            "Dst IP",
            "Dst Port",
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Protocol",
        ]:

            numeric_values = pd.to_numeric(data[feature], errors="coerce")
            mean_value = np.nanmean(numeric_values) if len(numeric_values) > 0 else 0
            std_value = np.nanstd(numeric_values) if len(numeric_values) > 0 else 0
            skew_value = (
                0 if len(numeric_values) < 3 else pd.Series(numeric_values).skew()
            )
            kurtosis_value = (
                0 if len(numeric_values) < 4 else pd.Series(numeric_values).kurtosis()
            )
            median_value = (
                np.nanmedian(numeric_values) if len(numeric_values) > 0 else 0
            )

            aggregated_features.extend(
                [mean_value, std_value, skew_value, kurtosis_value, median_value]
            )

    aggregated_df = pd.DataFrame(aggregated_features).T.reset_index(drop=True)

    return aggregated_df


def select_columns_forAE(input_csv, output_dir):
    selected_columns = ["365", "101", "86", "100", "130"]
    df = pd.read_csv(input_csv).dropna()

    df_selected = df[selected_columns]

    os.makedirs(output_dir, exist_ok=True)  # Đảm bảo thư mục tồn tại
    df_selected.to_csv(os.path.join(output_dir, "selected_columns.csv"), index=False)
