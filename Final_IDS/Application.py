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
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
executor = ThreadPoolExecutor(max_workers=4)
lock = threading.Lock()

# Configuration - use Path for cross-platform compatibility
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "pcap_splits"
CSV_OUTPUT_DIR = BASE_DIR / "csv_cicflowmeter"
CICFLOWMETER_DIR = BASE_DIR / "CICFlowMeter-4.0" / "bin"
ALERT_DIR = OUTPUT_DIR / "alerts"
CFM_PATH = CICFLOWMETER_DIR / "cfm.bat"
CHUNK_SIZE = 5000

# Ensure directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
CSV_OUTPUT_DIR.mkdir(exist_ok=True)
ALERT_DIR.mkdir(exist_ok=True)

# Load ML model and scaler
try:
    MODEL = load_model(BASE_DIR / "Model" / "autoencoder.h5")
    SCALER = joblib.load(BASE_DIR / "Model" / "scaler.pkl")
except Exception as e:
    logger.error(f"Failed to load ML model: {e}")
    raise

packet_count = 0
packet_buffer = []
file_index = 0


def extract_features_with_cicflowmeter(pcap_path: Path, output_dir: Path) -> Path:
    """Extract features from PCAP using CICFlowMeter"""
    if not CFM_PATH.exists():
        logger.error("CICFlowMeter not found at %s", CFM_PATH)
        return None

    try:
        cmd = [str(CFM_PATH), str(pcap_path), str(output_dir)]
        subprocess.run(cmd, check=True, cwd=str(CICFLOWMETER_DIR))
        logger.info("Extracted features from %s", pcap_path)

        # Find the generated CSV file
        csv_name = pcap_path.stem + ".pcap_Flow.csv"
        output_file = output_dir / csv_name

        if not output_file.exists():
            # Try alternative naming pattern if needed
            output_file = next(output_dir.glob("*.csv"), None)

        return output_file if output_file else None

    except subprocess.CalledProcessError as e:
        logger.error("CICFlowMeter failed: %s", e)
        return None


def aggregate_features(csv_file: Path) -> pd.DataFrame:
    """Aggregate network flow features for detection with proper feature naming"""
    try:
        data = pd.read_csv(csv_file)
        if data.empty:
            logger.warning("Empty CSV file: %s", csv_file)
            return None

        # Define features and aggregations
        feature_config = {
            "Flow IAT Max": ["std"],
            "Fwd IAT Mean": ["mean", "std"],
            "Bwd IAT Std": ["mean"],
            "Idle Std": ["mean"],
        }

        # Check for missing columns
        missing = [col for col in feature_config if col not in data.columns]
        if missing:
            logger.warning("Missing expected columns: %s", missing)
            return None

        # Perform aggregation with consistent naming
        aggregated = {}
        for feature, aggs in feature_config.items():
            for agg_func in aggs:
                col_name = f"{feature}_{agg_func}"
                aggregated[col_name] = [data[feature].agg(agg_func)]

        # Create DataFrame with consistent structure
        features_df = pd.DataFrame(aggregated)

        # Ensure consistent column order
        expected_columns = [
            "Flow IAT Max_std",
            "Fwd IAT Mean_mean",
            "Fwd IAT Mean_std",
            "Bwd IAT Std_mean",
            "Idle Std_mean",
        ]

        # Only keep columns we expect
        features_df = features_df.reindex(columns=expected_columns)

        logger.debug("Aggregated features: %s", features_df.to_dict("records")[0])
        return features_df

    except Exception as e:
        logger.error("Feature aggregation failed: %s", e)
        return None


def detect_anomalies(features: pd.DataFrame) -> np.ndarray:
    """Detect anomalies with proper feature scaling"""
    try:
        if features is None or features.empty:
            return np.array([])

        # Convert to numpy array in correct order
        feature_array = features.values.astype("float32")

        # Scale features - assumes SCALER was trained on same feature order
        features_scaled = SCALER.transform(feature_array)

        # Get reconstruction error
        reconstructions = MODEL.predict(features_scaled)
        test_loss = tf.keras.losses.mae(reconstructions, features_scaled).numpy()

        # Apply threshold (adjust based on your model)
        threshold = 0.1
        predictions = (test_loss > threshold).astype(int)

        logger.debug(
            "Anomaly detection results - Loss: %s, Predictions: %s",
            test_loss,
            predictions,
        )
        return predictions

    except Exception as e:
        logger.error("Anomaly detection failed: %s", e)
        return np.array([])


def handle_packet(packet):
    """Callback for each captured packet"""
    global packet_count, packet_buffer, file_index

    with lock:
        packet_buffer.append(packet)
        packet_count += 1

        if packet_count >= CHUNK_SIZE:
            # Process the current batch
            current_buffer = packet_buffer.copy()
            current_index = file_index
            file_index += 1

            # Reset for next batch
            packet_buffer.clear()
            packet_count = 0

            # Submit for processing
            executor.submit(process_packet_batch, current_buffer, current_index)


def process_packet_batch(buffer: list, index: int):
    """Process a batch of packets"""
    try:
        # Save PCAP
        pcap_path = OUTPUT_DIR / f"capture_{index}.pcap"
        wrpcap(str(pcap_path), buffer)
        logger.info("Saved PCAP: %s", pcap_path)

        # Extract features
        csv_path = extract_features_with_cicflowmeter(pcap_path, CSV_OUTPUT_DIR)
        if not csv_path or not csv_path.exists():
            logger.warning("No features extracted for %s", pcap_path)
            return

        # Aggregate features
        features = aggregate_features(csv_path)
        if features is None or features.empty:
            logger.warning("No features aggregated for %s", csv_path)
            return

        # Detect anomalies
        predictions = detect_anomalies(features)
        print("predictions: ", predictions)
        if predictions.any():
            handle_alert(predictions, buffer, index)

    except Exception as e:
        logger.error("Error processing batch %d: %s", index, e)
    finally:
        # Clean up temporary files
        for f in [pcap_path, csv_path]:
            if f and f.exists():
                try:
                    f.unlink()
                except Exception as e:
                    logger.warning("Could not delete %s: %s", f, e)


def handle_alert(predictions: np.ndarray, packets: list, index: int):
    """Handle detected intrusion"""
    alert_count = np.sum(predictions)
    logger.warning("🚨 Detected %d anomalies in batch %d", alert_count, index)

    # Save alert data
    alert_dir = ALERT_DIR / f"alert_{index}"
    alert_dir.mkdir(exist_ok=True)

    alert_pcap = alert_dir / f"alert_{index}.pcap"
    wrpcap(str(alert_pcap), packets)

    # Send via WebSocket
    socketio.emit(
        "intrusion_alert",
        {
            "timestamp": time.time(),
            "file_path": str(alert_pcap),
            "message": f"Detected {alert_count} anomalies",
            "severity": "high",
        },
    )


@app.route("/status")
def status():
    return jsonify(
        {
            "status": "running",
            "packet_count": packet_count,
            "buffer_size": len(packet_buffer),
            "last_processed": file_index,
        }
    )


if __name__ == "__main__":
    logger.info("🚀 Starting IDS monitoring...")
    try:
        # Start packet capture in background
        sniff_thread = threading.Thread(
            target=sniff, kwargs={"prn": handle_packet, "store": False}, daemon=True
        )
        sniff_thread.start()

        # Start Flask app
        socketio.run(app, host="0.0.0.0", port=5000)

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error("Fatal error: %s", e)
