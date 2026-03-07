from scapy.all import sniff
import joblib
import numpy as np

# Load trained Random Forest model
MODEL_PATH = "../models/mitm_rf_model.pkl"
model = joblib.load(MODEL_PATH)


def extract_features(packet):
    """
    Extract features from captured packet
    """

    packet_length = len(packet)

    protocol = 0

    if packet.haslayer("TCP"):
        protocol = 6

    elif packet.haslayer("UDP"):
        protocol = 17

    return [packet_length, protocol]


def analyze_packet(packet):
    """
    Analyze packet using trained model
    """

    features = extract_features(packet)

    features = np.array(features).reshape(1, -1)

    prediction = model.predict(features)[0]

    if prediction == 1:
        print("⚠ MITM Attack Detected")

    else:
        print("Normal Traffic")


def start_detection():
    """
    Start real-time packet sniffing
    """

    print("Starting packet monitoring...")

    sniff(
        prn=analyze_packet,
        store=False
    )