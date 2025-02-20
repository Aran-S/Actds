import pandas as pd
import joblib
import scapy.all as scapy
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Load trained ML model
model = joblib.load("threat_model.pkl")

from scapy.layers.inet import IP, TCP, UDP

def extract_features(packet):
    """Extracts all required numerical features from network packets."""
    features = {
        "src_port": packet.sport if hasattr(packet, "sport") else 0,
        "dst_port": packet.dport if hasattr(packet, "dport") else 0,
        "proto": packet.proto if hasattr(packet, "proto") else 0,
        "length": len(packet),
        "flags": packet[TCP].flags if packet.haslayer(TCP) else 0,  # FIXED
        "ttl": packet[IP].ttl if packet.haslayer(IP) else 0,
        "window_size": packet[TCP].window if packet.haslayer(TCP) else 0,
    }

    # Ensure extracted features match the model's expected features
    expected_features = model.feature_names_in_
    extracted_values = [features.get(feature, 0) for feature in expected_features]
    
    return extracted_values



# Analyze network packets
def analyze_packet(packet):
    features = extract_features(packet)  # Extract features
    prediction = model.predict([features])  # Predict threat
    return "Malicious" if prediction == 1 else "Safe"

@app.route("/analyze", methods=["GET"])
def analyze():
    packets = scapy.sniff(count=10)  # Capture 10 packets
    results = [analyze_packet(packet) for packet in packets]
    return jsonify({"analysis": results})

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
