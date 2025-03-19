import pandas as pd
import joblib
import scapy.all as scapy
from flask import Flask, render_template, jsonify, request
import requests  # Added to fetch website content
from bs4 import BeautifulSoup  # Import BeautifulSoup for HTML parsing
import logging  # Import logging module

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

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

def analyze_website_content(content):
    """Analyze the content of a website for potential threats."""
    try:
        soup = BeautifulSoup(content, "html.parser")
        title = soup.title.string if soup.title else "No Title"

        # Define keywords or patterns that might indicate specific threats
        threat_keywords = {
            "malware": "Malware-related content detected",
            "phishing": "Phishing attempt detected",
            "attack": "Potential attack-related content detected",
            "unauthorized": "Unauthorized access-related content detected",
            "exploit": "Exploit-related content detected",
        }

        # Check for the presence of threat keywords in the content
        threats_found = [
            {"keyword": keyword, "description": description}
            for keyword, description in threat_keywords.items()
            if keyword in content.lower()
        ]

        if threats_found:
            threat_details = "; ".join(
                [f"{threat['description']} (keyword: {threat['keyword']})" for threat in threats_found]
            )
            return f"Threats detected: {threat_details}. Title: {title}"
        else:
            return f"No threats detected. Title: {title}"
    except Exception as e:
        logging.error("Error analyzing website content", exc_info=True)
        return f"Error analyzing content: {str(e)}"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        response = requests.get(url, timeout=10)  # Add timeout to prevent hanging
        response.raise_for_status()
        content = response.text
        result = analyze_website_content(content)
        return jsonify({"url": url, "analysis": [result]})  # Ensure analysis is an array
    except requests.exceptions.Timeout:
        logging.error("Request to the URL timed out")
        return jsonify({"error": "Request timed out"}), 504
    except requests.RequestException as e:
        logging.error("Error fetching the URL", exc_info=True)
        return jsonify({"error": f"Error fetching the URL: {str(e)}"}), 500
    except Exception as e:
        logging.error("Unexpected error occurred", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
