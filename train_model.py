import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
df = pd.read_csv("dataset.csv")  # Replace with actual dataset file

# Drop unnecessary columns (IP addresses, text fields that cannot be converted)
df = df.drop(columns=["src_ip", "dst_ip", "dns_query", "ssl_subject", "ssl_issuer", 
                      "http_uri", "http_user_agent", "http_orig_mime_types", 
                      "http_resp_mime_types", "weird_name", "weird_addl", "type"], 
             errors="ignore")

# Convert categorical columns to numerical values
for column in df.select_dtypes(include=["object"]).columns:
    df[column] = df[column].astype("category").cat.codes  # Convert text to numbers

# Handle missing values
df = df.fillna(0)

# Separate features (X) & target variable (y)
X = df.drop(columns=["label"], errors="ignore")  # Features
y = df["label"].fillna(0).astype(int)  # Convert labels, fill NaN with 0

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train ML model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate Model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save Model as PKL
joblib.dump(model, "threat_model.pkl")
print("Model saved as threat_model.pkl")
